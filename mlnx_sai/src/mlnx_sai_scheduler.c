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
#define __MODULE__ SAI_SCHEDULER

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_sched_attr_getter(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_sched_attr_setter(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static const sai_attribute_entry_t        sched_attribs[] = {
    { SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM, false, true, true, true,
      "QoS scheduler alg", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, false, true, true, true,
      "QoS scheduler weight", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_SCHEDULER_ATTR_SHAPER_TYPE, false, true, true, true,
      "QoS scheduler type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE, false, true, true, true,
      "QoS scheduler min rate", SAI_ATTR_VAL_TYPE_U64 },
    { SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE, false, true, true, true,
      "QoS scheduler min burst rate", SAI_ATTR_VAL_TYPE_U64 },
    { SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, false, true, true, true,
      "QoS scheduler max rate", SAI_ATTR_VAL_TYPE_U64 },
    { SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE, false, true, true, true,
      "QoS scheduler max burst rate", SAI_ATTR_VAL_TYPE_U64 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t sched_vendor_attribs[] = {
    { SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_attr_getter, (void*)SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM,
      mlnx_sched_attr_setter, (void*)SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM },
    { SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_attr_getter, (void*)SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
      mlnx_sched_attr_setter, (void*)SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT},
    { SAI_SCHEDULER_ATTR_SHAPER_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_attr_getter, (void*)SAI_SCHEDULER_ATTR_SHAPER_TYPE,
      mlnx_sched_attr_setter, (void*)SAI_SCHEDULER_ATTR_SHAPER_TYPE },
    { SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_attr_getter, (void*)SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE,
      mlnx_sched_attr_setter, (void*)SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE },
    { SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_attr_getter, (void*)SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
      mlnx_sched_attr_setter, (void*)SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE },
    { SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static sai_status_t sched_db_entry_get(sai_object_id_t oid, mlnx_sched_profile_t **sched)
{
    sai_status_t status;
    uint32_t     idx;

    assert(sched != NULL);

    status = mlnx_object_to_type(oid, SAI_OBJECT_TYPE_SCHEDULER, &idx, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (idx >= MAX_SCHED) {
        SX_LOG_ERR("Scheduler id is invalid\n");
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *sched = &sai_qos_sched_db[idx];
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sched_attr_getter(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    uint32_t              attr_id = (sai_scheduler_attr_t)arg;
    mlnx_sched_profile_t *sched;
    sai_status_t          status;

    SX_LOG_ENTER();

    sai_qos_db_read_lock();

    status = sched_db_entry_get(key->object_id, &sched);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    assert(sched != NULL);
    assert(sched->is_used);

    switch (attr_id) {
    case SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM:
        if (sched->ets.dwrr == TRUE) {
            value->s32 = SAI_SCHEDULING_DWRR;
        } else {
            value->s32 = SAI_SCHEDULING_STRICT;
        }
        break;

    case SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
        if (sched->ets.dwrr == FALSE) {
            SX_LOG_ERR("Weight can't be used for strict prio alg type\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        } else {
            value->u32 = sched->ets.dwrr_weight;
        }
        break;

    case SAI_SCHEDULER_ATTR_SHAPER_TYPE:
        value->s32 = SAI_METER_TYPE_BYTES;
        break;

    case SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE:
        value->u64 = sched->min_rate;
        break;

    case SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
        value->u64 = sched->max_rate;
        break;
    }

out:
    SX_LOG_EXIT();
    sai_qos_db_unlock();
    return status;
}

/* Min valid rate for the shaper */
#define MIN_SHAPER_RATE_BPS (200 * 1000 * 1000 / 8)

static void check_rate(uint64_t rate, bool is_min)
{
    if (rate < MIN_SHAPER_RATE_BPS) {
        SX_LOG_WRN("Set %s rate to 0. Valid rate for scheduler should be >= 200mbps\n",
                   is_min ? "min" : "max");
    }
}

/* fix up rate value from SAI */
static uint32_t ets_fixup_rate(uint64_t rate)
{
    if (rate < MIN_SHAPER_RATE_BPS) {
        return 0;
    }

    return (uint32_t)(rate / 1000.0 * 8);
}

static void sai_to_sdk_rate(uint64_t min_rate, uint64_t max_rate, sx_cos_ets_element_config_t *ets)
{
    if (0 == max_rate) {
        ets->max_shaper_rate = 0xFFFFFFF;
    } else {
        ets->max_shaper_rate = ets_fixup_rate(max_rate);
    }

    if (0 == min_rate) {
        ets->min_shaper_rate = 0;
    } else {
        ets->min_shaper_rate = ets_fixup_rate(ets->min_shaper_rate);
    }
}

static void ets_element_dump(sx_port_log_id_t port_log_id, sx_cos_ets_element_config_t *ets)
{
    char *name = "(unknown)";

    if (ets->element_hierarchy == SX_COS_ETS_HIERARCHY_PORT_E) {
        name = "port";
    } else if (ets->element_hierarchy == SX_COS_ETS_HIERARCHY_TC_E) {
        name = "queue";
    } else if (ets->element_hierarchy == SX_COS_ETS_HIERARCHY_SUB_GROUP_E) {
        name = "sub-group";
    } else if (ets->element_hierarchy == SX_COS_ETS_HIERARCHY_GROUP_E) {
        name = "group";
    }

    SX_LOG_DBG("ETS element on %s (port log id=0x%x):\n", name, port_log_id);
    SX_LOG_DBG("\tpackets_mode=%u\n", ets->packets_mode);
    SX_LOG_DBG("\tdwrr=%u, dwrr_enable=%u, dwrr_weight=%u\n", ets->dwrr, ets->dwrr_enable, ets->dwrr_weight);
    SX_LOG_DBG("\tmin_shaper_rate=%u, min_shaper_enable=%u\n", ets->min_shaper_rate, ets->min_shaper_enable);
    SX_LOG_DBG("\tmax_shaper_rate=%u, max_shaper_rate_enable=%u\n", ets->max_shaper_rate, ets->max_shaper_enable);
    SX_LOG_DBG("\telement_hierarchy=%u, element_index=%u, next_element_index=%u\n",
               ets->element_hierarchy,
               ets->element_index,
               ets->next_element_index);
}

static sai_status_t ets_element_update(sx_port_log_id_t port_log_id, sx_cos_ets_element_config_t *ets, char *name)
{
    sx_cos_ets_element_config_t *ets_list;
    uint32_t                     max_ets_count = MAX_ETS_ELEMENTS;
    sai_status_t                 status;
    uint32_t                     ii;

    ets_list = (sx_cos_ets_element_config_t*)malloc(sizeof(*ets_list) * MAX_ETS_ELEMENTS);
    if (!ets_list) {
        SX_LOG_ERR("Failed to allocate ETS list\n");
        return SAI_STATUS_NO_MEMORY;
    }

    status = sx_api_cos_port_ets_element_get(gh_sdk, port_log_id, ets_list, &max_ets_count);
    if (status != SX_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed get ETS list - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    for (ii = 0; ii < MAX_ETS_ELEMENTS; ii++) {
        if ((ets_list[ii].element_index == ets->element_index) &&
            (ets_list[ii].element_hierarchy == ets->element_hierarchy)) {
            ets->next_element_index = ets_list[ii].next_element_index;
            break;
        }
    }

    ets_element_dump(port_log_id, ets);

    status = sx_api_cos_port_ets_element_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                             port_log_id, ets, 1);

    if (status != SX_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed to apply scheduler on %s - %s.\n",
                   name, SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

out:
    free(ets_list);
    return status;
}

static sai_status_t queue_update_ets(sx_port_log_id_t             port_log_id,
                                     sx_cos_ets_element_config_t *ets,
                                     mlnx_sched_obj_t            *obj)
{
    ets->element_hierarchy = obj->ets_type;
    ets->element_index     = obj->index;
    ets->min_shaper_enable = TRUE;
    ets->max_shaper_enable = TRUE;

    return ets_element_update(port_log_id, ets, "queue");
}

static sai_status_t port_update_ets(sx_port_log_id_t port_log_id, sx_cos_ets_element_config_t *ets)
{
    if (ets->min_shaper_rate > 0) {
        SX_LOG_ERR("Min bandwidth rate can't be used on the port\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    ets->element_hierarchy  = SX_COS_ETS_HIERARCHY_PORT_E;
    ets->next_element_index = 0;
    ets->element_index      = 0;
    ets->min_shaper_enable  = FALSE;
    ets->max_shaper_enable  = TRUE;
    ets->dwrr               = FALSE;
    ets->dwrr_enable        = FALSE;

    return ets_element_update(port_log_id, ets, "port");
}

static sai_status_t group_update_ets(sx_port_log_id_t             port_log_id,
                                     sx_cos_ets_element_config_t *ets,
                                     uint8_t                      level,
                                     uint8_t                      index)
{
    ets->element_hierarchy = level;
    ets->element_index     = index;
    if (level == 0) {
        return port_update_ets(port_log_id, ets);
    }

    /* The following are SDK limitations */
    if (level == 1) {
        ets->min_shaper_enable = FALSE;
        ets->max_shaper_enable = FALSE;
    }
    return ets_element_update(port_log_id, ets, "group");
}

/* DB read lock is required */
static sai_status_t scheduler_to_group_apply(sai_object_id_t  scheduler_id,
                                             sx_port_log_id_t port_id,
                                             uint8_t          level,
                                             uint8_t          index)
{
    sx_cos_ets_element_config_t ets = {0};
    sai_status_t                status;
    mlnx_sched_profile_t       *sched;

    if (scheduler_id != SAI_NULL_OBJECT_ID) {
        status = sched_db_entry_get(scheduler_id, &sched);
        if (SAI_ERR(status)) {
            return status;
        }

        if ((level == 1) && (sched->ets.dwrr == TRUE) && (sched->ets.dwrr_enable == TRUE)) {
            SX_LOG_ERR("DWRR alg type is not supported for groups on level 1\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        memcpy(&ets, &sched->ets, sizeof(ets));
        sai_to_sdk_rate(sched->min_rate, sched->max_rate, &ets);
    } else {
        sai_to_sdk_rate(0, 0, &ets);
    }

    return group_update_ets(port_id, &ets, level, index);
}

static mlnx_iter_ret_t sched_profile_update_groups(mlnx_qos_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;
    sai_object_id_t        scheduler_id;

    assert(port != NULL);
    assert(ctx != NULL);
    assert(ctx->arg != NULL);

    scheduler_id = *(sai_object_id_t*)ctx->arg;

    if (obj->type != MLNX_SCHED_OBJ_GROUP) {
        return ITER_NEXT;
    }

    if (scheduler_id == obj->scheduler_id) {
        ctx->sai_status = scheduler_to_group_apply(scheduler_id, port->log_port_id, obj->level,
                                                   obj->index);
        if (SAI_ERR(ctx->sai_status)) {
            return ITER_STOP;
        }
    }

    return ITER_NEXT;
}

static sai_status_t mlnx_sched_attr_setter(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    uint32_t                    attr_id = (sai_scheduler_attr_t)arg;
    mlnx_sched_profile_t       *sched;
    mlnx_qos_port_config_t     *port;
    mlnx_qos_queue_config_t    *queue;
    sx_cos_ets_element_config_t ets;
    sai_status_t                status;
    uint32_t                    ii, qi;
    mlnx_sched_iter_ctx_t       ctx;

    SX_LOG_ENTER();

    sai_qos_db_write_lock();

    status = sched_db_entry_get(key->object_id, &sched);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    assert(sched != NULL);
    assert(sched->is_used);

    switch (attr_id) {
    case SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM:
        if (value->s32 == SAI_SCHEDULING_DWRR) {
            sched->ets.dwrr = TRUE;
        } else if (value->s32 == SAI_SCHEDULING_STRICT) {
            sched->ets.dwrr = FALSE;
        } else {
            SX_LOG_ERR("Not supported alg type(%u)\n", value->s32);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
        break;

    case SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
        if (sched->ets.dwrr != TRUE) {
            SX_LOG_ERR("Weight can be used only for DWRR scheduler type\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        if ((value->u32 < 1) || (value->u32 > 100)) {
            SX_LOG_ERR("Weight must be in range 1..100, actual is %u\n", value->u32);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        sched->ets.dwrr_weight = value->u32;
        break;

    case SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE:
        sched->min_rate = value->u64;
        check_rate(value->u64, true);
        break;

    case SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
        sched->max_rate = value->u64;
        check_rate(value->u64, false);
        break;

    case SAI_SCHEDULER_ATTR_SHAPER_TYPE:
        if (value->s32 != SAI_METER_TYPE_BYTES) {
            SX_LOG_ERR("Only bytes/s shaper type is supported\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
        break;
    }

    memcpy(&ets, &sched->ets, sizeof(ets));
    sai_to_sdk_rate(sched->min_rate, sched->max_rate, &ets);

    qos_port_foreach(port, ii) {
        if (port->scheduler_id == key->object_id) {
            status = port_update_ets(port->log_port_id, &ets);

            if (status != SAI_STATUS_SUCCESS) {
                goto out;
            }
        }

        port_queues_foreach(port, queue, qi) {
            if (queue->sched_obj.scheduler_id == key->object_id) {
                status = queue_update_ets(port->log_port_id, &ets, &queue->sched_obj);

                if (status != SAI_STATUS_SUCCESS) {
                    goto out;
                }
            }
        }

        ctx.sai_status = SAI_STATUS_SUCCESS;
        ctx.arg        = (void*)&key->object_id;

        status = mlnx_sched_hierarchy_foreach(port, sched_profile_update_groups, &ctx);
        if (status != SAI_STATUS_SUCCESS) {
            goto out;
        }
    }

out:
    if (status == SAI_STATUS_SUCCESS) {
        sai_qos_db_sync();
    }

    SX_LOG_EXIT();

    sai_qos_db_unlock();
    return status;
}

sai_status_t mlnx_scheduler_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_log_verbosity_level_set(gh_sdk,
                                                             SX_LOG_VERBOSITY_BOTH, level, level));
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief  Create Scheduler Profile
 *
 * @param[out] scheduler_id Scheduler id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_create_scheduler_profile(_Out_ sai_object_id_t      *scheduler_id,
                                                  _In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *attr;
    mlnx_sched_profile_t         sched;
    sai_status_t                 status;
    uint32_t                     index;
    uint32_t                     ii;

    SX_LOG_ENTER();

    if (NULL == scheduler_id) {
        SX_LOG_ERR("NULL scheduler id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, sched_attribs,
                                    sched_vendor_attribs,
                                    SAI_COMMON_API_CREATE);

    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    /* Set default values */
    sched.ets.max_shaper_rate   = 0;
    sched.ets.min_shaper_rate   = 0;
    sched.ets.max_shaper_enable = TRUE;
    sched.ets.min_shaper_enable = TRUE;
    sched.ets.dwrr_enable       = TRUE;
    sched.ets.dwrr_weight       = 1;
    sched.ets.dwrr              = TRUE;
    sched.ets.packets_mode      = FALSE;
    sched.is_used               = TRUE;
    sched.min_rate              = 0;
    sched.max_rate              = 0;

    /* Handle SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM */
    status = find_attrib_in_list(attr_count, attr_list,
                                 SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM,
                                 &attr, &index);

    if (status == SAI_STATUS_SUCCESS) {
        if (attr->s32 == SAI_SCHEDULING_STRICT) {
            sched.ets.dwrr = FALSE;
        } else if (attr->s32 != SAI_SCHEDULING_DWRR) {
            SX_LOG_ERR("Not supported alg type=%d\n", attr->s32);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    /* Handle SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT */
    status = find_attrib_in_list(attr_count, attr_list,
                                 SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
                                 &attr, &index);

    if (status == SAI_STATUS_SUCCESS) {
        if (!sched.ets.dwrr) {
            SX_LOG_ERR("Weight requires DWRR algorithm\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if ((attr->u32 < 1) || (attr->u32 > 100)) {
            SX_LOG_ERR("Weight must be in range 1..100, actual is %u\n", attr->u32);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        sched.ets.dwrr_weight = attr->u32;
    }

    /* Handle SAI_SCHEDULER_ATTR_SHAPER_TYPE */
    status = find_attrib_in_list(attr_count, attr_list,
                                 SAI_SCHEDULER_ATTR_SHAPER_TYPE,
                                 &attr, &index);

    if ((status == SAI_STATUS_SUCCESS) && (attr->s32 != SAI_METER_TYPE_BYTES)) {
        SX_LOG_ERR("Only bytes/s meter type is supported\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Handle SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE */
    status = find_attrib_in_list(attr_count, attr_list,
                                 SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE,
                                 &attr, &index);

    if (status == SAI_STATUS_SUCCESS) {
        sched.min_rate = attr->u64;
        check_rate(attr->u64, true);
    }

    /* Handle SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE */
    status = find_attrib_in_list(attr_count, attr_list,
                                 SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
                                 &attr, &index);

    if (status == SAI_STATUS_SUCCESS) {
        sched.max_rate = attr->u64;
        check_rate(attr->u64, false);
    }

    if ((sched.max_rate > 0) && (sched.min_rate > sched.max_rate)) {
        SX_LOG_ERR("Scheduler min bandwidth rate can't be > max bandwidth rate\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_qos_db_write_lock();

    for (ii = 0; ii < MAX_SCHED; ii++) {
        if (sai_qos_sched_db[ii].is_used) {
            continue;
        }

        status = mlnx_create_object(SAI_OBJECT_TYPE_SCHEDULER, ii, NULL,
                                    scheduler_id);

        if (status != SAI_STATUS_SUCCESS) {
            sai_qos_db_unlock();
            return status;
        }

        SX_LOG_NTC("Allocated scheduler with index=%u\n", ii);

        memcpy(&sai_qos_sched_db[ii], &sched, sizeof(sched));

        break;
    }

    if (ii == MAX_SCHED) {
        sai_qos_db_unlock();
        SX_LOG_ERR("QoS Scheduler DB is full\n");
        return SAI_STATUS_TABLE_FULL;
    }

    sai_qos_db_sync();
    sai_qos_db_unlock();

    SX_LOG_NTC("Created scheduler id=%" PRIx64 "\n", *scheduler_id);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static mlnx_iter_ret_t sched_profile_use_check(mlnx_qos_port_config_t *cfg, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;

    assert(ctx != NULL);

    if (obj->scheduler_id == *(sai_object_id_t*)ctx->arg) {
        ctx->sai_status = SAI_STATUS_OBJECT_IN_USE;
        return ITER_STOP;
    }

    return ITER_NEXT;
}

/**
 * @brief  Remove Scheduler profile
 *
 * @param[in] scheduler_id Scheduler id
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_remove_scheduler_profile(_In_ sai_object_id_t scheduler_id)
{
    mlnx_qos_port_config_t *port;
    mlnx_sched_profile_t   *sched;
    mlnx_sched_iter_ctx_t   ctx = { .arg = &scheduler_id, .sai_status = SAI_STATUS_SUCCESS };
    sai_status_t            status;
    uint32_t                ii;

    SX_LOG_ENTER();

    sai_qos_db_write_lock();

    status = sched_db_entry_get(scheduler_id, &sched);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    qos_port_foreach(port, ii) {
        /* Check if scheduler is bound to the port */
        if (port->scheduler_id == scheduler_id) {
            SX_LOG_ERR("Can't remove scheduler_id %" PRIx64 ", used by port log id 0x%x\n",
                       scheduler_id, port->log_port_id);

            status = SAI_STATUS_OBJECT_IN_USE;
            goto out;
        }

        status = mlnx_sched_hierarchy_foreach(port, sched_profile_use_check, &ctx);
        if (status != SAI_STATUS_SUCCESS) {
            goto out;
        }
    }

    sched->is_used = false;

out:
    if (status == SAI_STATUS_SUCCESS) {
        sai_qos_db_sync();
    }

    sai_qos_db_unlock();

    if (status == SAI_STATUS_SUCCESS) {
        SX_LOG_NTC("Removed scheduler id=%" PRIx64 "\n", scheduler_id);
    }

    SX_LOG_EXIT();
    return status;
}

static void mlnx_sched_key_to_str(_In_ sai_object_id_t qos_map_id, _Out_ char *key_str)
{
    sai_status_t sai_status;
    uint32_t     id;

    sai_status = mlnx_object_to_type(qos_map_id, SAI_OBJECT_TYPE_SCHEDULER,
                                     &id, NULL);

    if (sai_status != SAI_STATUS_SUCCESS) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid scheduler id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "scheduler id %u", id);
    }
}

/**
 * @brief  Set Scheduler Attribute
 *
 * @param[in] scheduler_id Scheduler id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_set_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = scheduler_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    mlnx_sched_key_to_str(scheduler_id, key_str);
    return sai_set_attribute(&key, key_str, sched_attribs, sched_vendor_attribs, attr);
}

/**
 * @brief  Get Scheduler attribute
 *
 * @param[in] scheduler_id - scheduler id
 * @param[in] attr_count - number of attributes
 * @param[inout] attr_list - array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */

static sai_status_t mlnx_get_scheduler_attribute(_In_ sai_object_id_t     scheduler_id,
                                                 _In_ uint32_t            attr_count,
                                                 _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = scheduler_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    mlnx_sched_key_to_str(scheduler_id, key_str);
    return sai_get_attributes(&key, key_str, sched_attribs,
                              sched_vendor_attribs, attr_count, attr_list);
}

sai_status_t mlnx_scheduler_to_port_apply(sai_object_id_t scheduler_id, sai_object_id_t port_id)
{
    sx_port_log_id_t            port_log_id;
    sx_cos_ets_element_config_t ets;
    mlnx_sched_profile_t       *sched;
    sai_status_t                status;
    uint32_t                    port_idx;

    status = mlnx_object_to_type(port_id, SAI_OBJECT_TYPE_PORT, &port_log_id, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    status = mlnx_qos_get_port_index(port_log_id, &port_idx);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    memset(&ets, 0, sizeof(ets));

    sai_qos_db_write_lock();

    if (scheduler_id != SAI_NULL_OBJECT_ID) {
        status = sched_db_entry_get(scheduler_id, &sched);
        if (status != SAI_STATUS_SUCCESS) {
            goto out;
        }

        if (sched->ets.dwrr) {
            status = SAI_STATUS_INVALID_PARAMETER;
            SX_LOG_ERR("DWRR can't be used on the port\n");
            goto out;
        }

        if (sched->min_rate > 0) {
            status = SAI_STATUS_INVALID_PARAMETER;
            SX_LOG_ERR("Min bandwidth rate can't be used on the port\n");
            goto out;
        }

        memcpy(&ets, &sched->ets, sizeof(ets));
        sai_to_sdk_rate(sched->min_rate, sched->max_rate, &ets);
    } else {
        sai_to_sdk_rate(0, 0, &ets);
    }

    status = port_update_ets(port_log_id, &ets);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    sai_qos_port_db[port_idx].scheduler_id = scheduler_id;
    sai_qos_db_sync();

out:
    sai_qos_db_unlock();
    return status;
}

/* DB write lock is required */
sai_status_t mlnx_scheduler_to_group_apply(sai_object_id_t scheduler_id, sai_object_id_t group_id)
{
    mlnx_qos_port_config_t *port;
    sx_port_log_id_t        port_id;
    sai_status_t            status;
    uint8_t                 level;
    uint8_t                 index;

    status = mlnx_sched_group_parse_id(group_id, &port_id, &level, &index);
    if (SAI_ERR(status)) {
        return status;
    }

    status = scheduler_to_group_apply(scheduler_id, port_id, level, index);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_port_qos_cfg_lookup(port_id, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_DBG("Set scheduler profile id %" PRIx64 " on group at port %x level %u index %u\n",
               scheduler_id, port_id, level, index);

    port->sched_hierarchy.groups[level][index].scheduler_id = scheduler_id;
    return status;
}

/* DB read/write lock is needed */
sai_status_t __mlnx_scheduler_to_queue_apply(sai_object_id_t   scheduler_id,
                                             sx_port_log_id_t  port_log_id,
                                             mlnx_sched_obj_t *obj)
{
    sx_cos_ets_element_config_t ets;
    mlnx_sched_profile_t       *sched;
    sai_status_t                status;

    memset(&ets, 0, sizeof(ets));

    if (scheduler_id != SAI_NULL_OBJECT_ID) {
        status = sched_db_entry_get(scheduler_id, &sched);

        if (SAI_ERR(status)) {
            sai_qos_db_unlock();
            return status;
        }

        memcpy(&ets, &sched->ets, sizeof(ets));
        sai_to_sdk_rate(sched->min_rate, sched->max_rate, &ets);
    } else {
        sai_to_sdk_rate(0, 0, &ets);
    }

    status = queue_update_ets(port_log_id, &ets, obj);
    if (SAI_ERR(status)) {
        return status;
    }

    return status;
}

sai_status_t mlnx_scheduler_to_queue_apply(sai_object_id_t scheduler_id, sai_object_id_t queue_id)
{
    uint8_t                  ext_data[EXTENDED_DATA_SIZE] = {0};
    uint32_t                 queue_index;
    sx_port_log_id_t         port_log_id;
    mlnx_qos_queue_config_t *queue;
    sai_status_t             status;

    status = mlnx_object_to_type(queue_id, SAI_OBJECT_TYPE_QUEUE, &port_log_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    queue_index = ext_data[0];
    /* TODO: Customer specific limitation */
    if (queue_index >= MAX_USED_TC) {
        SX_LOG_ERR("Queues with index >= 8 are not supported by scheduler\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sai_qos_db_write_lock();

    status = mlnx_queue_cfg_lookup(port_log_id, queue_index, &queue);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    status = __mlnx_scheduler_to_queue_apply(scheduler_id, port_log_id, &queue->sched_obj);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to apply scheduler parameters to queue %" PRIx64 ", index %u\n",
                   queue_id, queue_index);
        goto out;
    }

    queue->sched_obj.scheduler_id = scheduler_id;

    sai_qos_db_sync();

out:
    sai_qos_db_unlock();
    return status;
}

/**
 * @brief  Scheduler methods table retrieved with sai_api_query()
 */
const sai_scheduler_api_t mlnx_scheduler_api = {
    mlnx_create_scheduler_profile,
    mlnx_remove_scheduler_profile,
    mlnx_set_scheduler_attribute,
    mlnx_get_scheduler_attribute
};
