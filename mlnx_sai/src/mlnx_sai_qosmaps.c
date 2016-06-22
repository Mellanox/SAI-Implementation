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
#define __MODULE__ SAI_QOS_MAPS

static sai_status_t mlnx_qos_map_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_qos_map_list_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
static sai_status_t mlnx_qos_map_list_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t        qos_map_attribs[] = {
    { SAI_QOS_MAP_ATTR_TYPE, true, true, false, true,
      "QoS map type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, false, true, true, true,
      "QoS map params list", SAI_ATTR_VAL_TYPE_QOSMAP },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t qos_map_vendor_attribs[] = {
    { SAI_QOS_MAP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_qos_map_type_get, NULL,
      NULL, NULL },
    { SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_qos_map_list_get, NULL,
      mlnx_qos_map_list_set, NULL },
};

/* db read lock is needed */
static mlnx_qos_map_t * db_qos_map_get(uint32_t id)
{
    return &g_sai_db_ptr->qos_maps_db[id - 1];
}

/* db read lock is needed */
static sai_status_t db_qos_map_check_if_exist(uint32_t id)
{
    mlnx_qos_map_t *qos_map;

    if (!id || (id > MAX_QOS_MAPS)) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    qos_map = db_qos_map_get(id);
    if (!qos_map->is_used) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

/* db read/write lock is needed */
static sai_status_t db_qos_map_alloc(uint32_t *id)
{
    int ii;

    for (ii = 1; ii <= MAX_QOS_MAPS; ii++) {
        mlnx_qos_map_t *qos_map = db_qos_map_get(ii);

        if (!qos_map->is_used) {
            *id              = ii;
            qos_map->is_used = true;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_TABLE_FULL;
}

/* db read/write lock is needed */
static sai_status_t db_qos_map_free(uint32_t id)
{
    sai_status_t status;

    status = db_qos_map_check_if_exist(id);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    memset(db_qos_map_get(id), 0, sizeof(mlnx_qos_map_t));
    return SAI_STATUS_SUCCESS;
}

static void qos_map_param_err(const char *name, uint32_t param, uint32_t ii)
{
    SX_LOG_ERR("Invalid %s value in QoS map list: [%u]=%u\n", name, ii, param);
}

static bool qos_map_dscp_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_COS_DSCP_CHECK_RANGE(param)) {
        qos_map_param_err("dscp", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_dot1p_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_COS_PCP_CHECK_RANGE(param)) {
        qos_map_param_err("dot1p", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_tc_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_CHECK_MAX(param, MAX_PORT_PRIO)) {
        qos_map_param_err("tc", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_color_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_CHECK_MAX(param, MLNX_QOS_MAP_COLOR_MAX)) {
        qos_map_param_err("color", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_queue_index_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_CHECK_MAX(param, SX_COS_TCLASS_REQUIRED)) {
        qos_map_param_err("queue_index", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_pg_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_CHECK_MAX(param, SXD_COS_PORT_PRIO_MAX)) {
        qos_map_param_err("pg", param, ii);
        return false;
    }

    return true;
}

static bool qos_map_pfc_param_is_valid(uint32_t param, uint32_t ii)
{
    if (!SX_COS_IEEE_PRIO_CHECK_RANGE(param)) {
        qos_map_param_err("pfc prio", param, ii);
        return false;
    }

    return true;
}

static sai_status_t sai_dot1p_to_tc_color_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t count = qos_params->count;
    uint32_t ii;

    for (ii = 0; ii < count; ii++) {
        if (!qos_map_dot1p_param_is_valid(qos_params->list[ii].key.dot1p, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if ((qos_map->type == SAI_QOS_MAP_DOT1P_TO_TC) &&
            !qos_map_tc_param_is_valid(qos_params->list[ii].value.tc, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if ((qos_map->type == SAI_QOS_MAP_DOT1P_TO_COLOR) &&
            !qos_map_color_param_is_valid(qos_params->list[ii].value.color, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (ii = 0; ii < count; ii++) {
        qos_map->from.pcp_dei[ii].pcp       = qos_params->list[ii].key.dot1p;
        qos_map->from.pcp_dei[ii].dei       = 0;
        qos_map->to.prio_color[ii].priority = qos_params->list[ii].value.tc;
        qos_map->to.prio_color[ii].color    = qos_params->list[ii].value.color;

        /* The trick is to use double map with dei=0 & dei=1 */
        qos_map->from.pcp_dei[ii + count].pcp       = qos_params->list[ii].key.dot1p;
        qos_map->from.pcp_dei[ii + count].dei       = 1;
        qos_map->to.prio_color[ii + count].priority = qos_params->list[ii].value.tc;
        qos_map->to.prio_color[ii + count].color    = qos_params->list[ii].value.color;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_dscp_to_tc_color_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_dscp_param_is_valid(qos_params->list[ii].key.dscp, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if ((qos_map->type == SAI_QOS_MAP_DSCP_TO_TC) &&
            !qos_map_tc_param_is_valid(qos_params->list[ii].value.tc, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if ((qos_map->type == SAI_QOS_MAP_DSCP_TO_COLOR) &&
            !qos_map_color_param_is_valid(qos_params->list[ii].value.color, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.dscp[ii]              = qos_params->list[ii].key.dscp;
        qos_map->to.prio_color[ii].priority = qos_params->list[ii].value.tc;
        qos_map->to.prio_color[ii].color    = qos_params->list[ii].value.color;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_tc_to_queue_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_tc_param_is_valid(qos_params->list[ii].key.tc, ii) ||
            !qos_map_queue_index_param_is_valid(qos_params->list[ii].value.queue_index, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }
    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.prio_color[ii].priority = qos_params->list[ii].key.tc;
        qos_map->to.queue[ii]                 = qos_params->list[ii].value.queue_index;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_tc_and_color_to_dscp_mlnx_convert(mlnx_qos_map_t           *qos_map,
                                                          const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_tc_param_is_valid(qos_params->list[ii].key.tc, ii) ||
            !qos_map_color_param_is_valid(qos_params->list[ii].key.color, ii) ||
            !qos_map_dscp_param_is_valid(qos_params->list[ii].value.dscp, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }
    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.prio_color[ii].priority = qos_params->list[ii].key.tc;
        qos_map->from.prio_color[ii].color    = qos_params->list[ii].key.color;
        qos_map->to.dscp[ii]                  = qos_params->list[ii].value.dscp;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_tc_and_color_to_dot1p_mlnx_convert(mlnx_qos_map_t           *qos_map,
                                                           const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_tc_param_is_valid(qos_params->list[ii].key.tc, ii) ||
            !qos_map_color_param_is_valid(qos_params->list[ii].key.color, ii) ||
            !qos_map_dot1p_param_is_valid(qos_params->list[ii].value.dot1p, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }
    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.prio_color[ii].priority = qos_params->list[ii].key.tc;
        qos_map->from.prio_color[ii].color    = qos_params->list[ii].key.color;
        qos_map->to.pcp_dei[ii].pcp           = qos_params->list[ii].value.dot1p;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_tc_to_pg_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_tc_param_is_valid(qos_params->list[ii].key.tc, ii) ||
            !qos_map_pg_param_is_valid(qos_params->list[ii].value.pg, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.prio_color[ii].priority = qos_params->list[ii].key.tc;
        qos_map->to.pg[ii]                    = qos_params->list[ii].value.pg;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_pfc_to_pg_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_pfc_param_is_valid(qos_params->list[ii].key.prio, ii) ||
            !qos_map_tc_param_is_valid(qos_params->list[ii].value.pg, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.pfc[ii] = qos_params->list[ii].key.prio;
        qos_map->to.pg[ii]    = qos_params->list[ii].value.pg;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_pfc_to_queue_mlnx_convert(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    uint32_t ii;

    for (ii = 0; ii < qos_params->count; ii++) {
        if (!qos_map_pfc_param_is_valid(qos_params->list[ii].key.prio, ii) ||
            !qos_map_queue_index_param_is_valid(qos_params->list[ii].value.queue_index, ii)) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (ii = 0; ii < qos_params->count; ii++) {
        qos_map->from.pfc[ii] = qos_params->list[ii].key.prio;
        qos_map->to.queue[ii] = qos_params->list[ii].value.queue_index;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Fill default QoS map params by type
 *
 * @param[inout] qos_map params with specified type
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t mlnx_qos_map_set_default(_Inout_ mlnx_qos_map_t *qos_map)
{
    sai_qos_map_type_t qos_map_type = qos_map->type;
    bool               is_used      = qos_map->is_used;
    uint32_t           ii;

    memset(qos_map, 0, sizeof(*qos_map));
    qos_map->type    = qos_map_type;
    qos_map->is_used = is_used;

    /* We fill all keys. Default values equal zero by memset */
    if ((qos_map->type == SAI_QOS_MAP_DOT1P_TO_TC) ||
        (qos_map->type == SAI_QOS_MAP_DOT1P_TO_COLOR)) {
        qos_map->count = COS_PCP_MAX_NUM + 1;

        for (ii = 0; ii < qos_map->count; ii++) {
            qos_map->from.pcp_dei[ii].pcp = ii;
        }
    } else if ((qos_map->type == SAI_QOS_MAP_DSCP_TO_TC) ||
               (qos_map->type == SAI_QOS_MAP_DSCP_TO_COLOR)) {
        qos_map->count = SX_COS_PORT_DSCP_MAX + 1;

        for (ii = 0; ii < qos_map->count; ii++) {
            qos_map->from.dscp[ii] = ii;
        }
    } else if (qos_map->type == SAI_QOS_MAP_TC_TO_QUEUE) {
        qos_map->count = MAX_PORT_PRIO + 1;

        for (ii = 0; ii < qos_map->count; ii++) {
            qos_map->from.prio_color[ii].priority = ii;
        }
    } else if (qos_map->type == SAI_QOS_MAP_TC_TO_PRIORITY_GROUP) {
        qos_map->count = MAX_PORT_PRIO + 1;

        for (ii = 0; ii < qos_map->count; ii++) {
            qos_map->from.prio_color[ii].priority = ii;
        }
    } else if (qos_map->type == SAI_QOS_MAP_PFC_PRIORITY_TO_PRIORITY_GROUP) {
        qos_map->count = SXD_COS_PORT_PRIO_MAX + 1;

        for (ii = 0; ii < qos_map->count; ii++) {
            qos_map->from.pfc[ii] = ii;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t db_qos_map_fill_params(mlnx_qos_map_t *qos_map, const sai_qos_map_list_t *qos_params)
{
    sai_status_t status;

    if (!qos_params) {
        return mlnx_qos_map_set_default(qos_map);
    }

    if (qos_params->count > MLNX_QOS_MAP_CODES_MAX) {
        SX_LOG_ERR("Map overflow %u %u\n", qos_params->count, MLNX_QOS_MAP_CODES_MAX);
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    switch (qos_map->type) {
    case SAI_QOS_MAP_DOT1P_TO_TC:
    case SAI_QOS_MAP_DOT1P_TO_COLOR:
        status = sai_dot1p_to_tc_color_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_DSCP_TO_TC:
    case SAI_QOS_MAP_DSCP_TO_COLOR:
        status = sai_dscp_to_tc_color_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_TC_TO_QUEUE:
        status = sai_tc_to_queue_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_TC_AND_COLOR_TO_DSCP:
        status = sai_tc_and_color_to_dscp_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_TC_AND_COLOR_TO_DOT1P:
        status = sai_tc_and_color_to_dot1p_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_TC_TO_PRIORITY_GROUP:
        status = sai_tc_to_pg_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_PFC_PRIORITY_TO_PRIORITY_GROUP:
        status = sai_pfc_to_pg_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_PFC_PRIORITY_TO_QUEUE:
        status = sai_pfc_to_queue_mlnx_convert(qos_map, qos_params);
        break;

    case SAI_QOS_MAP_CUSTOM_RANGE_BASE:
    default:
        SX_LOG_ERR("Invalid QoS map type (%u)\n", qos_map->type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (status == SAI_STATUS_SUCCESS) {
        qos_map->count = qos_params->count;
    }

    return status;
}

static void qos_map_key_to_str(_In_ sai_object_id_t qos_map_id, _Out_ char *key_str)
{
    sai_status_t sai_status;
    uint32_t     id;

    sai_status = mlnx_object_to_type(qos_map_id, SAI_OBJECT_TYPE_QOS_MAPS,
                                     &id, NULL);

    if (sai_status != SAI_STATUS_SUCCESS) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid qos map id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "qos map id %u", id);
    }
}


/** Qos Map type [sai_qos_map_type_t] (MANDATORY_ON_CREATE|CREATE_ONLY) */
static sai_status_t mlnx_qos_map_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    mlnx_qos_map_t *qos_map;
    sai_status_t    status;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_qos_map_get_by_id(key->object_id, &qos_map);
    if (status == SAI_STATUS_SUCCESS) {
        value->u32 = qos_map->type;
    }

    sai_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/** QoS Mapping List [sai_qos_map_list_t],
 *
 * Defaults:
 *   All Dot1p/DSCP maps to traffic class 0
 *   All Dot1p/DSCP maps to color SAI_PACKET_COLOR_GREEN
 *   All traffic class maps to queue 0.
 */
static sai_status_t mlnx_qos_map_list_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_qos_map_list_t *qos_params = &value->qosmap;
    mlnx_qos_map_t     *qos_map;
    sai_status_t        status;
    uint32_t            ii;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_qos_map_get_by_id(key->object_id, &qos_map);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed get QoS map by oid\n");
        goto out;
    }

    if (qos_params->count < qos_map->count) {
        SX_LOG_ERR("Insufficient list buffer size.Allocated %u needed %u\n",
                   qos_map->count, qos_params->count);
        qos_params->count = qos_map->count;
        status            = SAI_STATUS_BUFFER_OVERFLOW;
        goto out;
    }
    qos_params->count = qos_map->count;

    for (ii = 0; ii < qos_params->count; ii++) {
        switch (qos_map->type) {
        case SAI_QOS_MAP_DOT1P_TO_TC:
        case SAI_QOS_MAP_DOT1P_TO_COLOR:
            qos_params->list[ii].key.dot1p   = qos_map->from.pcp_dei[ii].pcp;
            qos_params->list[ii].value.tc    = qos_map->to.prio_color[ii].priority;
            qos_params->list[ii].value.color = qos_map->to.prio_color[ii].color;
            break;

        case SAI_QOS_MAP_DSCP_TO_TC:
        case SAI_QOS_MAP_DSCP_TO_COLOR:
            qos_params->list[ii].key.dscp    = qos_map->from.dscp[ii];
            qos_params->list[ii].value.tc    = qos_map->to.prio_color[ii].priority;
            qos_params->list[ii].value.color = qos_map->to.prio_color[ii].color;
            break;

        case SAI_QOS_MAP_TC_TO_QUEUE:
            qos_params->list[ii].key.tc            = qos_map->from.prio_color[ii].priority;
            qos_params->list[ii].value.queue_index = qos_map->to.queue[ii];
            break;

        case SAI_QOS_MAP_TC_AND_COLOR_TO_DSCP:
            qos_params->list[ii].key.tc     = qos_map->from.prio_color[ii].priority;
            qos_params->list[ii].key.color  = qos_map->from.prio_color[ii].color;
            qos_params->list[ii].value.dscp = qos_map->to.dscp[ii];
            break;

        case SAI_QOS_MAP_TC_AND_COLOR_TO_DOT1P:
            qos_params->list[ii].key.tc      = qos_map->from.prio_color[ii].priority;
            qos_params->list[ii].key.color   = qos_map->from.prio_color[ii].color;
            qos_params->list[ii].value.dot1p = qos_map->to.pcp_dei[ii].pcp;
            break;

        case SAI_QOS_MAP_TC_TO_PRIORITY_GROUP:
            qos_params->list[ii].key.tc   = qos_map->from.prio_color[ii].priority;
            qos_params->list[ii].value.pg = qos_map->to.pg[ii];
            break;

        case SAI_QOS_MAP_PFC_PRIORITY_TO_PRIORITY_GROUP:
            qos_params->list[ii].key.prio = qos_map->from.pfc[ii];
            qos_params->list[ii].value.pg = qos_map->to.pg[ii];
            break;

        case SAI_QOS_MAP_PFC_PRIORITY_TO_QUEUE:
            qos_params->list[ii].key.prio          = qos_map->from.pfc[ii];
            qos_params->list[ii].value.queue_index = qos_map->to.queue[ii];
            break;

        case SAI_QOS_MAP_CUSTOM_RANGE_BASE:
        default:
            SX_LOG_ERR("Invalid QoS map type (%u)\n", qos_map->type);
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* QoS Mapping List [sai_qos_map_list_t] */
static sai_status_t mlnx_qos_map_list_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    mlnx_port_config_t *port;
    mlnx_qos_map_t     *qos_map;
    uint32_t            qos_map_idx;
    sai_status_t        status;
    uint32_t            port_idx;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_QOS_MAPS, &qos_map_idx, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Invalid qos map id\n");
        return status;
    }

    sai_db_write_lock();

    status = mlnx_qos_map_get_by_id(key->object_id, &qos_map);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    status = db_qos_map_fill_params(qos_map, &value->qosmap);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Error while fill QoS params\n");
        goto out;
    }

    mlnx_port_foreach(port, port_idx) {
        if (port->qos_maps[qos_map->type] != qos_map_idx) {
            continue;
        }

        status = mlnx_port_qos_map_apply(port->saiport, key->object_id, qos_map->type);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("Failed to update port %" PRIx64 " with new QoS map\n", port->saiport);
            goto out;
        }

        SX_LOG_NTC("Port %" PRIx64 " was updated with new QoS map\n", port->saiport);
    }

out:
    sai_db_sync();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_qos_map_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create Qos Map
 *
 * @param[out] qos_map_id Qos Map Id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_create_qos_map(_Out_ sai_object_id_t     * qos_map_id,
                                        _In_ uint32_t               attr_count,
                                        _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *type, *list = NULL;
    char                         value_str[MAX_VALUE_STR_LEN];
    uint32_t                     type_index, list_index;
    mlnx_qos_map_t              *qos_map;
    sai_status_t                 status;
    uint32_t                     new_id;

    *value_str = '\0';

    SX_LOG_ENTER();

    if (NULL == qos_map_id) {
        SX_LOG_ERR("NULL qos map id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, qos_map_attribs,
                                    qos_map_vendor_attribs,
                                    SAI_COMMON_API_CREATE);

    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_QOS_MAP_ATTR_TYPE,
                                 &type, &type_index);

    assert(status == SAI_STATUS_SUCCESS);

    sai_db_write_lock();

    status = db_qos_map_alloc(&new_id);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed to alloc qos map\n");
        goto out;
    }

    qos_map       = db_qos_map_get(new_id);
    qos_map->type = type->u32;

    status = find_attrib_in_list(attr_count, attr_list, SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
                                 &list, &list_index);

    status = db_qos_map_fill_params(qos_map, status == SAI_STATUS_SUCCESS ? &list->qosmap : NULL);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed to fill new qos map params\n");
        db_qos_map_free(new_id);
        goto out;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_QOS_MAPS, new_id, NULL, qos_map_id);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed create mlnx object id\n");
        db_qos_map_free(new_id);
        goto out;
    }

    if (list) {
        sai_qos_map_to_str(&list->qosmap, type->u32, MAX_VALUE_STR_LEN, value_str);
    }

    SX_LOG_NTC("Created qos map id %" PRIx64 ", %s\n", *qos_map_id, value_str);

out:
    sai_db_sync();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove Qos Map
 *
 *  @param[in] qos_map_id Qos Map id to be removed.
 *
 *  @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
static sai_status_t mlnx_remove_qos_map(_In_ sai_object_id_t qos_map_id)
{
    mlnx_qos_map_t     *qos_map;
    mlnx_port_config_t *port;
    sai_status_t        status;
    uint32_t            port_idx;
    uint32_t            del_id;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(qos_map_id, SAI_OBJECT_TYPE_QOS_MAPS, &del_id, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Invalid qos map id\n");
        return status;
    }

    sai_db_write_lock();

    status = mlnx_qos_map_get_by_id(qos_map_id, &qos_map);
    if (status != SAI_STATUS_SUCCESS) {
        goto out;
    }

    if (g_sai_db_ptr->switch_qos_maps[qos_map->type]) {
        status = SAI_STATUS_OBJECT_IN_USE;
        SX_LOG_ERR("QoS map is already in use by switch\n");
        goto out;
    }

    mlnx_port_foreach(port, port_idx) {
        if (port->qos_maps[qos_map->type] == del_id) {
            status = SAI_STATUS_OBJECT_IN_USE;
            SX_LOG_ERR("QoS map is already in use by port %" PRIx64 "\n", port->saiport);
            goto out;
        }
    }

    status = db_qos_map_free(del_id);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed to remove qos map id=%u\n", del_id);
    } else {
        sai_db_sync();
    }

out:
    sai_db_unlock();

    if (status == SAI_STATUS_SUCCESS) {
        SX_LOG_NTC("Removed QoS map id=%" PRIx64 "\n", qos_map_id);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set attributes for qos map
 *
 * @param[in] qos_map_id Qos Map Id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_set_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = qos_map_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    qos_map_key_to_str(qos_map_id, key_str);
    return sai_set_attribute(&key, key_str, qos_map_attribs, qos_map_vendor_attribs, attr);
}

/**
 * @brief  Get attrbutes of qos map
 *
 * @param[in] qos_map_id  map id
 * @param[in] attr_count  number of attributes
 * @param[inout] attr_list  array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */
static sai_status_t mlnx_get_qos_map_attribute(_In_ sai_object_id_t     qos_map_id,
                                               _In_ uint32_t            attr_count,
                                               _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = qos_map_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    qos_map_key_to_str(qos_map_id, key_str);
    return sai_get_attributes(&key, key_str, qos_map_attribs,
                              qos_map_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief  Lookup qos_map by oid (db read lock is needed)
 *
 * @param[in] qos_map_id  map id
 * @param[in] attr_count  number of attributes
 * @param[out] qos_map    QoS Map
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */
sai_status_t mlnx_qos_map_get_by_id(_In_ sai_object_id_t obj_id, _Inout_ mlnx_qos_map_t **qos_map)
{
    sai_status_t status;
    uint32_t     id;

    status = mlnx_object_to_type(obj_id, SAI_OBJECT_TYPE_QOS_MAPS, &id, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Invalid qos map id %" PRIx64 "\n", obj_id);
        return status;
    }

    status = db_qos_map_check_if_exist(id);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("QoS map does not exist with id %" PRIx64 "\n", obj_id);
        return status;
    }

    *qos_map = db_qos_map_get(id);
    return SAI_STATUS_SUCCESS;
}

const sai_qos_map_api_t mlnx_qos_maps_api = {
    mlnx_create_qos_map,
    mlnx_remove_qos_map,
    mlnx_set_qos_map_attribute,
    mlnx_get_qos_map_attribute,
};
