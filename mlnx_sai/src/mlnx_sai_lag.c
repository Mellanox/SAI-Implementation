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
#define __MODULE__ SAI_LAG

typedef enum port_params_ {
    PORT_PARAMS_QOS        = 1 << 0,
        PORT_PARAMS_WRED   = 1 << 1,
        PORT_PARAMS_MIRROR = 1 << 2,
        PORT_PARAMS_ALL    = ~0,
} port_params_t;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t lag_attribs[] = {
    { SAI_LAG_ATTR_PORT_LIST, false, false, false, true,
      "LAG port list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_lag_port_list_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static const sai_vendor_attribute_entry_t lag_vendor_attribs[] = {
    { SAI_LAG_ATTR_PORT_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_lag_port_list_get, NULL,
      NULL, NULL },
};
static const sai_attribute_entry_t        lag_member_attribs[] = {
    { SAI_LAG_MEMBER_ATTR_LAG_ID, true, true, false, true,
      "LAG ID for LAG Member", SAI_ATTR_VAL_TYPE_OID },
    { SAI_LAG_MEMBER_ATTR_PORT_ID, true, true, false, true,
      "PORT ID for LAG Member", SAI_ATTR_VAL_TYPE_OID },
    { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, false, true, true, true,
      "LAG Member Egress Disable", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, false, true, true, true,
      "LAG Member Ingress Disable", SAI_ATTR_VAL_TYPE_BOOL },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_lag_member_lag_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_lag_member_port_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_lag_member_egress_disable_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_lag_member_egress_disable_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_lag_member_ingress_disable_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_lag_member_ingress_disable_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static const sai_vendor_attribute_entry_t lag_member_vendor_attribs[] = {
    { SAI_LAG_MEMBER_ATTR_LAG_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_lag_member_lag_id_get, NULL,
      NULL, NULL },
    { SAI_LAG_MEMBER_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_lag_member_port_id_get, NULL,
      NULL, NULL },
    { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_lag_member_egress_disable_get, NULL,
      mlnx_lag_member_egress_disable_set, NULL },
    { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_lag_member_ingress_disable_get, NULL,
      mlnx_lag_member_ingress_disable_set, NULL },
};
static void lag_key_to_str(_In_ sai_object_id_t lag_id, _Out_ char *key_str)
{
    uint32_t lagid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lagid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG ID %u", lagid);
    }
}

static void lag_member_key_to_str(_In_ sai_object_id_t lag_member_id, _Out_ char *key_str)
{
    uint32_t lag_memberid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER, &lag_memberid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG Member ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG ID Member %u", lag_memberid);
    }
}

static sai_status_t mlnx_port_params_clone(mlnx_port_config_t *to, mlnx_port_config_t *from, port_params_t clone)
{
    sx_cos_rewrite_enable_t      rewrite_enable;
    uint32_t                     max_ets_count;
    sx_cos_trust_level_t         trust_level;
    sx_cos_ets_element_config_t *ets = NULL;
    sx_span_session_id_t         mirror_id;
    mlnx_qos_queue_config_t     *queue_cfg;
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    uint8_t                      prio;
    uint32_t                     ii;

    /* QoS */
    if (clone & PORT_PARAMS_QOS) {
        max_ets_count = MAX_ETS_ELEMENTS;
        ets           = (sx_cos_ets_element_config_t*)malloc(sizeof(sx_cos_ets_element_config_t) * max_ets_count);
        if (!ets) {
            return SAI_STATUS_NO_MEMORY;
        }

        status = sx_api_cos_port_default_prio_get(gh_sdk, from->logical, &prio);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get port's default traffic class - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_trust_get(gh_sdk, from->logical, &trust_level);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get trust level from port %x - %s\n", from->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_rewrite_enable_get(gh_sdk, from->logical, &rewrite_enable);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get dscp rewrite enable - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_ets_element_get(gh_sdk, from->logical, ets, &max_ets_count);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed get ETS list - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_default_prio_set(gh_sdk, to->logical, prio);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to set port's default prio(%u) - %s\n", prio, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        for (ii = 0; ii < MLNX_QOS_MAP_TYPES_MAX; ii++) {
            sai_object_id_t oid;

            if (from->qos_maps[ii]) {
                status = mlnx_create_object(SAI_OBJECT_TYPE_QOS_MAPS, from->qos_maps[ii], NULL, &oid);
                if (SAI_ERR(status)) {
                    goto out;
                }
            } else {
                oid = SAI_NULL_OBJECT_ID;
            }

            status = mlnx_port_qos_map_apply(to->saiport, oid, ii);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to update port 0x%x with QoS map %" PRIx64 "\n", to->logical, oid);
                goto out;
            }
        }

        status = sx_api_cos_port_rewrite_enable_set(gh_sdk, to->logical, rewrite_enable);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to set dscp rewrite enable from - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_ets_element_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                                 to->logical, ets, max_ets_count);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to update ETS elements on LAG port id 0x%x - %s\n", to->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_cos_port_trust_set(gh_sdk, to->logical, trust_level);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to set trust level for LAG %x - %s\n", to->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        /* Copy for the LAG actually, it needs when one of the profiles (Scheduler, QoS) will be changed
         * so the LAG will be updated with new changes */
        memcpy(&to->sched_hierarchy, &from->sched_hierarchy, sizeof(to->sched_hierarchy));
        memcpy(to->qos_maps, from->qos_maps, sizeof(to->qos_maps));
        from->scheduler_id = to->scheduler_id;
    }
    /* WRED */
    if (clone & PORT_PARAMS_WRED) {
        port_queues_foreach(from, queue_cfg, ii) {
            mlnx_qos_queue_config_t *to_queue;

            status = mlnx_queue_cfg_lookup(to->logical, ii, &to_queue);
            if (SAI_ERR(status)) {
                goto out;
            }
            to_queue->wred_id = queue_cfg->wred_id;

            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }
            if (queue_cfg->wred_id == SAI_NULL_OBJECT_ID) {
                continue;
            }

            status = __mlnx_wred_apply_to_queue_idx(to, ii, queue_cfg->wred_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        if (from->wred_id != SAI_NULL_OBJECT_ID) {
            status = __mlnx_wred_apply_to_port(to, from->wred_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
        to->wred_id = from->wred_id;
    }
    /* Mirroring */
    if (clone & PORT_PARAMS_MIRROR) {
        status = sx_api_span_mirror_get(gh_sdk, from->logical, SX_SPAN_MIRROR_INGRESS, &mirror_id);
        if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
            SX_LOG_ERR("Failed to get ingress mirror id - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
        if (status != SX_STATUS_ENTRY_NOT_FOUND) {
            status = sx_api_span_mirror_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                            to->logical, SX_SPAN_MIRROR_INGRESS, mirror_id);
            SX_LOG_ERR("Failed to set ingress mirror id %u to port %" PRIx64 "(0x%x) - %s\n",
                       mirror_id, to->saiport, to->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }

        status = sx_api_span_mirror_get(gh_sdk, from->logical, SX_SPAN_MIRROR_EGRESS, &mirror_id);
        if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
            SX_LOG_ERR("Failed to get egress mirror id - %s\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
        if (status != SX_STATUS_ENTRY_NOT_FOUND) {
            status = sx_api_span_mirror_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                            to->logical, SX_SPAN_MIRROR_EGRESS, mirror_id);
            SX_LOG_ERR("Failed to set egress mirror id %u to port %" PRIx64 "(0x%x) - %s\n",
                       mirror_id, to->saiport, to->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
        status = SAI_STATUS_SUCCESS;
    }

out:
    free(ets);
    return status;
}

static sai_status_t remove_port_from_lag(sx_port_log_id_t lag_id, sx_port_log_id_t port_id)
{
    sx_status_t         sx_status;
    sai_status_t        status;
    mlnx_port_config_t *port;
    mlnx_port_config_t *lag;

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        return status;
    }
    status = mlnx_port_by_log_id(lag_id, &lag);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                          &lag_id, &port_id, 1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed remove port log id %x from LAG log id %x - %s\n", port_id, lag_id,
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = mlnx_hash_ecmp_cfg_apply_on_port(port_id);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port learning mode - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* Do re-apply for port params which were removed by us before add to the LAG */
    status = mlnx_port_params_clone(port, lag, PORT_PARAMS_WRED | PORT_PARAMS_MIRROR);
    if (SAI_ERR(status)) {
        goto out;
    }

    port->lag_id = 0;

out:
    return status;
}

static sai_status_t mlnx_lag_remove_all_ports(sai_object_id_t lag_oid)
{
    sai_status_t      status;
    sx_port_log_id_t  lag_id;
    sx_status_t       sx_status;
    sx_port_log_id_t *port_list = NULL;
    uint32_t          port_cnt  = 0;
    uint32_t          ii        = 0;

    status = mlnx_object_to_type(lag_oid, SAI_OBJECT_TYPE_LAG, &lag_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag_id, NULL, &port_cnt);
    if (SX_ERR(sx_status)) {
        return sdk_to_sai(sx_status);
    }
    if (!port_cnt) {
        return SAI_STATUS_SUCCESS;
    }

    port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * port_cnt);
    if (NULL == port_list) {
        SX_LOG_ERR("Can't allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag_id, port_list, &port_cnt);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        goto out;
    }

    sai_db_write_lock();
    for (ii = 0; ii < port_cnt; ii++) {
        status = remove_port_from_lag(lag_id, port_list[ii]);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            goto out;
        }
    }
    sai_db_unlock();

out:
    free(port_list);
    return status;
}

/* TODO: print profiles info on error */
/* SDK already validate QoS settings, so just check WRED, Policer & Mirroring profiles */
static sai_status_t ports_l1_params_check(mlnx_port_config_t *port1, mlnx_port_config_t *port2)
{
    mlnx_qos_queue_config_t *queue_cfg1, *queue_cfg2;
    sx_span_session_id_t     mirror_id1, mirror_id2;
    sai_status_t             status;
    uint32_t                 ii;

    assert(port1 != NULL);
    assert(port2 != NULL);

    /* WRED */
    if (port1->wred_id != port2->wred_id) {
        SX_LOG_ERR("Port oid %" PRIx64 " and port oid %" PRIx64 " have different WRED profiles\n",
                   port1->saiport, port2->saiport);

        return SAI_STATUS_INVALID_PARAMETER;
    }
    port_queues_foreach(port1, queue_cfg1, ii) {
        status = mlnx_queue_cfg_lookup(port2->logical, ii, &queue_cfg2);
        if (SAI_ERR(status)) {
            return status;
        }

        if (queue_cfg1->wred_id != queue_cfg2->wred_id) {
            SX_LOG_ERR(
                "Port oid %" PRIx64 " and port oid %" PRIx64 " on queue index %u have different WRED profiles\n",
                port1->saiport,
                port2->saiport,
                ii);

            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    /* Mirroring */
    mirror_id1 = mirror_id2 = 0xff;
    status     = sx_api_span_mirror_get(gh_sdk, port1->logical, SX_SPAN_MIRROR_INGRESS, &mirror_id1);
    if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ingress mirror id - %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    status = sx_api_span_mirror_get(gh_sdk, port2->logical, SX_SPAN_MIRROR_INGRESS, &mirror_id2);
    if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ingress mirror id - %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    if (mirror_id1 != mirror_id2) {
        SX_LOG_ERR("Port oid %" PRIx64 " and port oid %" PRIx64 " have different mirror ingress session id\n",
                   port1->saiport, port2->saiport);

        return SAI_STATUS_INVALID_PARAMETER;
    }

    mirror_id1 = mirror_id2 = 0xff;
    status     = sx_api_span_mirror_get(gh_sdk, port1->logical, SX_SPAN_MIRROR_EGRESS, &mirror_id1);
    if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ingress mirror id - %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    status = sx_api_span_mirror_get(gh_sdk, port2->logical, SX_SPAN_MIRROR_EGRESS, &mirror_id2);
    if ((status != SX_STATUS_ENTRY_NOT_FOUND) && SX_ERR(status)) {
        SX_LOG_ERR("Failed to get ingress mirror id - %s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    if (mirror_id1 != mirror_id2) {
        SX_LOG_ERR("Port oid %" PRIx64 " and port oid %" PRIx64 " have different mirror egress session id\n",
                   port1->saiport, port2->saiport);

        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t validate_port(mlnx_port_config_t *lag, mlnx_port_config_t *port)
{
    if (port->vlans) {
        SX_LOG_ERR("Can't add port with created VLANs count=%u\n", port->vlans);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (port->fdbs) {
        SX_LOG_ERR("Can't add port with created FDBs count=%u\n", port->fdbs);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (port->rifs) {
        SX_LOG_ERR("Can't add port with created RIFs count=%u\n", port->rifs);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_ERR(ports_l1_params_check(lag, port))) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_port_list_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t      status;
    sai_object_id_t   lag_id = key->object_id;
    sx_port_log_id_t  lag_log_port_id;
    sx_port_log_id_t *log_port_list = NULL;
    uint32_t          log_port_cnt  = 0;
    uint32_t          ii;
    sx_status_t       sx_status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                               lag_log_port_id, NULL, &log_port_cnt))) {
        return sdk_to_sai(sx_status);
    }

    if (value->objlist.count < log_port_cnt) {
        SX_LOG_ERR("Insufficient list buffer size. Allocated %u needed %u\n",
                   value->objlist.count, log_port_cnt);
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                   lag_log_port_id, log_port_list, &log_port_cnt))) {
            free(log_port_list);
            return sdk_to_sai(sx_status);
        }

        for (ii = 0; ii < log_port_cnt; ii++) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_create_object(SAI_OBJECT_TYPE_PORT, (uint32_t)log_port_list[ii], NULL,
                                        &value->objlist.list[ii]))) {
                free(log_port_list);
                return status;
            }
        }
        free(log_port_list);
    }
    value->objlist.count = log_port_cnt;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_lag_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, lag_log_port_id, NULL, &value->oid))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_port_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t log_port_id;
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, log_port_id, NULL, &value->oid))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_egress_disable_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_port_log_id_t      lag_log_port_id = 0;
    sx_port_log_id_t      log_port_id;
    uint8_t               extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t       lag_member_id = key->object_id;
    sx_distributor_mode_t distributor_mode;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_distributor_get(gh_sdk, lag_log_port_id, log_port_id, &distributor_mode))) {
        return sdk_to_sai(sx_status);
    }

    if (distributor_mode == DISTRIBUTOR_DISABLE) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_egress_disable_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_distributor_set
                         (gh_sdk, lag_log_port_id, log_port_id,
                         value->booldata ? DISTRIBUTOR_DISABLE : DISTRIBUTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_ingress_disable_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t        status;
    sx_status_t         sx_status;
    sx_port_log_id_t    lag_log_port_id = 0;
    sx_port_log_id_t    log_port_id;
    uint8_t             extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t     lag_member_id = key->object_id;
    sx_collector_mode_t collector_mode;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_get(gh_sdk, lag_log_port_id, log_port_id, &collector_mode))) {
        return sdk_to_sai(sx_status);
    }

    if (collector_mode == COLLECTOR_DISABLE) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_ingress_disable_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_set
                         (gh_sdk, lag_log_port_id, log_port_id,
                         value->booldata ? COLLECTOR_DISABLE : COLLECTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_lag(_Out_ sai_object_id_t     * lag_id,
                                    _In_ uint32_t               attr_count,
                                    _In_ const sai_attribute_t *attr_list)
{
    sai_status_t        status;
    sx_status_t         sx_status;
    char                list_str[MAX_LIST_VALUE_STR_LEN];
    char                key_str[MAX_KEY_STR_LEN];
    sx_port_log_id_t    lag_log_port_id = 0;
    uint32_t            ii              = 0;
    mlnx_port_config_t *lag             = NULL;

    SX_LOG_ENTER();

    if (NULL == lag_id) {
        SX_LOG_ERR("NULL lag id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, lag_attribs, lag_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, lag_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag, %s\n", list_str);

    sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, DEFAULT_ETH_SWID,
                                          &lag_log_port_id, NULL, 0);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed create LAG %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, (uint32_t)lag_log_port_id, NULL, lag_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();
    for (ii = MAX_PORTS; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_ports_db[ii].logical == 0) {
            mlnx_ports_db[ii].logical = lag_log_port_id;
            mlnx_ports_db[ii].saiport = *lag_id;
            lag                       = &mlnx_ports_db[ii];
            lag->start_queues_index   = ii * (MAX_ETS_TC + 1);
            break;
        }
    }

    if (!lag) {
        SX_LOG_ERR("Failed to allocate LAG id in SAI DB\n.");
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    lag_key_to_str(*lag_id, key_str);
    SX_LOG_NTC("Created %s\n", key_str);

    status = mlnx_port_config_init(lag);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed initialize LAG oid %" PRIx64 " port config\n", lag->saiport);
        goto out;
    }

    status = mlnx_hash_ecmp_cfg_apply_on_port(lag->logical);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    if (SAI_ERR(status)) {
        if (lag_log_port_id) {
            sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, DEFAULT_ETH_SWID, &lag_log_port_id, NULL, 0);
        }
        if (lag) {
            memset(lag, 0, sizeof(*lag));
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_remove_lag(_In_ sai_object_id_t lag_id)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id;
    uint32_t         ii = 0;

    SX_LOG_NTC("Remove SAI LAG oid %" PRIx64 "\n", (uint64_t)lag_id);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    /*  Remove all ports from the LAG first */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_lag_remove_all_ports(lag_id))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, DEFAULT_ETH_SWID,
                                               &lag_log_port_id, NULL, 0))) {
        return sdk_to_sai(sx_status);
    }

    /* Remove from lag_db */
    sai_db_write_lock();
    for (ii = MAX_PORTS; ii < MAX_PORTS * 2; ii++) {
        if (mlnx_ports_db[ii].logical == lag_log_port_id) {
            memset(&mlnx_ports_db[ii], 0, sizeof(mlnx_port_config_t));
            break;
        }
    }
    sai_db_unlock();

    if (ii == MAX_PORTS * 2) {
        /* Should not reach this place */
        SX_LOG_ERR("Failed to find lag id in SAI DB.\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_lag_attribute(_In_ sai_object_id_t lag_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_set_attribute(&key, key_str, lag_attribs, lag_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_attribute(_In_ sai_object_id_t     lag_id,
                                           _In_ uint32_t            attr_count,
                                           _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_get_attributes(&key, key_str, lag_attribs, lag_vendor_attribs, attr_count, attr_list);
}

static sai_status_t mlnx_create_lag_member(_Out_ sai_object_id_t     * lag_member_id,
                                           _In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    const sai_attribute_value_t *attr_lag_id, *attr_port_id, *attr_egress_disable, *attr_ingress_disable;
    sai_object_id_t              lag_oid, port_oid;
    uint32_t                     index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_port_log_id_t             lag_id;
    sx_port_log_id_t             port_id;
    uint32_t                     port_cnt = 0;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];
    mlnx_port_config_t          *port         = NULL;
    mlnx_port_config_t          *lag          = NULL;
    sx_collector_mode_t          collect_mode = COLLECTOR_ENABLE;
    sx_distributor_mode_t        dist_mode    = DISTRIBUTOR_ENABLE;

    SX_LOG_ENTER();

    memset(extended_data, 0, sizeof(extended_data));

    if (NULL == lag_member_id) {
        SX_LOG_ERR("NULL lag member id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, lag_member_attribs, lag_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, lag_member_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_MEMBER_ATTR_LAG_ID, &attr_lag_id, &index);
    if (SAI_ERR(status)) {
        return status;
    }
    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_MEMBER_ATTR_PORT_ID, &attr_port_id, &index);
    if (SAI_ERR(status)) {
        return status;
    }

    /* get egress mode */
    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
                                 &attr_egress_disable, &index);
    if (!SAI_ERR(status)) {
        dist_mode = attr_egress_disable->booldata ? DISTRIBUTOR_DISABLE : DISTRIBUTOR_ENABLE;
    }

    /* get ingress mode */
    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
                                 &attr_ingress_disable, &index);
    if (!SAI_ERR(status)) {
        collect_mode = attr_ingress_disable->booldata ? COLLECTOR_DISABLE : COLLECTOR_ENABLE;
    }

    lag_oid  = attr_lag_id->oid;
    port_oid = attr_port_id->oid;

    status = mlnx_object_to_type(lag_oid, SAI_OBJECT_TYPE_LAG, &lag_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }
    status = mlnx_object_to_type(port_oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Add port to lag */
    sai_db_write_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }
    status = mlnx_port_by_log_id(lag_id, &lag);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag->logical, NULL, &port_cnt);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        goto out;
    }

    if (port_cnt) {
        status = validate_port(lag, port);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        status = mlnx_port_params_clone(lag, port, PORT_PARAMS_ALL);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                          &lag->logical, &port->logical, 1);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        SX_LOG_ERR("Failed to add lag port %s.\n", SX_STATUS_MSG(sx_status));
        goto out;
    }

    sx_status = sx_api_lag_port_collector_set(gh_sdk, lag->logical, port->logical, collect_mode);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        goto out;
    }
    sx_status = sx_api_lag_port_distributor_set(gh_sdk, lag->logical, port->logical, dist_mode);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        goto out;
    }

    port->lag_id = lag->logical;

    /* create lag member id */
    extended_data[2] = SX_PORT_SUB_ID_GET(lag_id);     /* Port-Sub-ID */
    extended_data[1] = SX_PORT_LAG_ID_GET(lag_id);     /* LAG-ID */
    extended_data[0] = SX_PORT_TYPE_ID_GET(lag_id);    /* Type-ID: SX_PORT_TYPE_LAG */

    status = mlnx_create_object(SAI_OBJECT_TYPE_LAG_MEMBER, port_id, extended_data, lag_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();

    lag_member_key_to_str(*lag_member_id, key_str);
    SX_LOG_NTC("Created LAG member %s\n", key_str);
    return status;
}

static sai_status_t mlnx_remove_lag_member(_In_ sai_object_id_t lag_member_id)
{
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_status_t     status          = SAI_STATUS_SUCCESS;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;

    status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                 &log_port_id, extended_data);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    sai_db_write_lock();
    status = remove_port_from_lag(lag_log_port_id, log_port_id);
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_set_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_set_attribute(&key, key_str, lag_member_attribs, lag_member_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_member_attribute(_In_ sai_object_id_t     lag_member_id,
                                                  _In_ uint32_t            attr_count,
                                                  _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              lag_member_attribs,
                              lag_member_vendor_attribs,
                              attr_count,
                              attr_list);
}

sai_status_t mlnx_lag_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_lag_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_lag_api_t mlnx_lag_api = {
    mlnx_create_lag,
    mlnx_remove_lag,
    mlnx_set_lag_attribute,
    mlnx_get_lag_attribute,
    mlnx_create_lag_member,
    mlnx_remove_lag_member,
    mlnx_set_lag_member_attribute,
    mlnx_get_lag_member_attribute
};
