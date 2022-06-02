/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    PORT_PARAMS_QOS          = 1 << 0,
    PORT_PARAMS_QUEUE        = 1 << 1,
    PORT_PARAMS_MIRROR       = 1 << 2,
    PORT_PARAMS_FOR_LAG      = PORT_PARAMS_QOS | PORT_PARAMS_QUEUE | PORT_PARAMS_MIRROR,
    PORT_PARAMS_FLOOD        = 1 << 3,
    PORT_PARAMS_VLAN         = 1 << 4,
    PORT_PARAMS_SFLOW        = 1 << 5,
    PORT_PARAMS_POLICER      = 1 << 6,
    PORT_PARAMS_LEARN_MODE   = 1 << 7,
    PORT_PARAMS_EGRESS_BLOCK = 1 << 8,
} port_params_t;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
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
    { SAI_LAG_ATTR_INGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG },
    { SAI_LAG_ATTR_EGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG },
    { SAI_LAG_ATTR_PORT_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_lag_pvid_attr_get, NULL,
      mlnx_port_lag_pvid_attr_set, NULL },
    { SAI_LAG_ATTR_DEFAULT_VLAN_PRIORITY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_lag_default_vlan_prio_get, NULL,
      mlnx_port_lag_default_vlan_prio_set, NULL },
    { SAI_LAG_ATTR_DROP_UNTAGGED,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_lag_drop_tags_get, (void*)SAI_LAG_ATTR_DROP_UNTAGGED,
      mlnx_port_lag_drop_tags_set, (void*)SAI_LAG_ATTR_DROP_UNTAGGED },
    { SAI_LAG_ATTR_DROP_TAGGED,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_port_lag_drop_tags_get, (void*)SAI_LAG_ATTR_DROP_TAGGED,
      mlnx_port_lag_drop_tags_set, (void*)SAI_LAG_ATTR_DROP_TAGGED },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_lag_obj_type_info =
{ lag_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_lag_member_obj_type_info =
{ lag_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
static void lag_key_to_str(_In_ sai_object_id_t lag_id, _Out_ char *key_str)
{
    uint32_t lagid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lagid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG %x", lagid);
    }
}

static void lag_member_key_to_str(_In_ sai_object_id_t lag_member_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_lag_member = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG Member");
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "LAG member (%x,%x)",
                 mlnx_lag_member.id.log_port_id,
                 mlnx_lag_member.ext.lag.lag_id);
    }
}

static sai_status_t mlnx_port_params_clone(mlnx_port_config_t *to, mlnx_port_config_t *from, port_params_t clone)
{
    sx_status_t                  sx_status;
    sx_cos_rewrite_enable_t      rewrite_enable;
    uint32_t                     max_ets_count;
    sx_cos_trust_level_t         trust_level;
    sx_cos_ets_element_config_t *ets = NULL;
    sx_fdb_learn_mode_t          sx_fdb_learn_mode;
    sx_port_log_id_t            *log_ports = NULL;
    mlnx_qos_queue_config_t     *queue_cfg;
    mlnx_qos_queue_config_t     *to_queue_cfg;
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    uint8_t                      prio;
    uint32_t                     ii;

    /* QoS */
    if (clone & PORT_PARAMS_QOS) {
        max_ets_count = MAX_ETS_ELEMENTS;
        ets = (sx_cos_ets_element_config_t*)malloc(sizeof(sx_cos_ets_element_config_t) * max_ets_count);
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

            if ((ii == SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP) ||
                (ii == SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP)) {
                continue;
            }

            if (from->qos_maps[ii]) {
                status = mlnx_create_object(SAI_OBJECT_TYPE_QOS_MAP, from->qos_maps[ii], NULL, &oid);
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
    /* WRED and scheduler */
    if (clone & PORT_PARAMS_QUEUE) {
        port_queues_foreach(from, queue_cfg, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }

            SX_LOG_DBG("Cloning scheduler from %x to %x, qi %d, scheduler %lx\n",
                       from->logical,
                       to->logical,
                       ii,
                       queue_cfg->sched_obj.scheduler_id);
            status = mlnx_queue_cfg_lookup(to->logical,
                                           ii,
                                           &to_queue_cfg);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Fail to lookup queue cfg for log port %x and idx %d\n",
                           to->logical, ii);
                goto out;
            }
            memcpy(&(to_queue_cfg->sched_obj), &(queue_cfg->sched_obj),
                   sizeof(to_queue_cfg->sched_obj));
        }

        port_queues_foreach(from, queue_cfg, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }

            SX_LOG_DBG("Cloning WRED from %x to %x, qi %d, wred %lx\n",
                       from->logical,
                       to->logical,
                       ii,
                       queue_cfg->wred_id);

            status = mlnx_wred_apply_to_queue(to, ii, queue_cfg->wred_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }
    }
    /* Mirroring */
    if (clone & PORT_PARAMS_MIRROR) {
        status = mlnx_port_mirror_sessions_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (clone & PORT_PARAMS_VLAN) {
        sx_ingr_filter_mode_t mode;
        sx_status_t           sx_status;

        /* Align VLAN ingress filter */
        sx_status = sx_api_vlan_port_ingr_filter_get(gh_sdk, from->logical, &mode);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Port ingress filter get for port oid %" PRIx64 " failed - %s\n",
                       from->saiport, SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_vlan_port_ingr_filter_set(gh_sdk, to->logical, mode);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Port ingress filter set for port oid %" PRIx64 " failed - %s\n",
                       to->saiport, SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (clone & PORT_PARAMS_SFLOW) {
        status = mlnx_port_samplepacket_params_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (clone & PORT_PARAMS_POLICER) {
        status = mlnx_port_storm_control_policer_params_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (clone & PORT_PARAMS_LEARN_MODE) {
        sx_status = sx_api_fdb_port_learn_mode_get(gh_sdk, from->logical, &sx_fdb_learn_mode);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get port [%x] learning mode - %s.\n", from->logical, SX_STATUS_MSG(status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, to->logical, sx_fdb_learn_mode);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port [%x] learning mode %s - %s.\n", to->logical,
                       SX_LEARN_MODE_MSG(sx_fdb_learn_mode), SX_STATUS_MSG(status));
            status = sdk_to_sai(sx_status);
            goto out;
        }

        SX_LOG_DBG("Cloned fdb learn mode %s from port [%x] to port [%x]\n", SX_LEARN_MODE_MSG(sx_fdb_learn_mode),
                   from->logical, to->logical);
    }

    if ((clone & PORT_PARAMS_EGRESS_BLOCK) && is_egress_block_in_use()) {
        status = mlnx_port_egress_block_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    free(ets);
    free(log_ports);
    return status;
}

/* When LAG is added to VLAN then it's members are added to this VLAN by SDK, but
 * SDK do not remove the port from this VLAN when the port is removed from LAG */
static sai_status_t port_reset_vlan_params_from_port(mlnx_port_config_t *port, mlnx_port_config_t *lag)
{
    uint16_t            vlan_count = 0;
    mlnx_bridge_port_t *lag_bport, *port_bport;
    sx_port_vlans_t    *vlan_list;
    sx_status_t         sx_status;
    sai_status_t        status;
    uint16_t            vid;
    uint16_t            ii = 0;
    sx_vlan_ports_t     port_list;

    /* Reset to default VLAN ingress filter */
    sx_status = sx_api_vlan_port_ingr_filter_set(gh_sdk, port->logical, SX_INGR_FILTER_ENABLE);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Port ingress filter set %x failed - %s\n", port->logical, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Reset port PVID to default VLAN=1 */
    sx_status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, port->logical, DEFAULT_VLAN);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port pvid - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_INF("Try to delete port 0x%x in lag 0x%x from vlan %d.\n",
               port->logical, lag->logical, lag->pvid_create_rif);
    if (lag->pvid_create_rif) {
        port_bport = 0;
        status = mlnx_bridge_1q_port_by_log(port->logical, &port_bport);
        if ((status != SAI_STATUS_SUCCESS) ||
            !mlnx_vlan_port_is_set(lag->pvid_create_rif, port_bport)) {
            memset(&port_list, 0, sizeof(port_list));
            port_list.log_port = port->logical;
            sx_status = sx_api_vlan_ports_set(gh_sdk,
                                              SX_ACCESS_CMD_DELETE,
                                              DEFAULT_ETH_SWID,
                                              lag->pvid_create_rif,
                                              &port_list, 1);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to delete port 0x%x in lag 0x%x from vlan %d - %s.\n",
                           port->logical, lag->logical, lag->pvid_create_rif, SX_STATUS_MSG(sx_status));
            }
        } else {
            SX_LOG_INF("Port 0x%x was in vlan %d before lag creating rif.\n",
                       port->logical, port->pvid_create_rif);
        }
    }

    if (!mlnx_port_is_in_bridge_1q(lag)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_bridge_1q_port_by_log(lag->logical, &lag_bport);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to lookup bridge port by LAG log id %x\n", lag->logical);
        return status;
    }
    vlan_count = lag_bport->vlans;

    /* Remove port from VLANs on the LAG */
    if (vlan_count) {
        vlan_list = (sx_port_vlans_t*)calloc(vlan_count, sizeof(sx_port_vlans_t));
        if (NULL == vlan_list) {
            SX_LOG_ERR("Can't allocate vlan list\n");
            return SAI_STATUS_NO_MEMORY;
        }

        mlnx_vlan_id_foreach(vid) {
            if (!mlnx_vlan_port_is_set(vid, lag_bport)) {
                continue;
            }

            status = mlnx_fid_flood_ctrl_port_event_handle(vid, &mlnx_vlan_db_get_vlan(vid)->flood_data,
                                                           &port->logical, 1, MLNX_PORT_EVENT_DELETE);
            if (SAI_ERR(status)) {
                free(vlan_list);
                return status;
            }

            vlan_list[ii++].vid = vid;
        }

        sx_status =
            sx_api_vlan_port_multi_vlan_set(gh_sdk, SX_ACCESS_CMD_DELETE, port->logical, vlan_list, vlan_count);
        free(vlan_list);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete vlans from port oid %" PRIx64 " - %s.\n",
                       port->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }
    }

    return sdk_to_sai(sx_status);
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
        return status;
    }

    port->lag_id = 0;

    status = port_reset_vlan_params_from_port(port, lag);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_config_apply_to_port(port_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port learning mode - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Do re-apply for port params which were removed by us before add to the LAG */
    status = mlnx_port_params_clone(port, lag, PORT_PARAMS_QUEUE | PORT_PARAMS_MIRROR | PORT_PARAMS_SFLOW |
                                    PORT_PARAMS_POLICER | PORT_PARAMS_EGRESS_BLOCK);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_port_move_isolation_group_from_lag(lag, port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_internal_acls_bind(SX_ACCESS_CMD_ADD, port->saiport, SAI_OBJECT_TYPE_PORT);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to bind internal ACLs to port 0x%x\n", port->logical);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_remove_all_ports(sai_object_id_t lag_oid)
{
    sai_status_t      status;
    sx_port_log_id_t  lag_id;
    sx_status_t       sx_status;
    sx_port_log_id_t *port_list = NULL;
    uint32_t          port_cnt = 0;
    uint32_t          ii = 0;

    status = mlnx_object_to_log_port(lag_oid, &lag_id);
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

    for (ii = 0; ii < port_cnt; ii++) {
        status = remove_port_from_lag(lag_id, port_list[ii]);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            goto out;
        }
    }

out:
    free(port_list);
    return status;
}

static sai_status_t validate_port(mlnx_port_config_t *lag, mlnx_port_config_t *port)
{
    sai_status_t status;
    bool         is_in_use_for_port_isolation;

    if (mlnx_port_is_in_bridge_1q(port)) {
        SX_LOG_ERR("Can't add port which is under bridge\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (port->rifs) {
        SX_LOG_ERR("Can't add port with created RIFs count=%u\n", port->rifs);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_port_isolation_is_in_use(port, &is_in_use_for_port_isolation);
    if (SAI_ERR(status)) {
        return status;
    }

    if (is_in_use_for_port_isolation) {
        SX_LOG_ERR("Can't add port oid %" PRIx64 " - is a member another port's port isolation\n", port->saiport);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (port->is_span_analyzer_port) {
        SX_LOG_ERR("SAI port 0x%" PRIx64 " is analyzer port\n", port->saiport);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_port_list_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t        status;
    sai_object_id_t     lag_id = key->key.object_id;
    sx_port_log_id_t    lag_log_port_id;
    sx_port_log_id_t   *log_port_list = NULL;
    uint32_t            log_port_cnt = 0;
    uint32_t            ii;
    sx_status_t         sx_status;
    mlnx_port_config_t *port;
    bool                is_warmboot_init_stage = false;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_log_port(lag_id, &lag_log_port_id))) {
        return status;
    }

    is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                             (!g_sai_db_ptr->issu_end_called);

    if (is_warmboot_init_stage) {
        if (0 == lag_log_port_id) {
            log_port_cnt = 0;
        } else {
            mlnx_port_phy_foreach(port, ii) {
                if (port->lag_id == lag_log_port_id) {
                    log_port_cnt++;
                }
            }
        }
    } else if (SX_STATUS_SUCCESS !=
               (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                      lag_log_port_id, NULL, &log_port_cnt))) {
        return sdk_to_sai(sx_status);
    }

    if (value->objlist.count < log_port_cnt) {
        if (0 == value->objlist.count) {
            status = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
        } else {
            status = SAI_STATUS_BUFFER_OVERFLOW;
        }
        SX_LOG(((0 == value->objlist.count) ? SX_LOG_NOTICE : SX_LOG_ERROR),
               "Insufficient list buffer size. Allocated %u needed %u\n",
               value->objlist.count, log_port_cnt);
        value->objlist.count = log_port_cnt;
        return status;
    }

    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }
        if (!is_warmboot_init_stage) {
            if (SX_STATUS_SUCCESS !=
                (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                       lag_log_port_id, log_port_list, &log_port_cnt))) {
                free(log_port_list);
                return sdk_to_sai(sx_status);
            }
        } else {
            log_port_cnt = 0;
            mlnx_port_phy_foreach(port, ii) {
                if (port->lag_id == lag_log_port_id) {
                    log_port_list[log_port_cnt] = port->logical;
                    log_port_cnt++;
                }
            }
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
    sai_object_id_t  lag_member_id = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};
    sx_port_log_id_t lag_log_port_id = 0;
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    status = mlnx_log_port_to_object(lag_log_port_id, &value->oid);
    if (SAI_ERR(status)) {
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
    sai_object_id_t  lag_member_id = key->key.object_id;

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
    sai_object_id_t       lag_member_id = key->key.object_id;
    sx_distributor_mode_t distributor_mode;
    mlnx_object_id_t      mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    if (SX_STATUS_SUCCESS !=
        (sx_status =
             sx_api_lag_port_distributor_get(gh_sdk, lag_log_port_id, mlnx_lag_member.id.log_port_id,
                                             &distributor_mode))) {
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
    sai_object_id_t  lag_member_id = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_distributor_set
                         (gh_sdk, lag_log_port_id, mlnx_lag_member.id.log_port_id,
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
    sai_object_id_t     lag_member_id = key->key.object_id;
    sx_collector_mode_t collector_mode;
    mlnx_object_id_t    mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    if (SX_STATUS_SUCCESS !=
        (sx_status =
             sx_api_lag_port_collector_get(gh_sdk, lag_log_port_id, mlnx_lag_member.id.log_port_id,
                                           &collector_mode))) {
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
    sai_object_id_t  lag_member_id = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_set
                         (gh_sdk, lag_log_port_id, mlnx_lag_member.id.log_port_id,
                         value->booldata ? COLLECTOR_DISABLE : COLLECTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_apply_lag_attributes(mlnx_port_config_t *lag,
                                              uint32_t            lag_ingress_acl_attr_index,
                                              uint32_t            lag_egress_acl_attr_index)
{
    sai_status_t          sai_status = SAI_STATUS_FAILURE;
    sx_status_t           sx_status = SX_STATUS_ERROR;
    acl_index_t           ing_acl_index = ACL_INDEX_INVALID, egr_acl_index = ACL_INDEX_INVALID;
    sx_vlan_frame_types_t accptd_frm_types;

    SX_LOG_ENTER();

    if (NULL == lag) {
        SX_LOG_ERR("Empty port config\n");
        goto out;
    }

    sai_status = mlnx_hash_config_apply_to_port(lag->logical);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to apply hash config on LAG port 0x%x\n", lag->logical);
        goto out;
    }

    if (lag->issu_lag_attr.lag_ingress_acl_oid_changed) {
        sai_status = mlnx_acl_bind_point_attrs_check_and_fetch(lag->issu_lag_attr.lag_ingress_acl_oid,
                                                               MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
                                                               lag_ingress_acl_attr_index,
                                                               &ing_acl_index);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to check and fetch ingress ACL: %" PRIx64 "\n",
                       lag->issu_lag_attr.lag_ingress_acl_oid);
            goto out;
        }

        sai_status = mlnx_acl_port_lag_rif_bind_point_set(lag->saiport, MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
                                                          ing_acl_index);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set bind point for LAG %" PRIx64 " with ingress ACL index %d\n",
                       lag->saiport, ing_acl_index.acl_db_index);
            goto out;
        }
    }

    if (lag->issu_lag_attr.lag_egress_acl_oid_changed) {
        sai_status = mlnx_acl_bind_point_attrs_check_and_fetch(lag->issu_lag_attr.lag_egress_acl_oid,
                                                               MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
                                                               lag_egress_acl_attr_index,
                                                               &egr_acl_index);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to check and fetch egress ACL: %" PRIx64 "\n",
                       lag->issu_lag_attr.lag_egress_acl_oid);
            goto out;
        }

        sai_status = mlnx_acl_port_lag_rif_bind_point_set(lag->saiport, MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
                                                          egr_acl_index);
        if (SAI_ERR(sai_status)) {
            SX_LOG_ERR("Failed to set bind point for LAG %" PRIx64 " with egress ACL index %d\n",
                       lag->saiport, egr_acl_index.acl_db_index);
            goto out;
        }
    }

    if (lag->issu_lag_attr.lag_pvid_changed) {
        sx_status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, lag->logical, lag->issu_lag_attr.lag_pvid);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set pvid %d to LAG %x - %s\n", lag->issu_lag_attr.lag_pvid, lag->logical,
                       SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (lag->issu_lag_attr.lag_default_vlan_priority_changed) {
        sx_status =
            sx_api_cos_port_default_prio_set(gh_sdk, lag->logical, lag->issu_lag_attr.lag_default_vlan_priority);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set LAG %x default prio - %s.\n", lag->logical, SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    if (lag->issu_lag_attr.lag_drop_tagged_changed || lag->issu_lag_attr.lag_drop_untagged_changed) {
        memset(&accptd_frm_types, 0, sizeof(accptd_frm_types));
        accptd_frm_types.allow_untagged = accptd_frm_types.allow_tagged = accptd_frm_types.allow_priotagged = true;

        if (lag->issu_lag_attr.lag_drop_tagged_changed) {
            accptd_frm_types.allow_tagged = !(lag->issu_lag_attr.lag_drop_tagged);
        }

        if (lag->issu_lag_attr.lag_drop_untagged_changed) {
            accptd_frm_types.allow_untagged = !(lag->issu_lag_attr.lag_drop_untagged);
        }

        sx_status = sx_api_vlan_port_accptd_frm_types_set(gh_sdk, lag->logical, &accptd_frm_types);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set LAG %x accepted frame types - %s.\n", lag->logical, SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    sai_status = mlnx_wred_mirror_port_event(lag->logical, true);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Error setting port mirror wred discard for lag 0x%x\n", lag->logical);
        goto out;
    }
out:
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_create_lag(_Out_ sai_object_id_t     * lag_id,
                                    _In_ sai_object_id_t        switch_id,
                                    _In_ uint32_t               attr_count,
                                    _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    const sai_attribute_value_t *attr_ing_acl = NULL;
    const sai_attribute_value_t *attr_egr_acl = NULL;
    const sai_attribute_value_t *attr_pvid = NULL;
    const sai_attribute_value_t *attr_def_vlan_prio = NULL;
    const sai_attribute_value_t *attr_drop_untagged = NULL;
    const sai_attribute_value_t *attr_drop_tagged = NULL;
    acl_index_t                  ing_acl_index = ACL_INDEX_INVALID, egr_acl_index = ACL_INDEX_INVALID;
    sx_port_log_id_t             lag_log_port_id = 0;
    uint32_t                     ii = 0;
    uint32_t                     attr_ingress_acl_index, attr_egress_acl_index;
    uint32_t                     attr_pvid_index, attr_def_vlan_prio_index, attr_drop_untagged_index,
                                 attr_drop_tagged_index;
    mlnx_port_config_t *lag = NULL;
    const bool          is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                 (!g_sai_db_ptr->issu_end_called);
    uint32_t port_db_idx = 0;

    SX_LOG_ENTER();

    if (NULL == lag_id) {
        SX_LOG_ERR("NULL lag id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_LAG, lag_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_LAG, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag, %s\n", list_str);

    sai_db_write_lock();
    acl_global_lock();

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_LAG_ATTR_INGRESS_ACL,
                                 &attr_ing_acl,
                                 &attr_ingress_acl_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_ing_acl->oid,
                                                           MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
                                                           attr_ingress_acl_index,
                                                           &ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status =
        find_attrib_in_list(attr_count, attr_list, SAI_LAG_ATTR_EGRESS_ACL, &attr_egr_acl, &attr_egress_acl_index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_egr_acl->oid,
                                                           MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
                                                           attr_egress_acl_index,
                                                           &egr_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    find_attrib_in_list(attr_count, attr_list, SAI_LAG_ATTR_PORT_VLAN_ID, &attr_pvid, &attr_pvid_index);
    find_attrib_in_list(attr_count,
                        attr_list,
                        SAI_LAG_ATTR_DEFAULT_VLAN_PRIORITY,
                        &attr_def_vlan_prio,
                        &attr_def_vlan_prio_index);
    find_attrib_in_list(attr_count,
                        attr_list,
                        SAI_LAG_ATTR_DROP_UNTAGGED,
                        &attr_drop_untagged,
                        &attr_drop_untagged_index);
    find_attrib_in_list(attr_count, attr_list, SAI_LAG_ATTR_DROP_TAGGED, &attr_drop_tagged, &attr_drop_tagged_index);

    if (!is_warmboot_init_stage) {
        sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, DEFAULT_ETH_SWID,
                                              &lag_log_port_id, NULL, 0);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed create LAG %s.\n", SX_STATUS_MSG(sx_status));
            status = sdk_to_sai(sx_status);
            goto out;
        }
    }

    for (ii = MAX_PORTS; ii < MAX_PORTS * 2; ii++) {
        if (!mlnx_ports_db[ii].is_present) {
            if (!is_warmboot_init_stage) {
                mlnx_ports_db[ii].logical = lag_log_port_id;
            } else if (!mlnx_ports_db[ii].sdk_port_added) {
                continue;
            }

            lag_log_port_id = mlnx_ports_db[ii].logical;

            status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, ii, NULL, lag_id);
            if (SAI_ERR(status)) {
                goto out;
            }

            mlnx_ports_db[ii].saiport = *lag_id;
            lag = &mlnx_ports_db[ii];

            port_db_idx = ii;

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

    if (!is_warmboot_init_stage) {
        status = mlnx_port_add(lag, true);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to add LAG port 0x%x\n", lag->logical);
            goto out;
        }
    } else {
        mlnx_ports_db[port_db_idx].is_present = true;
    }

    if (attr_ing_acl) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_ingress_acl_oid = attr_ing_acl->oid;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_ingress_acl_oid_changed = true;
    }
    if (attr_egr_acl) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_egress_acl_oid = attr_egr_acl->oid;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_egress_acl_oid_changed = true;
    }
    if (attr_pvid) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_pvid = attr_pvid->u16;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_pvid_changed = true;
    } else {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_pvid = DEFAULT_VLAN;
    }
    if (attr_def_vlan_prio) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_default_vlan_priority = attr_def_vlan_prio->u8;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_default_vlan_priority_changed = true;
    }
    if (attr_drop_tagged) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_drop_tagged = attr_drop_tagged->booldata;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_drop_tagged_changed = true;
    }
    if (attr_drop_untagged) {
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_drop_untagged = attr_drop_untagged->booldata;
        mlnx_ports_db[port_db_idx].issu_lag_attr.lag_drop_untagged_changed = true;
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_apply_lag_attributes(lag, attr_ingress_acl_index, attr_egress_acl_index);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Error creating LAG with attributes\n");
            goto out;
        }
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_internal_acls_bind(SX_ACCESS_CMD_ADD, *lag_id, SAI_OBJECT_TYPE_LAG);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to bind internal ACLs to port 0x%x\n", lag_log_port_id);
            goto out;
        }
    }
out:
    acl_global_unlock();
    if (SAI_ERR(status)) {
        if (lag && lag->is_present) {
            mlnx_port_del(lag);
            lag->saiport = SAI_NULL_OBJECT_ID;
            lag->logical = 0;
        }

        if (lag_log_port_id) {
            sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, DEFAULT_ETH_SWID, &lag_log_port_id, NULL, 0);
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_remove_lag(_In_ sai_object_id_t lag_id)
{
    sx_port_log_id_t    lag_log_port_id;
    sx_status_t         sx_status;
    sai_status_t        status;
    mlnx_port_config_t *lag;
    char                key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    status = mlnx_object_to_log_port(lag_id, &lag_log_port_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    status = mlnx_port_by_log_id(lag_log_port_id, &lag);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_port_in_use_check(lag);
    if (SAI_ERR(status)) {
        goto out;
    }

    /*  Remove all ports from the LAG first */
    status = mlnx_lag_remove_all_ports(lag_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    memset(&(lag->issu_lag_attr), 0, sizeof(lag->issu_lag_attr));

    status = mlnx_port_del(lag);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove LAG log id 0x%x\n", lag->logical);
        goto out;
    }

    sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, DEFAULT_ETH_SWID,
                                          &lag_log_port_id, NULL, 0);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
    }

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_set_lag_attribute(_In_ sai_object_id_t lag_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_LAG, lag_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_attribute(_In_ sai_object_id_t     lag_id,
                                           _In_ uint32_t            attr_count,
                                           _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_LAG, lag_vendor_attribs, attr_count, attr_list);
}

static sai_status_t mlnx_create_lag_member(_Out_ sai_object_id_t     * lag_member_id,
                                           _In_ sai_object_id_t        switch_id,
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
    uint32_t                     lag_db_idx;
    sx_port_log_id_t             port_id;
    uint32_t                     port_cnt = 0;
    mlnx_port_config_t          *port = NULL;
    mlnx_port_config_t          *lag = NULL;
    sx_collector_mode_t          collect_mode = COLLECTOR_ENABLE;
    sx_distributor_mode_t        dist_mode = DISTRIBUTOR_ENABLE;
    mlnx_object_id_t             mlnx_lag_member = {0};
    bool                         is_acl_rollback_needed = false;
    bool                         is_internal_acls_rollback_needed = false;
    const uint32_t               ingress_acl_index = 0;
    const uint32_t               egress_acl_index = 0;
    uint32_t                     ii = 0;
    mlnx_qos_queue_config_t     *lag_queue_cfg;
    mlnx_qos_queue_config_t     *port_queue_cfg;
    const bool                   is_warmboot_init_stage = (BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) &&
                                                          (!g_sai_db_ptr->issu_end_called);

    SX_LOG_ENTER();

    if (NULL == lag_member_id) {
        SX_LOG_ERR("NULL lag member id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_LAG_MEMBER, MAX_LIST_VALUE_STR_LEN, list_str);
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

    lag_oid = attr_lag_id->oid;
    port_oid = attr_port_id->oid;

    status = mlnx_object_to_type(port_oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();
    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_port_idx_by_obj_id(lag_oid, &lag_db_idx);
    if (SAI_ERR(status)) {
        goto out;
    }

    lag = &(mlnx_ports_db[lag_db_idx]);

    status = validate_port(lag, port);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (is_warmboot_init_stage) {
        if (!mlnx_ports_db[lag_db_idx].is_present || !mlnx_ports_db[lag_db_idx].sdk_port_added) {
            SX_LOG_ERR("LAG db idx is not present (%d), or SDK LAG is not added (%d)\n",
                       mlnx_ports_db[lag_db_idx].is_present, mlnx_ports_db[lag_db_idx].sdk_port_added);
            goto out;
        }
        if (!(mlnx_ports_db[lag_db_idx].logical)) {
            mlnx_ports_db[lag_db_idx].logical = port->before_issu_lag_id;

            /* continue the rest work of create_lag */
            status = mlnx_port_add(lag, true);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to add LAG port 0x%x\n", lag->logical);
                goto out;
            }

            if (port->issu_lag_attr.lag_drop_untagged != lag->issu_lag_attr.lag_drop_untagged) {
                SX_LOG_ERR("LAG drop untagged inconsistent: port: %d, LAG: %d\n",
                           port->issu_lag_attr.lag_drop_untagged, lag->issu_lag_attr.lag_drop_untagged);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
            if (port->issu_lag_attr.lag_drop_tagged != lag->issu_lag_attr.lag_drop_tagged) {
                SX_LOG_ERR("LAG drop tagged inconsistent: port: %d, LAG: %d\n",
                           port->issu_lag_attr.lag_drop_tagged, lag->issu_lag_attr.lag_drop_tagged);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
            if (port->issu_lag_attr.lag_pvid != lag->issu_lag_attr.lag_pvid) {
                SX_LOG_ERR("LAG pvid inconsistent: port: %d, LAG: %d\n",
                           port->issu_lag_attr.lag_pvid, lag->issu_lag_attr.lag_pvid);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
            if (port->issu_lag_attr.lag_default_vlan_priority != lag->issu_lag_attr.lag_default_vlan_priority) {
                SX_LOG_ERR("LAG default vlan priority inconsistent: port: %d, LAG: %d\n",
                           port->issu_lag_attr.lag_default_vlan_priority,
                           lag->issu_lag_attr.lag_default_vlan_priority);
                status = SAI_STATUS_FAILURE;
                goto out;
            }

            status = mlnx_apply_lag_attributes(lag, ingress_acl_index, egress_acl_index);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Error creating lag\n");
                goto out;
            }
            if (SAI_STATUS_SUCCESS !=
                (status = mlnx_internal_acls_bind(SX_ACCESS_CMD_ADD, lag->saiport, SAI_OBJECT_TYPE_LAG))) {
                SX_LOG_ERR("Failed to bind internal ACLs to LAG\n");
                goto out;
            }
        } else if (port->before_issu_lag_id != mlnx_ports_db[lag_db_idx].logical) {
            SX_LOG_ERR("Port %x is already added to SDK lag %x and does not match current SDK LAG %x\n",
                       port_id, port->before_issu_lag_id, mlnx_ports_db[lag_db_idx].logical);
            status = SAI_STATUS_FAILURE;
            goto out;
        }

        /* During ISSU, WRED has already been applied on LAG via promotion,
         * thus only copy WRED id to LAG queue cfg */
        port_queues_foreach(port, port_queue_cfg, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }
            status = mlnx_queue_cfg_lookup(mlnx_ports_db[lag_db_idx].logical,
                                           ii,
                                           &lag_queue_cfg);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Fail to lookup queue cfg for log port %x and idx %d\n",
                           mlnx_ports_db[lag_db_idx].logical, ii);
                goto out;
            }
            lag_queue_cfg->wred_id = port_queue_cfg->wred_id;
            memcpy(&(lag_queue_cfg->sched_obj), &(port_queue_cfg->sched_obj),
                   sizeof(lag_queue_cfg->sched_obj));
        }
        memcpy(mlnx_ports_db[lag_db_idx].port_policers,
               port->port_policers,
               sizeof(port->port_policers));
        memset(port->port_policers, 0, sizeof(port->port_policers));
        mlnx_ports_db[lag_db_idx].internal_ingress_samplepacket_obj_idx =
            port->internal_ingress_samplepacket_obj_idx;
        port->internal_ingress_samplepacket_obj_idx = MLNX_INVALID_SAMPLEPACKET_SESSION;
        mlnx_ports_db[lag_db_idx].internal_egress_samplepacket_obj_idx =
            port->internal_egress_samplepacket_obj_idx;
        port->internal_egress_samplepacket_obj_idx = MLNX_INVALID_SAMPLEPACKET_SESSION;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag->logical, NULL, &port_cnt);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        goto out;
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_port_params_clone(lag,
                                        port,
                                        PORT_PARAMS_FOR_LAG | PORT_PARAMS_SFLOW | PORT_PARAMS_POLICER |
                                        PORT_PARAMS_EGRESS_BLOCK);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_params_clone(port, lag, PORT_PARAMS_VLAN | PORT_PARAMS_LEARN_MODE);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_samplepacket_params_clear(port, true);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_storm_control_policer_params_clear(port, true);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_mirror_params_clear(port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_egress_block_clear(port->logical);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_wred_port_queue_db_clear(port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_move_isolation_group_to_lag(port, lag);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (!is_warmboot_init_stage) {
        status = mlnx_internal_acls_bind(SX_ACCESS_CMD_DELETE, port_oid, SAI_OBJECT_TYPE_PORT);
        if (SAI_ERR(status)) {
            SX_LOG_NTC("Failed to unbind internal ACLs from port [%x]\n", port->logical);
            goto out;
        }
        is_internal_acls_rollback_needed = true;
    }

    status = mlnx_acl_port_lag_event_handle_unlocked(port, ACL_EVENT_TYPE_LAG_MEMBER_ADD);
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed to remove Lag member port[%x] from ACLs\n", lag->logical);
        goto out;
    }
    is_acl_rollback_needed = true;

    status = mlnx_wred_mirror_port_event(port->logical, false);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error removing port mirror wred discard for 0x%x\n", port->logical);
        goto out;
    }

    if (!is_warmboot_init_stage) {
        sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                              &lag->logical, &port->logical, 1);
        if (SAI_ERR(status = sdk_to_sai(sx_status))) {
            SX_LOG_ERR("Failed to add lag port %s.\n", SX_STATUS_MSG(sx_status));
            goto out;
        }
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
    lag_id = lag->logical;

    /* create lag member id */
    mlnx_lag_member.id.log_port_id = port_id;
    mlnx_lag_member.ext.lag.lag_id = SX_PORT_LAG_ID_GET(lag_id);

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_LAG_MEMBER, &mlnx_lag_member, lag_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    lag_member_key_to_str(*lag_member_id, key_str);
    SX_LOG_NTC("Created LAG member %s\n", key_str);

out:
    if (SAI_ERR(status)) {
        if (is_acl_rollback_needed) {
            mlnx_acl_port_lag_event_handle_unlocked(port, ACL_EVENT_TYPE_LAG_MEMBER_DEL);
        }

        if (is_internal_acls_rollback_needed) {
            mlnx_internal_acls_bind(SX_ACCESS_CMD_ADD, port_oid, SAI_OBJECT_TYPE_PORT);
        }
    }

    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

/* Need to be guarded by lock */
static sai_status_t mlnx_hostif_reapply(mlnx_port_config_t *port_config)
{
    uint32_t hostif_db_idx;
    char     set_addr_command[100];
    int      system_err;

    SX_LOG_ENTER();

    assert(NULL != port_config);
    if (port_config->has_hostif) {
        hostif_db_idx = port_config->hostif_db_idx;
        snprintf(set_addr_command, sizeof(set_addr_command), "ip link set dev %s address %s > /dev/null 2>&1",
                 g_sai_db_ptr->hostif_db[hostif_db_idx].ifname, g_sai_db_ptr->dev_mac);
        system_err = system(set_addr_command);
        if (0 != system_err) {
            SX_LOG_ERR("Failed running \"%s\".\n", set_addr_command);
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_lag_member(_In_ sai_object_id_t lag_member_id)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_object_id_t    mlnx_lag_member = {0};
    sx_port_log_id_t    lag_log_port_id = 0;
    uint32_t            members_count = 0;
    mlnx_port_config_t *port_config;
    mlnx_port_config_t *lag_config;
    sx_status_t         sx_status;
    char                key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);

    sai_db_write_lock();
    status = remove_port_from_lag(lag_log_port_id, mlnx_lag_member.id.log_port_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_port_by_log_id(mlnx_lag_member.id.log_port_id, &port_config);
    if (SAI_ERR(status)) {
        goto out;
    }
    status = mlnx_port_by_log_id(lag_log_port_id, &lag_config);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_acl_port_lag_event_handle_unlocked(port_config, ACL_EVENT_TYPE_LAG_MEMBER_DEL);
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed to remove Lag member port[%x] from ACLs\n", port_config->logical);
        goto out;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag_log_port_id, NULL, &members_count);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = mlnx_wred_mirror_port_event(port_config->logical, true);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error setting port mirror wred discard for port 0x%x\n", port_config->logical);
        goto out;
    }

    status = mlnx_hostif_reapply(port_config);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error reapplying host interface on port 0x%x\n", port_config->logical);
        goto out;
    }

    /* When removing the last member from the LAG, we no longer need to keep on the LAG the settings
     *  that were cloned to it from the first port, and any additional settings. Instead we need to
     *  clear these settings, so it will be possible to add any new member to this LAG. */
    if (members_count == 0) {
        mlnx_qos_queue_config_t *queue;
        uint32_t                 ii;

        port_queues_foreach(lag_config, queue, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }

            status = mlnx_wred_apply_to_queue(lag_config, ii, SAI_NULL_OBJECT_ID);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        status = mlnx_port_samplepacket_params_clear(lag_config, false);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_storm_control_policer_params_clear(lag_config, false);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_mirror_params_clear(lag_config);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_port_egress_block_clear(lag_config->logical);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    SX_LOG_NTC("Removed SAI LAG member\n");

out:
    SX_LOG_EXIT();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_set_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_member_attribute(_In_ sai_object_id_t     lag_member_id,
                                                  _In_ uint32_t            attr_count,
                                                  _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_LAG_MEMBER,
                              lag_member_vendor_attribs,
                              attr_count,
                              attr_list);
}

/**
 * @brief Bulk lag members creation.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_count Number of objects to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *    of attribute for each object to create.
 * @param[in] attr_list List of attributes for every object.
 * @param[in] mode Bulk operation error handling mode.
 *
 * @param[out] object_id List of object ids returned
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or #SAI_STATUS_FAILURE when
 * any of the objects fails to create. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
static sai_status_t mlnx_create_lag_members(_In_ sai_object_id_t          switch_id,
                                            _In_ uint32_t                 object_count,
                                            _In_ const uint32_t          *attr_count,
                                            _In_ const sai_attribute_t  **attr_list,
                                            _In_ sai_bulk_op_error_mode_t mode,
                                            _Out_ sai_object_id_t        *object_id,
                                            _Out_ sai_status_t           *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Bulk lag members removal.
 *
 * @param[in] object_count Number of objects to create
 * @param[in] object_id List of object ids
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or #SAI_STATUS_FAILURE when
 * any of the objects fails to remove. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
static sai_status_t mlnx_remove_lag_members(_In_ uint32_t                 object_count,
                                            _In_ const sai_object_id_t   *object_id,
                                            _In_ sai_bulk_op_error_mode_t mode,
                                            _Out_ sai_status_t           *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    mlnx_get_lag_member_attribute,
    mlnx_create_lag_members,
    mlnx_remove_lag_members,
};
