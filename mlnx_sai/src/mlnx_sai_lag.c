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
#define __MODULE__ SAI_LAG

typedef enum port_params_ {
    PORT_PARAMS_QOS         = 1 << 0,
        PORT_PARAMS_WRED    = 1 << 1,
        PORT_PARAMS_MIRROR  = 1 << 2,
        PORT_PARAMS_FOR_LAG = PORT_PARAMS_QOS | PORT_PARAMS_WRED | PORT_PARAMS_MIRROR,
        PORT_PARAMS_FLOOD   = 1 << 3,
        PORT_PARAMS_VLAN    = 1 << 4,
        PORT_PARAMS_PVID    = 1 << 5,
        PORT_PARAMS_SFLOW   = 1 << 6,
        PORT_PARAMS_POLICER = 1 << 7,
        PORT_PARAMS_LEARN_MODE = 1 << 8,
        PORT_PARAMS_EGRESS_BLOCK = 1 << 9,
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
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
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
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
    mlnx_object_id_t mlnx_lag_member = {0};
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG Member ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG ID Member %u", mlnx_lag_member.id.log_port_id);
    }
}

static sai_status_t mlnx_port_params_clone(mlnx_port_config_t *to, mlnx_port_config_t *from, port_params_t clone)
{
    sx_status_t                  sx_status;
    sx_cos_rewrite_enable_t      rewrite_enable;
    uint32_t                     max_ets_count;
    sx_cos_trust_level_t         trust_level;
    sx_cos_ets_element_config_t *ets = NULL;
    sx_vid_t                     pvid;
    sx_fdb_learn_mode_t          sx_fdb_learn_mode;
    mlnx_qos_queue_config_t     *queue_cfg;
    sai_status_t                 status = SAI_STATUS_SUCCESS;
    uint8_t                      prio;
    uint32_t                     ii;
    bool                         is_flood_disabled = false;

    is_flood_disabled = mlnx_fdb_is_flood_disabled();

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
        status = mlnx_port_mirror_sessions_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }
    if ((clone & PORT_PARAMS_FLOOD) && is_flood_disabled && mlnx_port_is_in_bridge(from)) {
        mlnx_bridge_port_t *bridge_port;
        uint16_t            fid;

        status = mlnx_bridge_port_by_log(from->logical, &bridge_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to lookup bridge port by log port id %x\n", from->logical);
            goto out;
        }

        mlnx_vlan_id_foreach(fid) {
            if (mlnx_vlan_port_is_set(fid, bridge_port)) {
                sx_status_t sx_status;

                if (g_sai_db_ptr->flood_action_uc == SAI_PACKET_ACTION_DROP) {
                    sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_ADD_PORTS,
                                                             DEFAULT_ETH_SWID, fid, SX_FLOOD_CONTROL_TYPE_UNICAST_E,
                                                             1, &to->logical);

                    status = sdk_to_sai(sx_status);
                }
                if (SAI_ERR(status)) {
                    goto out;
                }

                if (g_sai_db_ptr->flood_action_bc == SAI_PACKET_ACTION_DROP) {
                    sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_ADD_PORTS,
                                                             DEFAULT_ETH_SWID, fid, SX_FLOOD_CONTROL_TYPE_BROADCAST_E,
                                                             1, &to->logical);

                    status = sdk_to_sai(sx_status);
                }
                if (SAI_ERR(status)) {
                    goto out;
                }
            }
        }
    }
    if (clone & PORT_PARAMS_VLAN) {
        sx_vlan_frame_types_t frame_types;
        sx_ingr_filter_mode_t mode;
        sx_status_t           sx_status;

        /* Align VLAN accepted frame types */
        sx_status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, from->logical, &frame_types);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get port accepted frame types for port oid %" PRIx64 " - %s.\n",
                       from->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_vlan_port_accptd_frm_types_set(gh_sdk, to->logical, &frame_types);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port accepted frame types for port oid %" PRIx64 " - %s.\n",
                       to->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }

        /* Align VLAN ingress filter */
        sx_status = sx_api_vlan_port_ingr_filter_get(gh_sdk, from->logical, &mode);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Port ingress filter get for port oid %" PRIx64 " failed - %s\n",
                       from->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_vlan_port_ingr_filter_set(gh_sdk, to->logical, mode);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Port ingress filter set for port oid %" PRIx64 " failed - %s\n",
                       to->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }
    }

    if (clone & PORT_PARAMS_PVID) {
        sx_status = sx_api_vlan_port_pvid_get(gh_sdk, from->logical, &pvid);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to get port pvid for port oid %" PRIx64 " - %s.\n",
                       from->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, to->logical, pvid);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set port pvid for port oid %" PRIx64 " - %s.\n",
                       to->saiport, SX_STATUS_MSG(sx_status));

            return sdk_to_sai(sx_status);
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

    if (clone & PORT_PARAMS_EGRESS_BLOCK) {
        status = mlnx_port_egress_block_clone(to, from);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    free(ets);
    return status;
}

/* When LAG is added to VLAN then it's members are added to this VLAN by SDK, but
 * SDK do not remove the port from this VLAN when the port is removed from LAG */
static sai_status_t port_reset_vlan_params_from_port(mlnx_port_config_t *port, mlnx_port_config_t *lag)
{
    uint16_t              vlan_count = 0;
    sx_vlan_frame_types_t frame_types;
    mlnx_bridge_port_t   *lag_bport;
    sx_port_vlans_t      *vlan_list;
    sx_status_t           sx_status;
    sai_status_t          status;
    uint16_t              vid;
    uint16_t              ii = 0;

    /* Reset to default VLAN ingress filter */
    sx_status = sx_api_vlan_port_ingr_filter_set(gh_sdk, port->logical, SX_INGR_FILTER_ENABLE);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Port ingress filter set %x failed - %s\n", port->logical, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Reset to default VLAN accepted frame types */
    sx_status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port->logical, &frame_types);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    frame_types.allow_untagged = true;
    frame_types.allow_tagged   = true;
    sx_status                  = sx_api_vlan_port_accptd_frm_types_set(gh_sdk, port->logical, &frame_types);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port accepted frame types - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Reset port PVID to default VLAN=1 */
    sx_status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, port->logical, DEFAULT_VLAN);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port pvid - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (!mlnx_port_is_in_bridge(lag)) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_bridge_port_by_log(lag->logical, &lag_bport);
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
            mlnx_bridge_port_t port_bport = { .logical = port->logical };

            if (!mlnx_vlan_port_is_set(vid, lag_bport)) {
                continue;
            }

            mlnx_fdb_port_event_handle(&port_bport, vid, SAI_PORT_EVENT_DELETE);

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

    sx_status = mlnx_hash_ecmp_cfg_apply_on_port(port_id);
    if (SX_ERR(sx_status)) {
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set port learning mode - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Do re-apply for port params which were removed by us before add to the LAG */
    status = mlnx_port_params_clone(port, lag, PORT_PARAMS_WRED | PORT_PARAMS_MIRROR | PORT_PARAMS_SFLOW |
                                    PORT_PARAMS_POLICER | PORT_PARAMS_PVID | PORT_PARAMS_EGRESS_BLOCK);
    if (SAI_ERR(status)) {
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

/* TODO: print profiles info on error */
/* SDK already validate QoS settings, so just check WRED, Policer & Mirroring profiles and Sample Packet sessions*/
static sai_status_t ports_l1_params_check(mlnx_port_config_t *port1, mlnx_port_config_t *port2)
{
    sx_status_t              sx_status;
    sx_vid_t                 pvid1, pvid2;
    mlnx_qos_queue_config_t *queue_cfg1, *queue_cfg2;
    sai_status_t             status;
    uint32_t                 ii;
    bool                     egress_block_equal;

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

    /* PVID */
    sx_status = sx_api_vlan_port_pvid_get(gh_sdk, port1->logical, &pvid1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get port pvid for port oid %" PRIx64 " - %s.\n",
                   port1->saiport, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_vlan_port_pvid_get(gh_sdk, port2->logical, &pvid2);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get port pvid for port oid %" PRIx64 " - %s.\n",
                   port1->saiport, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (pvid1 != pvid2) {
        SX_LOG_ERR("Port oid %" PRIx64 " and port oid %" PRIx64 " have different pvid (%d and %d)\n",
                   port1->saiport, port2->saiport, pvid1, pvid2);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Mirroring */
    status = mlnx_port_mirror_params_check(port1, port2);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Sample packet */
    status = mlnx_port_samplepacket_params_check(port1, port2);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Policers */
    status = mlnx_port_storm_control_params_check(port1, port2);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Egress block list */
    status = mlnx_port_egress_block_compare(port1, port2, &egress_block_equal);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!egress_block_equal) {
        SX_LOG_ERR("Port oid %" PRIx64 " and port oid %" PRIx64 " have different EGRESS_BLOCK_PORT_LIST\n",
                   port1->saiport, port2->saiport);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t validate_port(mlnx_port_config_t *lag, mlnx_port_config_t *port)
{
    sai_status_t status;
    bool         is_in_use_for_egress_block;

    if (mlnx_port_is_in_bridge(port)) {
        SX_LOG_ERR("Can't add port which is under bridge\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (port->rifs) {
        SX_LOG_ERR("Can't add port with created RIFs count=%u\n", port->rifs);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = mlnx_port_egress_block_is_in_use(port->logical, &is_in_use_for_egress_block);
    if (SAI_ERR(status)) {
        return status;
    }

    if (is_in_use_for_egress_block) {
        SX_LOG_ERR("Can't add port oid %" PRIx64 " - is a member another port's EGRESS_BLOCK_LISTS\n", port->saiport);
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
    sai_status_t      status;
    sai_object_id_t   lag_id = key->key.object_id;
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
        if (0 == value->objlist.count) {
            status = MLNX_SAI_STATUS_BUFFER_OVERFLOW_EMPTY_LIST;
        } else {
            status = SAI_STATUS_BUFFER_OVERFLOW;
        }
        SX_LOG((0 == value->objlist.count) ? SX_LOG_NOTICE : SX_LOG_ERROR,
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
    sai_object_id_t  lag_member_id   = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};
    sx_port_log_id_t lag_log_port_id = 0;
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

    status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, lag_log_port_id, NULL, &value->oid);
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
    sai_object_id_t       lag_member_id   = key->key.object_id;
    sx_distributor_mode_t distributor_mode;
    mlnx_object_id_t      mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

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
    sai_object_id_t  lag_member_id   = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

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
    sai_object_id_t     lag_member_id   = key->key.object_id;
    sx_collector_mode_t collector_mode;
    mlnx_object_id_t    mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

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
    sai_object_id_t  lag_member_id   = key->key.object_id;
    mlnx_object_id_t mlnx_lag_member = {0};

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_set
                         (gh_sdk, lag_log_port_id, mlnx_lag_member.id.log_port_id,
                         value->booldata ? COLLECTOR_DISABLE : COLLECTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
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
    const sai_attribute_value_t *attr_ing_acl    = NULL;
    const sai_attribute_value_t *attr_egr_acl    = NULL;
    acl_index_t                  ing_acl_index   = ACL_INDEX_INVALID, egr_acl_index = ACL_INDEX_INVALID;
    sx_port_log_id_t             lag_log_port_id = 0;
    uint32_t                     ii              = 0, index;
    mlnx_port_config_t          *lag             = NULL;

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

    sai_db_write_lock();
    acl_global_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_ATTR_INGRESS_ACL, &attr_ing_acl, &index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_ing_acl->oid,
                                                           MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
                                                           index,
                                                           &ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_LAG_ATTR_EGRESS_ACL, &attr_egr_acl, &index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_egr_acl->oid,
                                                           MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
                                                           index,
                                                           &egr_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_LAG, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag, %s\n", list_str);

    sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, DEFAULT_ETH_SWID,
                                          &lag_log_port_id, NULL, 0);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed create LAG %s.\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, (uint32_t)lag_log_port_id, NULL, lag_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = MAX_PORTS; ii < MAX_PORTS * 2; ii++) {
        if (!mlnx_ports_db[ii].is_present) {
            mlnx_ports_db[ii].logical = lag_log_port_id;
            mlnx_ports_db[ii].saiport = *lag_id;
            lag                       = &mlnx_ports_db[ii];
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

    status = mlnx_port_add(lag);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add LAG port 0x%x\n", lag->logical);
        goto out;
    }

    status = mlnx_hash_ecmp_cfg_apply_on_port(lag->logical);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to apply ECMP config on LAG port 0x%x\n", lag->logical);
        goto out;
    }

    if (attr_ing_acl) {
        status = mlnx_acl_port_lag_rif_bind_point_set(lag->saiport, MLNX_ACL_BIND_POINT_TYPE_INGRESS_LAG,
                                                      ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (attr_egr_acl) {
        status = mlnx_acl_port_lag_rif_bind_point_set(lag->saiport, MLNX_ACL_BIND_POINT_TYPE_EGRESS_LAG,
                                                      egr_acl_index);
        if (SAI_ERR(status)) {
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

    SX_LOG_NTC("Remove SAI LAG oid %" PRIx64 "\n", (uint64_t)lag_id);

    status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL);
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
    sx_port_log_id_t             port_id;
    uint32_t                     port_cnt        = 0;
    mlnx_port_config_t          *port            = NULL;
    mlnx_port_config_t          *lag             = NULL;
    sx_collector_mode_t          collect_mode    = COLLECTOR_ENABLE;
    sx_distributor_mode_t        dist_mode       = DISTRIBUTOR_ENABLE;
    mlnx_object_id_t             mlnx_lag_member = {0};
    sai_object_id_t              wred_oid        = SAI_NULL_OBJECT_ID;
    sai_object_id_t              tmp_oid;
    sai_object_id_t              queue_id;
    mlnx_qos_queue_config_t     *queue;
    uint32_t                     ii;

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

    sai_db_write_lock();
    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }
    status = mlnx_port_by_log_id(lag_id, &lag);
    if (SAI_ERR(status)) {
        goto out;
    }

    wred_oid = port->wred_id;

    status = validate_port(lag, port);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Reset WRED from port & queues */
    port_queues_foreach(port, queue, ii) {
        if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
            continue;
        }

        status = mlnx_queue_cfg_lookup(port->logical, ii, &queue);
        if (SAI_ERR(status)) {
            goto out;
        }
        tmp_oid = queue->wred_id;
        status  = mlnx_create_queue_object(port->logical, ii, &queue_id);
        if (SAI_ERR(status)) {
        }

        status = mlnx_wred_apply(SAI_NULL_OBJECT_ID, queue_id);
        if (SAI_ERR(status)) {
            goto out;
        }
        queue->wred_id = tmp_oid;
    }

    status = mlnx_wred_apply(SAI_NULL_OBJECT_ID, port_oid);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* We need to keep it when port is removing from the LAG, to restore the original WRED profile */
    port->wred_id = wred_oid;

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag->logical, NULL, &port_cnt);
    if (SAI_ERR(status = sdk_to_sai(sx_status))) {
        goto out;
    }

    if (port_cnt) {
        status = ports_l1_params_check(lag, port);
        if (SAI_ERR(status)) {
            goto out;
        }
    } else {
        status = mlnx_port_params_clone(lag,
                                        port,
                                        PORT_PARAMS_FOR_LAG | PORT_PARAMS_SFLOW | PORT_PARAMS_POLICER |
                                        PORT_PARAMS_PVID | PORT_PARAMS_EGRESS_BLOCK);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_port_params_clone(port, lag, PORT_PARAMS_FLOOD | PORT_PARAMS_VLAN | PORT_PARAMS_LEARN_MODE);
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

    acl_global_lock();
    status = mlnx_acl_port_lag_event_handle(port, ACL_EVENT_TYPE_LAG_MEMBER_ADD);
    acl_global_unlock();
    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed to remove Lag member port[%x] from ACLs\n", lag->logical);
        goto out;
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
    mlnx_lag_member.id.log_port_id = port_id;
    mlnx_lag_member.ext.lag.lag_id = SX_PORT_LAG_ID_GET(lag_id);
    mlnx_lag_member.ext.lag.sub_id = SX_PORT_SUB_ID_GET(lag_id);

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_LAG_MEMBER, &mlnx_lag_member, lag_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    lag_member_key_to_str(*lag_member_id, key_str);
    SX_LOG_NTC("Created LAG member %s\n", key_str);

out:
    if (SAI_ERR(status) && (wred_oid != SAI_NULL_OBJECT_ID)) {
        port_queues_foreach(port, queue, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }
            status = mlnx_queue_cfg_lookup(port->logical, ii, &queue);
            if (SAI_ERR(status)) {
                goto out;
            }
            tmp_oid        = queue->wred_id;
            queue->wred_id = SAI_NULL_OBJECT_ID;
            status         = mlnx_create_queue_object(port->logical, ii, &queue_id);
            if (SAI_ERR(status)) {
            }

            status = mlnx_wred_apply(tmp_oid, queue_id);
            if (SAI_ERR(status)) {
                goto out;
            }
        }

        port->wred_id = SAI_NULL_OBJECT_ID;
        status        = mlnx_wred_apply(wred_oid, port_oid);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            return status;
        }
    }

    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_remove_lag_member(_In_ sai_object_id_t lag_member_id)
{
    sai_status_t        status          = SAI_STATUS_SUCCESS;
    mlnx_object_id_t    mlnx_lag_member = {0};
    sx_port_log_id_t    lag_log_port_id = 0;
    uint32_t            members_count   = 0;
    mlnx_port_config_t *port_config;
    mlnx_port_config_t *lag_config;
    sx_status_t         sx_status;
    sai_object_id_t     lag_oid;

    SX_LOG_NTC("Remove SAI LAG member oid %" PRIx64 "\n", (uint64_t)lag_member_id);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &mlnx_lag_member);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, SX_PORT_TYPE_LAG);
    SX_PORT_LAG_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.lag_id);
    SX_PORT_SUB_ID_SET(lag_log_port_id, mlnx_lag_member.ext.lag.sub_id);

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
    lag_oid = lag_config->saiport;

    acl_global_lock();
    status = mlnx_acl_port_lag_event_handle(port_config, ACL_EVENT_TYPE_LAG_MEMBER_DEL);
    acl_global_unlock();

    if (SAI_ERR(status)) {
        SX_LOG_NTC("Failed to remove Lag member port[%x] from ACLs\n", port_config->logical);
        goto out;
    }

    sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID, lag_log_port_id, NULL, &members_count);
    if (SX_ERR(sx_status)) {
        status = sdk_to_sai(sx_status);
        goto out;
    }

    /* When removing the last member from the LAG, we no longer need to keep on the LAG the settings
     *  that were cloned to it from the first port, and any additional settings. Instead we need to
     *  clear these settings, so it will be possible to add any new member to this LAG. */
    if (members_count == 0) {
        sai_object_id_t          queue_id;
        mlnx_qos_queue_config_t *queue;
        uint32_t                 ii;

        status = mlnx_wred_apply(SAI_NULL_OBJECT_ID, lag_oid);
        if (SAI_ERR(status)) {
            goto out;
        }
        port_queues_foreach(lag_config, queue, ii) {
            if (ii >= RM_API_COS_TRAFFIC_CLASS_NUM) {
                continue;
            }

            status = mlnx_queue_cfg_lookup(lag_config->logical, ii, &queue);
            if (SAI_ERR(status)) {
                goto out;
            }
            status = mlnx_create_queue_object(lag_config->logical, ii, &queue_id);
            if (SAI_ERR(status)) {
            }

            status = mlnx_wred_apply(SAI_NULL_OBJECT_ID, queue_id);
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
sai_status_t mlnx_create_lag_members(_In_ sai_object_id_t         switch_id,
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
 * @brief Bulk lag members removal.
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
sai_status_t mlnx_remove_lag_members(_In_ uint32_t               object_count,
                                     _In_ const sai_object_id_t *object_id,
                                     _In_ sai_bulk_op_type_t     type,
                                     _Out_ sai_status_t         *object_statuses)
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
