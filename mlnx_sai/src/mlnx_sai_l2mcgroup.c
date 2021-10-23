/*
 *  Copyright (C) 2018-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#define __MODULE__ SAI_L2MC_GROUP

#define l2mc_group_ptr_to_db_idx(ptr) ((uint32_t)((ptr) - g_sai_db_ptr->l2mc_groups))

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_l2mcgroup_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_l2mcgroup_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static const sai_vendor_attribute_entry_t l2mcgroup_vendor_attribs[] = {
    { SAI_L2MC_GROUP_ATTR_L2MC_MEMBER_LIST,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_l2mcgroup_attrib_get, (void*)SAI_L2MC_GROUP_ATTR_L2MC_MEMBER_LIST,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_l2mcgroup_obj_type_info =
{ l2mcgroup_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
static const sai_vendor_attribute_entry_t l2mcgroup_member_vendor_attribs[] = {
    { SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_GROUP_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_l2mcgroup_member_attrib_get, (void*)SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_GROUP_ID,
      NULL, NULL },
    { SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_OUTPUT_ID,
      {true, false, false, true},
      {true, false, false, true},
      mlnx_l2mcgroup_member_attrib_get, (void*)SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_OUTPUT_ID,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t          mlnx_l2mcgroup_member_obj_type_info =
{ l2mcgroup_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY(), OBJ_STAT_CAP_INFO_EMPTY()};
static void l2mcgroup_key_to_str(_In_ sai_object_id_t object_id, _Out_ char           *key_str)
{
    mlnx_object_id_t *moid = (mlnx_object_id_t*)&object_id;

    if (SAI_OBJECT_TYPE_L2MC_GROUP != moid->object_type) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid %s", SAI_TYPE_STR(moid->object_type));
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "%s %x", SAI_TYPE_STR(moid->object_type), moid->id.l2mc_group.db_idx);
    }
}

static void l2mcgroup_member_key_to_str(_In_ sai_object_id_t object_id, _Out_ char            *key_str)
{
    mlnx_object_id_t *moid = (mlnx_object_id_t*)&object_id;

    if (SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER != moid->object_type) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid %s", SAI_TYPE_STR(moid->object_type));
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "%s (group %x, bport %d)",
                 SAI_TYPE_STR(moid->object_type), moid->id.l2mc_group.db_idx,
                 moid->ext.l2mc_group_member.bport_db_idx);
    }
}

static sai_status_t mlnx_l2mc_group_db_alloc(_Out_ mlnx_l2mc_group_t **l2mc_group)
{
    uint32_t ii;

    assert(l2mc_group);

    for (ii = 0; ii < MLNX_L2MC_GROUP_DB_SIZE; ii++) {
        if (!l2mc_group_db(ii).is_used) {
            memset(&l2mc_group_db(ii), 0, sizeof(l2mc_group_db(ii)));
            l2mc_group_db(ii).is_used = true;

            *l2mc_group = &l2mc_group_db(ii);
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Failed to allocate L2 MC group in DB - DB is full\n");
    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

static sai_status_t mlnx_l2mc_group_init(_In_ mlnx_l2mc_group_t *l2mc_group)
{
    sx_status_t                  sx_status;
    sx_mc_container_id_t         sx_mc_container_id = SX_MC_CONTAINER_ID_INVALID;
    sx_mc_container_attributes_t sx_mc_container_attributes;

    assert(l2mc_group);
    assert(l2mc_group->is_used);

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

    sx_mc_container_attributes.type = SX_MC_CONTAINER_TYPE_PORT;

    sx_status = sx_api_mc_container_set(gh_sdk,
                                        SX_ACCESS_CMD_CREATE,
                                        &sx_mc_container_id,
                                        NULL,
                                        0,
                                        &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create sx_mc_container - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("Created sx_mc_container (%d)\n", sx_mc_container_id);

    l2mc_group->mc_container = sx_mc_container_id;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_deinit(_In_ mlnx_l2mc_group_t *l2mc_group)
{
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

    if (SX_MC_CONTAINER_ID_CHECK_RANGE(l2mc_group->mc_container)) {
        sx_status = sx_api_mc_container_set(gh_sdk,
                                            SX_ACCESS_CMD_DESTROY,
                                            &l2mc_group->mc_container,
                                            NULL,
                                            0,
                                            &sx_mc_container_attributes);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to remove sx_mc_container %x - %s\n",
                       l2mc_group->mc_container, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        l2mc_group->mc_container = SX_MC_CONTAINER_ID_INVALID;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_db_free(_Out_ mlnx_l2mc_group_t *l2mc_group)
{
    memset(l2mc_group, 0, sizeof(*l2mc_group));

    l2mc_group->is_used = false;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_oid_create(_In_ const mlnx_l2mc_group_t *l2mc_group, _Out_ sai_object_id_t         *oid)
{
    mlnx_object_id_t *moid;

    assert(l2mc_group);
    assert(oid);

    memset(oid, 0, sizeof(sai_object_id_t));

    moid = (mlnx_object_id_t*)oid;

    moid->object_type = SAI_OBJECT_TYPE_L2MC_GROUP;
    moid->id.l2mc_group.db_idx = l2mc_group_ptr_to_db_idx(l2mc_group);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_bports_get(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                               _Out_ mlnx_bridge_port_t    **bports,
                                               _Inout_ uint32_t             *bports_count)
{
    sai_status_t     status;
    sx_port_log_id_t sx_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         ports_count = MAX_BRIDGE_1Q_PORTS, ii;

    assert(l2mc_group);
    assert(bports);

    status = mlnx_l2mc_group_sx_ports_get(l2mc_group, sx_ports, &ports_count);
    if (SAI_ERR(status)) {
        return status;
    }

    if (*bports_count < ports_count) {
        SX_LOG_ERR("bports array size %u < %u\n", *bports_count, ports_count);
        *bports_count = ports_count;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    for (ii = 0; ii < ports_count; ii++) {
        status = mlnx_bridge_port_by_log(sx_ports[ii], &bports[ii]);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to find bridge port for log port %x in mc container %x\n",
                       sx_ports[ii], l2mc_group->mc_container);
            return SAI_STATUS_FAILURE;
        }
    }

    *bports_count = ports_count;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_oid_to_sai(_In_ sai_object_id_t oid, _Out_ mlnx_l2mc_group_t **l2mc_group)
{
    sai_status_t status;
    uint32_t     db_idx;

    assert(l2mc_group);

    status = mlnx_l2mc_group_oid_to_db_idx(oid, &db_idx);
    if (SAI_ERR(status)) {
        return status;
    }

    *l2mc_group = &l2mc_group_db(db_idx);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_oid_to_db_idx(_In_ sai_object_id_t oid, _Out_ uint32_t       *db_idx)
{
    const mlnx_object_id_t *moid;

    assert(db_idx);

    moid = (mlnx_object_id_t*)&oid;

    if (moid->object_type != SAI_OBJECT_TYPE_L2MC_GROUP) {
        SX_LOG_ERR("Invalid L2 MC group oid - %lx\n", oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *db_idx = moid->id.l2mc_group.db_idx;
    SX_LOG_NTC("oid %lx fetching l2mc idx %u\n", oid, moid->id.l2mc_group.db_idx);

    if (!MLNX_L2MC_GROUP_DB_IDX_IS_VALID(*db_idx)) {
        SX_LOG_ERR("Invalid db index %d in oid %lx\n", *db_idx, oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (!l2mc_group_db(*db_idx).is_used) {
        SX_LOG_ERR("Invalid L2 MC group in oid %lx - group is not created or deleted\n", oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_sx_ports_get(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                          _Out_ sx_port_log_id_t       *sx_ports,
                                          _Inout_ uint32_t             *ports_count)
{
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    sx_mc_next_hop_t            *sx_next_hops = NULL;
    uint32_t                     next_hops_count = MAX_BRIDGE_1Q_PORTS, ii;
    sx_status_t                  status = SAI_STATUS_SUCCESS;

    assert(l2mc_group);
    assert(sx_ports);
    assert(*ports_count >= MAX_BRIDGE_1Q_PORTS);

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));
    sx_next_hops = (sx_mc_next_hop_t*)malloc(sizeof(sx_mc_next_hop_t) * MAX_BRIDGE_1Q_PORTS);

    if (!sx_next_hops) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    sx_status = sx_api_mc_container_get(gh_sdk,
                                        SX_ACCESS_CMD_GET,
                                        l2mc_group->mc_container,
                                        sx_next_hops,
                                        &next_hops_count,
                                        &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ports from sx_mc_container %x - %s\n", l2mc_group->mc_container,
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (*ports_count < next_hops_count) {
        SX_LOG_ERR("sx_ports array size %u < %u\n", *ports_count, next_hops_count);
        *ports_count = next_hops_count;
        status = SAI_STATUS_BUFFER_OVERFLOW;
        goto out;
    }

    for (ii = 0; ii < next_hops_count; ii++) {
        sx_ports[ii] = sx_next_hops[ii].data.log_port;
    }

    *ports_count = next_hops_count;

out:
    free(sx_next_hops);
    return status;
}

sai_status_t mlnx_l2mc_group_to_pbs_info(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                         _Out_ mlnx_acl_pbs_info_t    *pbs_info)
{
    assert(l2mc_group);
    assert(pbs_info);

    pbs_info->type = MLNX_ACL_PBS_TYPE_MCGROUP;
    pbs_info->idx = l2mc_group_ptr_to_db_idx(l2mc_group);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_pbs_info_to_group(_In_ mlnx_acl_pbs_info_t pbs_info, _Out_ mlnx_l2mc_group_t **l2mc_group)
{
    assert(l2mc_group);
    assert(pbs_info.type == MLNX_ACL_PBS_TYPE_MCGROUP);

    *l2mc_group = &l2mc_group_db(pbs_info.idx);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_l2mc_group_pbs_use(_In_ mlnx_l2mc_group_t *l2mc_group)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_acl_pbs_entry_t    sx_pbs_entry;
    mlnx_acl_pbs_entry_t *pbs_entry;
    mlnx_bridge_port_t   *bports[MAX_PORTS_DB * 2] = {NULL};
    sx_port_id_t          sx_ports[MAX_PORTS_DB * 2] = {0};
    uint32_t              bports_count = MAX_PORTS_DB * 2, ii;

    assert(l2mc_group);

    pbs_entry = &l2mc_group->pbs_entry;

    if (pbs_entry->ref_counter == 0) {
        memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));

        status = mlnx_l2mc_group_bports_get(l2mc_group, bports, &bports_count);
        if (SAI_ERR(status)) {
            return status;
        }

        for (ii = 0; ii < bports_count; ii++) {
            sx_ports[ii] = bports[ii]->logical;
        }

        sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
        sx_pbs_entry.port_num = bports_count;
        sx_pbs_entry.log_ports = sx_ports;

        sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                                          &sx_pbs_entry, &pbs_entry->pbs_id);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to create pbs - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    pbs_entry->ref_counter++;

    return SAI_STATUS_SUCCESS;
}

void mlnx_l2mc_group_flood_ctrl_ref_inc(_In_ uint32_t group_db_idx)
{
    assert(MLNX_L2MC_GROUP_DB_IDX_IS_VALID(group_db_idx));

    l2mc_group_db(group_db_idx).flood_ctrl_ref++;

    SX_LOG_DBG("Increased a ref (%d) for l2mc group idx %u\n", l2mc_group_db(group_db_idx).flood_ctrl_ref,
               group_db_idx);
}

void mlnx_l2mc_group_flood_ctrl_ref_dec(_In_ uint32_t group_db_idx)
{
    assert(MLNX_L2MC_GROUP_DB_IDX_IS_VALID(group_db_idx));

    if (!l2mc_group_db(group_db_idx).flood_ctrl_ref) {
        SX_LOG_ERR("Failed to decrease a ref for L2MC group idx %u\n", group_db_idx);
        return;
    }

    l2mc_group_db(group_db_idx).flood_ctrl_ref--;

    SX_LOG_DBG("Decreased a ref (%d) for l2mc group idx %d\n", l2mc_group_db(group_db_idx).flood_ctrl_ref,
               group_db_idx);
}

static sai_status_t mlnx_l2mc_group_is_in_use(_In_ mlnx_l2mc_group_t *l2mc_group, _Out_ bool             *is_in_use)
{
    sx_status_t                  sx_status;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    uint32_t                     next_hops_count = 0;

    assert(l2mc_group);
    assert(is_in_use);

    if (l2mc_group->pbs_entry.ref_counter > 0) {
        SX_LOG_ERR("L2 MC group is in use in ACL Entry (%d ref(s))\n", l2mc_group->pbs_entry.ref_counter);
        *is_in_use = true;
        return SAI_STATUS_SUCCESS;
    }

    if (l2mc_group->flood_ctrl_ref > 0) {
        SX_LOG_ERR("L2 MC group is in use as flood control group (%d ref(s))\n", l2mc_group->flood_ctrl_ref);
        *is_in_use = true;
        return SAI_STATUS_SUCCESS;
    }

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));

    sx_status = sx_api_mc_container_get(gh_sdk,
                                        SX_ACCESS_CMD_GET,
                                        l2mc_group->mc_container,
                                        NULL,
                                        &next_hops_count,
                                        &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get ports count from sx_mc_container %x - %s\n", l2mc_group->mc_container,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (next_hops_count > 0) {
        SX_LOG_ERR("L2 MC group has %d member(s)\n", next_hops_count);
        *is_in_use = true;
        return SAI_STATUS_SUCCESS;
    }

    *is_in_use = false;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_member_sai_to_oid(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                                      _In_ mlnx_bridge_port_t      *bport,
                                                      _Out_ sai_object_id_t        *oid)
{
    mlnx_object_id_t *moid;

    assert(oid);

    memset(oid, 0, sizeof(sai_object_id_t));

    if (bport->index > UINT16_MAX) {
        SX_LOG_ERR("Failed to create L2 MC group member oid - bridge port id %d > max (%d)\n",
                   bport->index, UINT16_MAX);
        return SAI_STATUS_FAILURE;
    }

    moid = (mlnx_object_id_t*)oid;

    moid->object_type = SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER;
    moid->id.l2mc_group.db_idx = l2mc_group_ptr_to_db_idx(l2mc_group);
    moid->ext.l2mc_group_member.bport_db_idx = bport->index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_member_oid_to_sai(_In_ sai_object_id_t       oid,
                                                      _Out_ mlnx_bridge_port_t **bport,
                                                      _Out_ mlnx_l2mc_group_t  **l2mc_group)
{
    sai_status_t      status;
    uint32_t          db_idx;
    mlnx_object_id_t *moid;

    assert(bport);
    assert(l2mc_group);

    moid = (mlnx_object_id_t*)&oid;

    if (moid->object_type != SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER) {
        SX_LOG_ERR("Invalid L2 MC group member oid - %lx\n", oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    db_idx = moid->id.l2mc_group.db_idx;

    if (!MLNX_L2MC_GROUP_DB_IDX_IS_VALID(db_idx)) {
        SX_LOG_ERR("Invalid db index %d in oid %lx\n", db_idx, oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *l2mc_group = &l2mc_group_db(moid->id.l2mc_group.db_idx);

    if (!(*l2mc_group)->is_used) {
        SX_LOG_ERR("Invalid L2 MC group in oid %lx - group is not created or deleted\n", oid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    status = mlnx_bridge_port_by_idx(moid->ext.l2mc_group_member.bport_db_idx, bport);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to parse L2 MC group member oid\n");
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_sx_container_update(_In_ mlnx_l2mc_group_t        *l2mc_group,
                                                  _In_ const mlnx_bridge_port_t *bport,
                                                  _In_ bool                      add)
{
    sx_status_t                  sx_status;
    sx_access_cmd_t              sx_cmd;
    sx_mc_container_attributes_t sx_mc_container_attributes;
    sx_mc_next_hop_t             sx_mc_next_hop;

    assert(l2mc_group);
    assert(bport);

    memset(&sx_mc_container_attributes, 0, sizeof(sx_mc_container_attributes));
    memset(&sx_mc_next_hop, 0, sizeof(sx_mc_next_hop));

    sx_cmd = add ? SX_ACCESS_CMD_ADD : SX_ACCESS_CMD_DELETE;

    sx_mc_container_attributes.type = SX_MC_CONTAINER_TYPE_PORT;
    sx_mc_next_hop.type = SX_MC_NEXT_HOP_TYPE_LOG_PORT;
    sx_mc_next_hop.data.log_port = bport->logical;

    sx_status = sx_api_mc_container_set(gh_sdk, sx_cmd, &l2mc_group->mc_container,
                                        &sx_mc_next_hop, 1, &sx_mc_container_attributes);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s port %x, sx_mc_container %x - %s\n", SX_ACCESS_CMD_STR(sx_cmd), bport->logical,
                   l2mc_group->mc_container, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_sx_pbs_update(_In_ mlnx_l2mc_group_t        *l2mc_group,
                                            _In_ const mlnx_bridge_port_t *bport,
                                            _In_ bool                      add)
{
    sx_status_t        sx_status;
    sx_port_log_id_t   sx_port;
    sx_acl_pbs_id_t    sx_pbs;
    sx_access_cmd_t    sx_cmd;
    sx_acl_pbs_entry_t sx_pbs_entry;

    assert(l2mc_group);
    assert(bport);

    if (l2mc_group->pbs_entry.ref_counter == 0) {
        return SAI_STATUS_SUCCESS;
    }

    sx_pbs = l2mc_group->pbs_entry.pbs_id;

    memset(&sx_pbs_entry, 0, sizeof(sx_pbs_entry));

    sx_port = bport->logical;
    sx_cmd = add ? SX_ACCESS_CMD_ADD_PORTS : SX_ACCESS_CMD_DELETE_PORTS;

    sx_pbs_entry.entry_type = SX_ACL_PBS_ENTRY_TYPE_MULTICAST;
    sx_pbs_entry.port_num = 1;
    sx_pbs_entry.log_ports = &sx_port;

    sx_status = sx_api_acl_policy_based_switching_set(gh_sdk, sx_cmd, DEFAULT_ETH_SWID, &sx_pbs_entry, &sx_pbs);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s port %x to pbs %x - %s\n", SX_ACCESS_CMD_STR(sx_cmd), sx_port, sx_pbs,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_NTC("Added port %x to PBS %x\n", sx_port, sx_pbs);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_fid_uc_bc_flood_ctrl_update(_In_ sx_fid_t                  sx_fid,
                                                                _In_ sx_flood_control_type_t   sx_flood_type,
                                                                _In_ const mlnx_bridge_port_t *bport,
                                                                _In_ bool                      add)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_access_cmd_t  sx_cmd;
    sx_port_log_id_t fid_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         fid_ports_count = MAX_BRIDGE_1Q_PORTS, ii;
    bool             port_in_fid;

    assert(bport);

    status = mlnx_fid_ports_get(sx_fid, fid_ports, &fid_ports_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get fid %u ports\n", sx_fid);
        return status;
    }

    port_in_fid = false;
    for (ii = 0; ii < fid_ports_count; ii++) {
        if (fid_ports[ii] == bport->logical) {
            port_in_fid = true;
            break;
        }
    }

    if (!port_in_fid) {
        return SAI_STATUS_SUCCESS;
    }

    sx_cmd = (add) ? SX_ACCESS_CMD_DELETE_PORTS : SX_ACCESS_CMD_ADD_PORTS;
    sx_status = sx_api_fdb_flood_control_set(gh_sdk, sx_cmd, DEFAULT_ETH_SWID, sx_fid,
                                             sx_flood_type, 1, &bport->logical);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to %s ports to fid %u flood control - %s.\n", SX_ACCESS_CMD_STR(
                       sx_cmd), sx_fid, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("%s %x for fid %d %s flood control list\n", SX_ACCESS_CMD_STR(sx_cmd), bport->logical, sx_fid,
               (sx_flood_type == SX_FLOOD_CONTROL_TYPE_UNICAST_E) ? "UC" : "BC");

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_flood_ctrl_mc_refresh(_In_ const mlnx_l2mc_group_t *l2mc_group,
                                                          _In_ sx_fid_t                 sx_fid)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t sx_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         ports_count = MAX_BRIDGE_1Q_PORTS;

    assert(l2mc_group);

    status = mlnx_l2mc_group_sx_ports_get(l2mc_group, sx_ports, &ports_count);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_fdb_unreg_mc_flood_ports_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, sx_ports, ports_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set unreg fdb flood port list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("Refreshed fid %d L2MC group mc flood control config (set %d ports)\n", sx_fid, ports_count);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_fid_flood_ctrl_update(_In_ mlnx_l2mc_group_t        *l2mc_group,
                                                          _In_ sx_fid_t                  sx_fid,
                                                          _In_ mlnx_fid_flood_data_t    *flood_data,
                                                          _In_ const mlnx_bridge_port_t *bport,
                                                          _In_ bool                      add)
{
    sai_status_t               status;
    mlnx_fid_flood_ctrl_attr_t attr;
    uint32_t                   l2mc_group_db_idx;

    assert(l2mc_group);
    assert(flood_data);
    assert(bport);

    l2mc_group_db_idx = l2mc_group_ptr_to_db_idx(l2mc_group);

    for (attr = MLNX_FID_FLOOD_CTRL_ATTR_UC; attr < MLNX_FID_FLOOD_CTRL_ATTR_MAX; attr++) {
        if (g_sai_db_ptr->flood_actions[attr] == SAI_PACKET_ACTION_DROP) {
            continue;
        }

        if ((flood_data->types[attr].l2mc_db_idx != l2mc_group_db_idx) ||
            (flood_data->types[attr].type != MLNX_FID_FLOOD_TYPE_L2MC_GROUP)) {
            continue;
        }

        if (attr == MLNX_FID_FLOOD_CTRL_ATTR_UC) {
            status = mlnx_l2mc_group_fid_uc_bc_flood_ctrl_update(sx_fid, SX_FLOOD_CONTROL_TYPE_UNICAST_E, bport, add);
            if (SAI_ERR(status)) {
                return status;
            }

            continue;
        }

        if (attr == MLNX_FID_FLOOD_CTRL_ATTR_BC) {
            status =
                mlnx_l2mc_group_fid_uc_bc_flood_ctrl_update(sx_fid, SX_FLOOD_CONTROL_TYPE_BROADCAST_E, bport, add);
            if (SAI_ERR(status)) {
                return status;
            }

            continue;
        }

        if (attr == MLNX_FID_FLOOD_CTRL_ATTR_MC) {
            status = mlnx_l2mc_group_flood_ctrl_mc_refresh(l2mc_group, sx_fid);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_flood_ctrl_update(_In_ mlnx_l2mc_group_t        *l2mc_group,
                                                      _In_ const mlnx_bridge_port_t *bport,
                                                      _In_ bool                      add)
{
    sai_status_t    status;
    sai_vlan_id_t   vlan_id;
    mlnx_bridge_t  *bridge;
    mlnx_vlan_db_t *vlan;
    uint32_t        ii;

    assert(l2mc_group);
    assert(bport);

    if (l2mc_group->flood_ctrl_ref == 0) {
        return SAI_STATUS_SUCCESS;
    }

    mlnx_vlan_id_foreach(vlan_id) {
        if (!mlnx_vlan_is_created(vlan_id)) {
            continue;
        }

        vlan = mlnx_vlan_db_get_vlan(vlan_id);
        assert(vlan);

        status = mlnx_l2mc_group_fid_flood_ctrl_update(l2mc_group, vlan_id, &vlan->flood_data, bport, add);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    mlnx_bridge_1d_foreach(bridge, ii) {
        status = mlnx_l2mc_group_fid_flood_ctrl_update(l2mc_group,
                                                       bridge->sx_bridge_id,
                                                       &bridge->flood_data,
                                                       bport,
                                                       add);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mc_group_update(_In_ mlnx_l2mc_group_t        *l2mc_group,
                                           _In_ const mlnx_bridge_port_t *bport,
                                           _In_ bool                      add)
{
    sai_status_t status;

    status = mlnx_l2mc_sx_container_update(l2mc_group, bport, add);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_l2mc_sx_pbs_update(l2mc_group, bport, add);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_l2mc_group_flood_ctrl_update(l2mc_group, bport, add);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mcgroup_member_add(_In_ mlnx_l2mc_group_t *l2mc_group, _In_ mlnx_bridge_port_t *bport)
{
    sai_status_t status;

    assert(l2mc_group);
    assert(bport);

    if ((bport->port_type != SAI_BRIDGE_PORT_TYPE_PORT) && (bport->port_type != SAI_BRIDGE_PORT_TYPE_SUB_PORT)) {
        SX_LOG_ERR("Only SAI_BRIDGE_PORT_TYPE_PORT/SAI_BRIDGE_PORT_TYPE_SUB_PORT is supported\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    status = mlnx_l2mc_group_update(l2mc_group, bport, true);
    if (SAI_ERR(status)) {
        return status;
    }

    bport->l2mc_group_ref++;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mcgroup_member_del(_In_ mlnx_l2mc_group_t *l2mc_group, _In_ mlnx_bridge_port_t *bport)
{
    sai_status_t status;

    assert(l2mc_group);
    assert(bport);

    status = mlnx_l2mc_group_update(l2mc_group, bport, false);
    if (SAI_ERR(status)) {
        return status;
    }

    if (bport->l2mc_group_ref == 0) {
        SX_LOG_ERR("Attempt to decrease bport %d L2MC ref while it is 0\n", bport->index);
    } else {
        bport->l2mc_group_ref--;
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create L2MC group
 *
 * @param[out] l2mc_group_id L2MC group id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_create_l2mc_group(_Out_ sai_object_id_t      *l2mc_group_id,
                                           _In_ sai_object_id_t        switch_id,
                                           _In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list)
{
    sai_status_t       status;
    mlnx_l2mc_group_t *l2mc_group;
    char               list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char               key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    if (NULL == l2mc_group_id) {
        SX_LOG_ERR("NULL l2mc_group_id id param.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_L2MC_GROUP,
                                    l2mcgroup_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_L2MC_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create L2 MC group object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    sai_db_write_lock();

    status = mlnx_l2mc_group_db_alloc(&l2mc_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_l2mc_group_init(l2mc_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to init L2 MC Group\n");
        goto out;
    }

    status = mlnx_l2mc_group_oid_create(l2mc_group, l2mc_group_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    l2mcgroup_key_to_str(*l2mc_group_id, key_str);
    SX_LOG_NTC("Created %s. Object id [%lx]\n", key_str, *l2mc_group_id);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove L2MC group
 *
 * @param[in] l2mc_group_id L2MC group id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_remove_l2mc_group(_In_ sai_object_id_t l2mc_group_id)
{
    sai_status_t       status;
    mlnx_l2mc_group_t *l2mc_group;
    char               key_str[MAX_KEY_STR_LEN] = {0};
    bool               is_in_use = true;

    SX_LOG_ENTER();

    l2mcgroup_key_to_str(l2mc_group_id, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    sai_db_write_lock();

    status = mlnx_l2mc_group_oid_to_sai(l2mc_group_id, &l2mc_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_l2mc_group_is_in_use(l2mc_group, &is_in_use);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to check if L2 MC group %lx is in use\n", l2mc_group_id);
        goto out;
    }

    if (is_in_use) {
        SX_LOG_ERR("Failed to remove L2 MC group %lx\n", l2mc_group_id);
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    status = mlnx_l2mc_group_deinit(l2mc_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_l2mc_group_db_free(l2mc_group);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_l2mcgroup_attrib_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t          status;
    sai_l2mc_group_attr_t attr;
    mlnx_l2mc_group_t    *l2mc_group;
    mlnx_bridge_port_t   *bports[MAX_PORTS_DB * 2] = {NULL};
    sai_object_id_t       group_members[MAX_PORTS_DB * 2];
    uint32_t              bports_count = MAX_PORTS_DB * 2, ii;


    SX_LOG_ENTER();

    attr = (int64_t)arg;

    if (attr != SAI_L2MC_GROUP_ATTR_L2MC_MEMBER_LIST) {
        SX_LOG_ERR("Invalid attribute - %d\n", attr);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    sai_db_read_lock();

    status = mlnx_l2mc_group_oid_to_sai(key->key.object_id, &l2mc_group);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_l2mc_group_bports_get(l2mc_group, bports, &bports_count);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < bports_count; ii++) {
        status = mlnx_l2mc_group_member_sai_to_oid(l2mc_group, bports[ii], &group_members[ii]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_fill_objlist(group_members, bports_count, &value->objlist);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_l2mc_group_attribute(_In_ sai_object_id_t     l2mc_group_id,
                                                  _In_ uint32_t            attr_count,
                                                  _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = l2mc_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    l2mcgroup_key_to_str(l2mc_group_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_L2MC_GROUP,
                              l2mcgroup_vendor_attribs,
                              attr_count,
                              attr_list);
}

/**
 * @brief Create L2MC group member
 *
 * @param[out] l2mc_group_member_id L2MC group member id
 * @param[in] switch_id Switch ID
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_create_l2mc_group_member(_Out_ sai_object_id_t      *l2mc_group_member_id,
                                                  _In_ sai_object_id_t        switch_id,
                                                  _In_ uint32_t               attr_count,
                                                  _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *attr_group_id = NULL, *attr_output_id = NULL;
    mlnx_l2mc_group_t           *l2mc_group;
    mlnx_bridge_port_t          *bport;
    uint32_t                     attr_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    if (NULL == l2mc_group_member_id) {
        SX_LOG_ERR("NULL l2mc_group_member_id id param.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count,
                                    attr_list,
                                    SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER,
                                    l2mcgroup_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check.\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create L2 MC group member object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    find_attrib_in_list(attr_count, attr_list, SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_GROUP_ID, &attr_group_id, &attr_index);
    assert(attr_group_id);

    status = mlnx_l2mc_group_oid_to_sai(attr_group_id->oid, &l2mc_group);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    find_attrib_in_list(attr_count, attr_list, SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_OUTPUT_ID, &attr_output_id,
                        &attr_index);
    assert(attr_group_id);

    sai_db_write_lock();

    status = mlnx_bridge_port_by_oid(attr_output_id->oid, &bport);
    if (SAI_ERR(status)) {
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
        goto out;
    }

    status = mlnx_l2mcgroup_member_add(l2mc_group, bport);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_l2mc_group_member_sai_to_oid(l2mc_group, bport, l2mc_group_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    l2mcgroup_member_key_to_str(*l2mc_group_member_id, key_str);
    SX_LOG_NTC("Created %s. Object id [%lx]\n", key_str, *l2mc_group_member_id);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Remove L2MC group member
 *
 * @param[in] l2mc_group_member_id L2MC group member id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t mlnx_remove_l2mc_group_member(_In_ sai_object_id_t l2mc_group_member_id)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bport;
    mlnx_l2mc_group_t  *l2mc_group;
    char                key_str[MAX_KEY_STR_LEN] = {0};

    SX_LOG_ENTER();

    l2mcgroup_member_key_to_str(l2mc_group_member_id, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    status = mlnx_l2mc_group_member_oid_to_sai(l2mc_group_member_id, &bport, &l2mc_group);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_l2mcgroup_member_del(l2mc_group, bport);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove L2 MC group member %lx\n", l2mc_group_member_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_l2mcgroup_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t                 status;
    mlnx_l2mc_group_t           *l2mc_group;
    mlnx_bridge_port_t          *bport;
    sai_l2mc_group_member_attr_t attr;

    SX_LOG_ENTER();

    attr = (int64_t)arg;

    sai_db_read_lock();

    status = mlnx_l2mc_group_member_oid_to_sai(key->key.object_id, &bport, &l2mc_group);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    switch (attr) {
    case SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_GROUP_ID:
        status = mlnx_l2mc_group_oid_create(l2mc_group, &value->oid);
        break;

    case SAI_L2MC_GROUP_MEMBER_ATTR_L2MC_OUTPUT_ID:
        status = mlnx_bridge_port_to_oid(bport, &value->oid);
        break;

    default:
        SX_LOG_ERR("Invalid attribute %d\n", attr);
        status = SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_l2mc_group_member_attribute(_In_ sai_object_id_t     l2mc_group_member_id,
                                                         _In_ uint32_t            attr_count,
                                                         _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = l2mc_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    l2mcgroup_member_key_to_str(l2mc_group_member_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_L2MC_GROUP_MEMBER,
                              l2mcgroup_member_vendor_attribs, attr_count, attr_list);
}

sai_status_t mlnx_l2mc_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_mc_container_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_l2mc_group_api_t mlnx_l2mc_group_api = {
    mlnx_create_l2mc_group,
    mlnx_remove_l2mc_group,
    NULL,
    mlnx_get_l2mc_group_attribute,
    mlnx_create_l2mc_group_member,
    mlnx_remove_l2mc_group_member,
    NULL,
    mlnx_get_l2mc_group_member_attribute,
};
