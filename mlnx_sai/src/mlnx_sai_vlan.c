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
#define __MODULE__ SAI_VLAN

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define MLNX_FID_FLOOD_CTRL_DATA_DEFAULT \
    ((mlnx_fid_flood_type_data_t) {.type = MLNX_FID_FLOOD_TYPE_ALL, \
                                   .l2mc_db_idx = MLNX_L2MC_GROUP_DB_IDX_INVALID})

/* Returns true if value of mlnx_vlan_port_pair_t is not used */
#define MLNX_VLAN_MEMBER_BULK_PAIR_IS_USED(p) (p.state & MLNX_VLAN_MEMBER_BULK_PAIR_STATE_USED)

/* Converts sx value for vlan member taggin to state for mlnx_vlan_port_pair_t */
#define MLNX_VLAN_MEMBER_BULK_PAIR_TAGGING_SET(tagging) \
    ((tagging == SX_TAGGED_MEMBER) ?                    \
     MLNX_VLAN_MEMBER_BULK_PAIR_STATE_TAGGED :          \
     MLNX_VLAN_MEMBER_BULK_PAIR_STATE_UNTAGGED)

/* Converts a state of mlnx_vlan_port_pair_t to sx value for vlan member */
#define MLNX_VLAN_MEMBER_BULK_PAIR_TAGGING_GET(p)          \
    ((p.state == MLNX_VLAN_MEMBER_BULK_PAIR_STATE_TAGGED) ? \
     SX_TAGGED_MEMBER :                                     \
     SX_UNTAGGED_MEMBER)

typedef struct _mlnx_vlan_member_data_t {
    sai_object_id_t            oid;
    sx_vlan_id_t               vid;
    uint32_t                   bport_index;
    sx_untagged_member_state_t tagging;
    sx_untagged_prio_state_t   prio_tagging;
} mlnx_vlan_member_data_t;
typedef enum _mlnx_vlan_member_bulk_pair_state_t {
    MLNX_VLAN_MEMBER_BULK_PAIR_STATE_NOT_USED = 0,
    MLNX_VLAN_MEMBER_BULK_PAIR_STATE_USED     = 1,
    MLNX_VLAN_MEMBER_BULK_PAIR_STATE_UNTAGGED = ((0 << 1) | MLNX_VLAN_MEMBER_BULK_PAIR_STATE_USED),
    MLNX_VLAN_MEMBER_BULK_PAIR_STATE_TAGGED   = ((1 << 1) | MLNX_VLAN_MEMBER_BULK_PAIR_STATE_USED),
} PACKED_ENUM mlnx_vlan_member_bulk_pair_state_t;

PACKED(
    struct _mlnx_vlan_port_pair_t {
        mlnx_vlan_member_bulk_pair_state_t state;
        uint32_t object_index;
    }, );
typedef struct _mlnx_vlan_port_pair_t mlnx_vlan_port_pair_t;

PACKED(struct _mlnx_vlan_member_flood_ctrl_data_t {
           bool vlan_port_present[MAX_BRIDGE_1Q_PORTS][MAX_VLANS];
           uint16_t vlan_ports_count[MAX_VLANS];
       }, );
typedef struct _mlnx_vlan_member_flood_ctrl_data_t mlnx_vlan_member_flood_ctrl_data_t;
typedef struct _mlnx_vlan_member_prio_tag_port_data_t {
    bool                     is_used;
    sx_untagged_prio_state_t prio_tagging;
} mlnx_vlan_member_prio_tag_port_data_t;
typedef struct _mlnx_vlan_member_prio_tag_data_t {
    mlnx_vlan_member_prio_tag_port_data_t ports[MAX_BRIDGE_1Q_PORTS];
} mlnx_vlan_member_prio_tag_data_t;
typedef struct _mlnx_vlan_member_bulk_data_t {
    mlnx_vlan_port_pair_t              pairs[MAX_BRIDGE_1Q_PORTS][MAX_VLANS];
    uint16_t                           vlan_ports[MAX_VLANS];
    uint16_t                           port_vlans[MAX_BRIDGE_1Q_PORTS];
    mlnx_vlan_member_flood_ctrl_data_t flood_ctrl_data;
    mlnx_vlan_member_prio_tag_data_t   prio_tag_data;
} mlnx_vlan_member_bulk_data_t;

/*
 * Index for column or row in mlnx_vlan_member_bulk_data_t.pairs table
 */
typedef struct _mlnx_vlan_member_bulk_sequence_data_t {
    uint32_t index;
    bool     is_port;
} mlnx_vlan_member_bulk_sequence_data_t;

static mlnx_vlan_member_bulk_data_t mlnx_vlan_member_bulk_data;
static void mlnx_vlan_db_remove_vlan(_In_ sai_vlan_id_t vlan_id);
static sai_status_t mlnx_vlan_id_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_vlan_member_object_create(_In_ sx_vlan_id_t      vlan_id,
                                                   _In_ uint32_t          bport_index,
                                                   _Out_ sai_object_id_t *vlan_member_id);
static sai_status_t mlnx_vlan_member_oid_to_vlan_port(_In_ sai_object_id_t       vlan_member_id,
                                                      _Out_ uint16_t            *vlan_id,
                                                      _Out_ mlnx_bridge_port_t **bport);
static sai_status_t mlnx_vlan_learn_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_vlan_learn_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_vlan_flood_ctrl_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_vlan_flood_ctrl_type_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg);
static sai_status_t mlnx_vlan_flood_ctrl_l2mc_group_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_vlan_flood_ctrl_l2mc_group_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static sai_status_t mlnx_vlan_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_vlan_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static sai_status_t mlnx_vlan_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_vlan_member_tagging_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_vlan_member_tagging_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
/** STP Instance that the VLAN is associated to [sai_object_id_t] **/
static sai_status_t mlnx_vlan_stp_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_vlan_stp_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static mlnx_fid_flood_ctrl_type_t mlnx_vlan_flood_type_to_fid_type(_In_ sai_vlan_flood_control_type_t type);
static const sai_vendor_attribute_entry_t vlan_vendor_attribs[] = {
    { SAI_VLAN_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_id_get, NULL,
      NULL, NULL },
    { SAI_VLAN_ATTR_MEMBER_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_vlan_member_list_get, NULL,
      NULL, NULL },
    { SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_max_learned_addresses_get, NULL,
      mlnx_vlan_max_learned_addresses_set, NULL },
    { SAI_VLAN_ATTR_STP_INSTANCE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_stp_get, NULL,
      mlnx_vlan_stp_set, NULL },
    { SAI_VLAN_ATTR_LEARN_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_learn_get, NULL,
      mlnx_vlan_learn_set, NULL },
    { SAI_VLAN_ATTR_INGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN },
    { SAI_VLAN_ATTR_EGRESS_ACL,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN },
    { SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_type_get, (void*)SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE,
      mlnx_vlan_flood_ctrl_type_set, (void*)SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE },
    { SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_type_get, (void*)SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE,
      mlnx_vlan_flood_ctrl_type_set, (void*)SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE },
    { SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_type_get, (void*)SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE,
      mlnx_vlan_flood_ctrl_type_set, (void*)SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE },
    { SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_l2mc_group_get, (void*)SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP,
      mlnx_vlan_flood_ctrl_l2mc_group_set, (void*)SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP },
    { SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_l2mc_group_get, (void*)SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP,
      mlnx_vlan_flood_ctrl_l2mc_group_set, (void*)SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP },
    { SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_flood_ctrl_l2mc_group_get, (void*)SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP,
      mlnx_vlan_flood_ctrl_l2mc_group_set, (void*)SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP },
    { SAI_VLAN_ATTR_META_DATA,
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
static const mlnx_attr_enum_info_t        vlan_enum_info[] = {
    [SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE]   = ATTR_ENUM_VALUES_ALL(),
    [SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE]         = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_vlan_obj_type_info =
{ vlan_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(vlan_enum_info)};
static const sai_vendor_attribute_entry_t vlan_member_vendor_attribs[] = {
    { SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_member_tagging_get, NULL,
      mlnx_vlan_member_tagging_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        vlan_member_enum_info[] = {
    [SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE] = ATTR_ENUM_VALUES_ALL()
};
const mlnx_obj_type_attrs_info_t          mlnx_vlan_member_obj_type_info =
{ vlan_member_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(vlan_member_enum_info)};
static void vlan_key_to_str(_In_ sai_vlan_id_t vlan_id, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "vlan %u", vlan_id);
}

sai_status_t mlnx_max_learned_addresses_value_validate(_In_ uint32_t limit, _In_ uint32_t attr_index)
{
    if (!SX_FDB_UC_LIMIT_CHECK_RANGE(limit)) {
        SX_LOG_ERR("Invalid value for learning limit - %d. Valid range is [%d, %d)\n",
                   limit, 0, SX_FDB_MAX_ENTRIES);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_bridge_max_learned_addresses_set(_In_ sx_vid_t sx_vid, _In_ uint32_t limit)
{
    sx_status_t sx_status;
    uint32_t    sx_limit;

    /* Conversion from SAI to SDK for disabled limit */
    sx_limit = MLNX_FDB_LIMIT_SAI_TO_SX(limit);

    sx_status = sx_api_fdb_uc_limit_fid_set(gh_sdk, SX_ACCESS_CMD_SET, DEFAULT_ETH_SWID, sx_vid, sx_limit);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set learning limit - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_bridge_max_learned_addresses_get(_In_ sx_vid_t sx_vid, _In_ uint32_t *limit)
{
    sx_status_t sx_status;
    uint32_t    sx_limit;

    assert(limit);

    sx_status = sx_api_fdb_uc_limit_fid_get(gh_sdk, DEFAULT_ETH_SWID, sx_vid, &sx_limit);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get learning limit - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *limit = MLNX_FDB_LIMIT_SX_TO_SAI(sx_limit);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Vlan Id
 *
 * @type sai_uint16_t
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY | KEY
 */
static sai_status_t mlnx_vlan_id_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    uint16_t     vlan_id;
    sai_status_t status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->u16 = vlan_id;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_object_id_t    *port_list = NULL;
    uint32_t            ports_cnt = 0;
    uint16_t            vlan_id;
    sx_status_t         status = SAI_STATUS_SUCCESS;
    mlnx_bridge_port_t *port;
    uint32_t            ii;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    mlnx_vlan_ports_foreach(vlan_id, port, ii) {
        ports_cnt++;
    }

    if (!ports_cnt) {
        value->objlist.count = 0;
        goto out;
    }

    port_list = (sai_object_id_t*)malloc(sizeof(sai_object_id_t) * ports_cnt);
    if (!port_list) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    ports_cnt = 0;
    mlnx_vlan_ports_foreach(vlan_id, port, ii) {
        status = mlnx_vlan_member_object_create(vlan_id, port->index, &port_list[ports_cnt++]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_fill_objlist(port_list, ports_cnt, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    free(port_list);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_learn_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    uint16_t            vlan_id;
    sx_status_t         status;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_fid_learn_mode_get(gh_sdk, DEFAULT_ETH_SWID, vlan_id, &mode))) {
        SX_LOG_ERR("Failed to get learn mode %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SX_FDB_LEARN_MODE_DONT_LEARN == mode) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_learn_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    uint16_t            vlan_id;
    sx_status_t         status;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    if (value->booldata) {
        mode = SX_FDB_LEARN_MODE_DONT_LEARN;
    } else {
        mode = SX_FDB_LEARN_MODE_AUTO_LEARN;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_fid_learn_mode_set(gh_sdk, DEFAULT_ETH_SWID, vlan_id, mode))) {
        SX_LOG_ERR("Failed to set learn mode %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_max_learned_addresses_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint16_t     vlan_id;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_bridge_max_learned_addresses_get(vlan_id, &value->u32);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_max_learned_addresses_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint16_t     vlan_id;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_max_learned_addresses_value_validate(value->u32, 0);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_vlan_bridge_max_learned_addresses_set(vlan_id, value->u32);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

/* STP id getter */
static sai_status_t mlnx_vlan_stp_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sx_mstp_inst_id_t sx_stp_id;
    uint16_t          vlan_id;
    sai_status_t      status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Get STP by VLAN id */
    sai_db_read_lock();

    sx_stp_id = mlnx_vlan_stp_id_get(vlan_id);
    sai_db_unlock();

    /* Return STP id */
    status = mlnx_create_object(SAI_OBJECT_TYPE_STP, sx_stp_id,
                                NULL, &value->oid);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* STP id setter */
static sai_status_t mlnx_vlan_stp_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_object_id_t   sai_stp_id = value->oid;
    sx_mstp_inst_id_t sx_stp_id;
    uint16_t          vlan_id;
    sai_status_t      status;
    uint32_t          data;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Get new STP id */
    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get STP id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    /* validate STP id */
    if (!SX_MSTP_INST_ID_CHECK_RANGE(sx_stp_id)) {
        SX_LOG_ERR("Invalid STP id: should be within a range [%u - %u]\n",
                   SX_MSTP_INST_ID_MIN, SX_MSTP_INST_ID_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Remove VLAN from its' current STP */
    assert(NULL != g_sai_db_ptr);
    sai_db_write_lock();

    status = mlnx_vlan_stp_unbind(vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unmap VLAN [%u] from its' STP\n", vlan_id);
        goto out;
    }

    /* Bind VLAN to the new STP */
    status = mlnx_vlan_stp_bind(vlan_id, sx_stp_id);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Set VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];
    uint16_t               vid;
    sai_status_t           status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(vlan_id, &vid);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_key_to_str(vid, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs, attr);
}


/*
 * Routine Description:
 *    Get VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_vlan_attribute(_In_ sai_object_id_t     vlan_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];
    uint16_t               vid;
    sai_status_t           status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(vlan_id, &vid);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_key_to_str(vid, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Create a VLAN
 *
 * @param[out] vlan_id VLAN ID
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_create_vlan(_Out_ sai_object_id_t      *sai_vlan_id,
                              _In_ sai_object_id_t        switch_id,
                              _In_ uint32_t               attr_count,
                              _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    const sai_attribute_value_t *vid = NULL, *stp = NULL, *learn = NULL, *max_learned_addresses = NULL, *attr_value =
        NULL;
    uint32_t                     vid_index, stp_index, learn_index, max_learned_addresses_index, attr_index;
    sx_mstp_inst_id_t            sx_stp_id = mlnx_stp_get_default_stp();
    mlnx_object_id_t             stp_obj_id;
    mlnx_vlan_db_t              *vlan_db_entry;
    sai_object_id_t              vlan_oid;
    sai_status_t                 status;
    const sai_attribute_value_t *attr_ing_acl  = NULL;
    acl_index_t                  ing_acl_index = ACL_INDEX_INVALID;
    uint32_t                     ing_acl_attr_index;

    SX_LOG_ENTER();

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create VLAN, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_VLAN_ID, &vid, &vid_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = validate_vlan(vid->u16);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_vlan_oid_create(vid->u16, &vlan_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_STP_INSTANCE, &stp, &stp_index);
    if (stp) {
        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_STP, stp->oid, &stp_obj_id);
        if (SAI_ERR(status)) {
            return status;
        }
        sx_stp_id = stp_obj_id.id.stp_inst_id;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES,
                                 &max_learned_addresses, &max_learned_addresses_index);
    if (!SAI_ERR(status)) {
        status = mlnx_max_learned_addresses_value_validate(max_learned_addresses->u32, max_learned_addresses_index);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    sai_db_write_lock();
    acl_global_lock();

    if (mlnx_vlan_is_created(vid->u16)) {
        SX_LOG_ERR("VLAN %d is already created\n", vid->u16);
        status = SAI_STATUS_INVALID_ATTR_VALUE_0 + vid_index;
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_INGRESS_ACL, &attr_ing_acl, &ing_acl_attr_index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_ing_acl->oid, MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN,
                                                           ing_acl_attr_index, &ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_acl_vlan_bind_point_set(vlan_oid, MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN, ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (max_learned_addresses) {
        status = mlnx_vlan_bridge_max_learned_addresses_set(vid->u16, max_learned_addresses->u32);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_vlan_stp_bind(vid->u16, sx_stp_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_LEARN_DISABLE, &learn, &learn_index))) {
        sai_object_key_t key = { .key.object_id = vlan_oid };

        status = mlnx_vlan_learn_set(&key, learn, NULL);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    vlan_db_entry = mlnx_vlan_db_create_vlan(vid->u16);
    assert(vlan_db_entry);

    find_attrib_in_list(attr_count,
                        attr_list,
                        SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE,
                        &attr_value,
                        &attr_index);
    if (attr_value) {
        vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_UC].type = mlnx_vlan_flood_type_to_fid_type(
            attr_value->s32);
    }

    find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP, &attr_value, &attr_index);
    if (attr_value) {
        status =
            mlnx_l2mc_group_oid_to_db_idx(attr_value->oid,
                                          &vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_UC].l2mc_db_idx);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    find_attrib_in_list(attr_count,
                        attr_list,
                        SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE,
                        &attr_value,
                        &attr_index);
    if (attr_value) {
        vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_MC].type = mlnx_vlan_flood_type_to_fid_type(
            attr_value->s32);
    }

    find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP, &attr_value, &attr_index);
    if (attr_value) {
        status =
            mlnx_l2mc_group_oid_to_db_idx(attr_value->oid,
                                          &vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_MC].l2mc_db_idx);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, &attr_value, &attr_index);
    if (attr_value) {
        vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_BC].type = mlnx_vlan_flood_type_to_fid_type(
            attr_value->s32);
    }

    find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP, &attr_value, &attr_index);
    if (attr_value) {
        status =
            mlnx_l2mc_group_oid_to_db_idx(attr_value->oid,
                                          &vlan_db_entry->flood_data.types[MLNX_FID_FLOOD_CTRL_ATTR_BC].l2mc_db_idx);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    mlnx_fid_flood_ctrl_l2mc_group_refs_inc(&vlan_db_entry->flood_data);

    status       = SAI_STATUS_SUCCESS;
    *sai_vlan_id = vlan_oid;
    SX_LOG_NTC("Created vlan oid %" PRIx64 "\n", vlan_oid);

out:
    acl_global_unlock();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove a VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_vlan(_In_ sai_object_id_t sai_vlan_id)
{
    char                key_str[MAX_KEY_STR_LEN];
    mlnx_bridge_port_t *port;
    uint16_t            vlan_id;
    sai_status_t        status;
    uint32_t            port_idx;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(sai_vlan_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_key_to_str(vlan_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    mlnx_vlan_ports_foreach(vlan_id, port, port_idx) {
        SX_LOG_ERR("Failed to remove vlan which has vlan members\n");
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    if (!mlnx_vlan_is_created(vlan_id)) {
        SX_LOG_ERR("VLAN %d is not created\n", vlan_id);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_acl_vlan_bind_point_clear(sai_vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_stp_unbind(vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unmap VLAN [%u] from STP\n", vlan_id);
        goto out;
    }

    mlnx_fid_flood_ctrl_l2mc_group_refs_dec(&(mlnx_vlan_db_get_vlan(vlan_id)->flood_data));

    mlnx_vlan_db_remove_vlan(vlan_id);

    status = mlnx_fid_flood_ctrl_clear(vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Get vlan statistics counters.
 *
 * @param[in] vlan_id VLAN id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_vlan_stats(_In_ sai_object_id_t        sai_vlan_id,
                                        _In_ uint32_t               number_of_counters,
                                        _In_ const sai_stat_id_t   *counter_ids,
                                        _Out_ uint64_t             *counters)
{
    UNREFERENCED_PARAMETER(sai_vlan_id);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get vlan statistics counters extended.
 *
 * @param[in] vlan_id VLAN id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t mlnx_get_vlan_stats_ext(_In_ sai_object_id_t        vlan_id,
                                     _In_ uint32_t               number_of_counters,
                                     _In_ const sai_stat_id_t   *counter_ids,
                                     _In_ sai_stats_mode_t       mode,
                                     _Out_ uint64_t             *counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Clear vlan statistics counters.
 *
 * @param[in] vlan_id Vlan id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_clear_vlan_stats(_In_ sai_object_id_t        sai_vlan_id,
                                          _In_ uint32_t               number_of_counters,
                                          _In_ const sai_stat_id_t   *counter_ids)
{
    UNREFERENCED_PARAMETER(sai_vlan_id);
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

static void vlan_member_key_to_str(_In_ sai_object_id_t vlan_member_id, _Out_ char *key_str)
{
    mlnx_bridge_port_t *port;
    uint16_t            vlan;

    if (SAI_STATUS_SUCCESS != mlnx_vlan_member_oid_to_vlan_port(vlan_member_id, &vlan, &port)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid vlan member");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Vlan member port %x vlan %u", port->logical, vlan);
    }
}

bool mlnx_vlan_port_is_set(uint16_t vid, const mlnx_bridge_port_t *port)
{
    return array_bit_test(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
}

void mlnx_vlan_port_set(uint16_t vid, mlnx_bridge_port_t *port, bool is_set)
{
    assert(port->index < MAX_BRIDGE_1Q_PORTS);

    if (is_set && !mlnx_vlan_port_is_set(vid, port)) {
        array_bit_set(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        port->vlans++;
    } else if (!is_set && mlnx_vlan_port_is_set(vid, port)) {
        array_bit_clear(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        port->vlans--;
    }
}

sai_status_t mlnx_vlan_sai_tagging_to_sx(_In_ sai_vlan_tagging_mode_t      mode,
                                         _Out_ sx_untagged_member_state_t *tagging,
                                         _Out_ sx_untagged_prio_state_t   *prio_tagging)
{
    assert(tagging);
    assert(prio_tagging);

    switch (mode) {
    case SAI_VLAN_TAGGING_MODE_UNTAGGED:
        *tagging      = SX_UNTAGGED_MEMBER;
        *prio_tagging = SX_UNTAGGED_STATE;
        break;

    case SAI_VLAN_TAGGING_MODE_TAGGED:
        *tagging      = SX_TAGGED_MEMBER;
        *prio_tagging = SX_UNTAGGED_STATE;
        break;

    case SAI_VLAN_TAGGING_MODE_PRIORITY_TAGGED:
        *tagging      = SX_UNTAGGED_MEMBER;
        *prio_tagging = SX_PRIO_TAGGED_STATE;
        break;

    default:
        SX_LOG_ERR("Invalid tagging mode %d\n", mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_object_create(_In_ sx_vlan_id_t      vlan_id,
                                                   _In_ uint32_t          bport_index,
                                                   _Out_ sai_object_id_t *vlan_member_id)
{
    sai_status_t status;
    uint8_t      extended_data[EXTENDED_DATA_SIZE];

    assert(vlan_member_id);

    extended_data[0] = vlan_id & 0xff;
    extended_data[1] = vlan_id >> 8;

    status = mlnx_create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, bport_index, extended_data, vlan_member_id);
    if (SAI_ERR(status)) {
        return status;
    }

    return status;
}

sai_status_t mlnx_vlan_port_add(uint16_t vid, sai_vlan_tagging_mode_t mode, mlnx_bridge_port_t *port)
{
    sai_status_t             status;
    sx_vlan_ports_t          vlan_port_list;
    sx_untagged_prio_state_t sx_prio_tagging;
    sx_status_t              sx_status;

    memset(&vlan_port_list, 0, sizeof(vlan_port_list));

    vlan_port_list.log_port = port->logical;

    status = mlnx_vlan_sai_tagging_to_sx(mode, &vlan_port_list.is_untagged, &sx_prio_tagging);
    if (SAI_ERR(status)) {
        return status;
    }
    sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vid, &vlan_port_list, 1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_vlan_port_prio_tagged_set(gh_sdk, port->logical, sx_prio_tagging);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set prio tagging state to port %x - %s.\n", port->logical, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    mlnx_vlan_port_set(vid, port, true);
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_port_del(uint16_t vid, mlnx_bridge_port_t *port)
{
    sx_vlan_ports_t     port_list;
    sx_status_t         sx_status;
    mlnx_port_config_t *port_config;
    sai_status_t        status;

    memset(&port_list, 0, sizeof(port_list));

    port_list.log_port = port->logical;

    if (!mlnx_vlan_port_is_set(vid, port)) {
        return SAI_STATUS_SUCCESS;
    }

    /* On warmboot init, don't remove vlan 1 members from hw until issu end phase.
     * Sonic first delete all default members, then may recreate some based on actual membership. */
    if ((BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) && (!g_sai_db_ptr->issu_end_called) && (DEFAULT_VLAN == vid)) {
        status = mlnx_port_by_log_id(port->logical, &port_config);
        if (SAI_ERR(status)) {
            return status;
        }
        port_config->issu_remove_default_vid = true;
    } else {
        sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, vid, &port_list, 1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    mlnx_vlan_port_set(vid, port, false);
    return SAI_STATUS_SUCCESS;
}

/*
 *  \brief Create VLAN Member
 *  \param[out] vlan_member_id VLAN member ID
 *  \param[in] attr_count number of attributes
 *  \param[in] attr_list array of attributes
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_create_vlan_member(_Out_ sai_object_id_t     * vlan_member_id,
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *vid = NULL, *port = NULL, *tagging = NULL;
    uint32_t                     vid_index, port_index, tagging_index;
    sai_vlan_tagging_mode_t      mode = SAI_VLAN_TAGGING_MODE_UNTAGGED;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_port_log_id_t             log_port;
    mlnx_bridge_port_t          *bridge_port_cfg;
    mlnx_port_config_t          *port_config;
    uint16_t                     vlan_id;
    sai_status_t                 status;

    SX_LOG_ENTER();

    memset(extended_data, 0, sizeof(extended_data));

    if (NULL == vlan_member_id) {
        SX_LOG_ERR("NULL vlan member ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN_MEMBER, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create vlan member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_VLAN_ID, &vid, &vid_index);
    assert(SAI_STATUS_SUCCESS == status);
    status = sai_object_to_vlan(vid->oid, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, &port, &port_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_bridge_port_to_vlan_port(port->oid, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge port %" PRIx64 " to log port\n", port->oid);
        return status;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
                                 &tagging,
                                 &tagging_index);
    if (!SAI_ERR(status)) {
        mode = tagging->s32;
    }

    sai_db_write_lock();

    status = mlnx_bridge_1q_port_by_log(log_port, &bridge_port_cfg);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_port_add(vlan_id, mode, bridge_port_cfg);
    if (SAI_ERR(status)) {
        goto out;
    }

    if ((BOOT_TYPE_WARM == g_sai_db_ptr->boot_type) && (!g_sai_db_ptr->issu_end_called) && (DEFAULT_VLAN == vlan_id)) {
        status = mlnx_port_by_log_id(log_port, &port_config);
        if (SAI_ERR(status)) {
            goto out;
        }
        port_config->issu_remove_default_vid = false;
    }

    status = mlnx_fid_flood_ctrl_port_event_handle(vlan_id, &mlnx_vlan_db_get_vlan(vlan_id)->flood_data,
                                                   &bridge_port_cfg->logical, 1, MLNX_PORT_EVENT_ADD);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_member_object_create(vlan_id, bridge_port_cfg->index, vlan_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    vlan_member_key_to_str(*vlan_member_id, key_str);
    SX_LOG_NTC("Created vlan member %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 *  \brief Remove VLAN Member
 *  \param[in] vlan_member_id VLAN member ID
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_remove_vlan_member(_In_ sai_object_id_t vlan_member_id)
{
    char                key_str[MAX_KEY_STR_LEN];
    sai_status_t        status;
    mlnx_bridge_port_t *port;
    uint16_t            vlan;

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    SX_LOG_NTC("Remove vlan member interface %s\n", key_str);

    sai_db_write_lock();

    status = mlnx_vlan_member_oid_to_vlan_port(vlan_member_id, &vlan, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!mlnx_vlan_port_is_set(vlan, port)) {
        SX_LOG_ERR("Vlan member does not exist for this vlan %u and bridge port %x\n",
                   vlan, port->logical);

        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out;
    }

    status = mlnx_vlan_port_del(vlan, port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_fid_flood_ctrl_port_event_handle(vlan, &mlnx_vlan_db_get_vlan(vlan)->flood_data,
                                                   &port->logical, 1, MLNX_PORT_EVENT_DELETE);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_member_oid_to_vlan_port(_In_ sai_object_id_t       vlan_member_id,
                                                      _Out_ uint16_t            *vlan_id,
                                                      _Out_ mlnx_bridge_port_t **bport)
{
    sai_status_t status;
    uint32_t     bport_index;
    uint8_t      extended_data[EXTENDED_DATA_SIZE] = {0};

    assert(vlan_id);
    assert(bport);

    status = mlnx_object_to_type(vlan_member_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &bport_index, extended_data);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_bridge_port_by_idx(bport_index, bport);
    if (SAI_ERR(status)) {
        return status;
    }

    *vlan_id = ((uint16_t)extended_data[1]) << 8 | extended_data[0];
    if (!SXD_VID_CHECK_RANGE(*vlan_id)) {
        SX_LOG_ERR("Invalid vlan id %u\n", *vlan_id);
        return SAI_STATUS_INVALID_VLAN_ID;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_oid_to_data(_In_ sai_object_id_t           vlan_member_id,
                                                      _Out_ mlnx_vlan_member_data_t *vlan_member_data)
{
    sai_status_t        status;
    mlnx_bridge_port_t *bport;

    assert(vlan_member_data);

    memset(vlan_member_data, 0, sizeof(*vlan_member_data));

    status = mlnx_vlan_member_oid_to_vlan_port(vlan_member_id, &vlan_member_data->vid, &bport);
    if (SAI_ERR(status)) {
        return status;
    }

    if (!mlnx_vlan_port_is_set(vlan_member_data->vid, bport)) {
        SX_LOG_ERR("Port %x in not a member of VLAN %u\n", bport->logical, vlan_member_data->vid);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    vlan_member_data->bport_index = bport->index;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_attrs_parse(_In_ const sai_attribute_t    *attr_list,
                                                      _In_ uint32_t                  attr_count,
                                                      _Out_ mlnx_vlan_member_data_t *vlan_member_data)
{
    sai_status_t                 status;
    const sai_attribute_value_t *attr_value = NULL;
    mlnx_bridge_port_t          *bridge_port;
    uint32_t                     attr_index;

    if (!attr_list) {
        SX_LOG_ERR("attr_list is NULL\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!vlan_member_data) {
        SX_LOG_ERR("vlan_member_data is NULL\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    memset(vlan_member_data, 0, sizeof(*vlan_member_data));

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_VLAN_ID, &attr_value, &attr_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Missing mandatory attribute SAI_VLAN_MEMBER_ATTR_VLAN_ID\n");
        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
    }

    status = sai_object_to_vlan(attr_value->oid, &vlan_member_data->vid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, &attr_value, &attr_index);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Missing mandatory attribute SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID\n");
        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
    }

    status = mlnx_bridge_port_by_oid(attr_value->oid, &bridge_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge port %" PRIx64 " to index\n", attr_value->oid);
        return status;
    }

    if (bridge_port->port_type != SAI_BRIDGE_PORT_TYPE_PORT) {
        SX_LOG_ERR("Bridge port [%lx] type (%d) is not SAI_BRIDGE_PORT_TYPE_PORT\n", attr_value->oid,
                   bridge_port->port_type);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    if (mlnx_vlan_port_is_set(vlan_member_data->vid, bridge_port)) {
        SX_LOG_ERR("Port %x is already in VLAN %d\n", bridge_port->logical, vlan_member_data->vid);
        return SAI_STATUS_ITEM_ALREADY_EXISTS;
    }

    vlan_member_data->bport_index  = bridge_port->index;
    vlan_member_data->tagging      = SX_UNTAGGED_MEMBER;
    vlan_member_data->prio_tagging = SX_UNTAGGED_STATE;

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
                                 &attr_value, &attr_index);
    if (!SAI_ERR(status)) {
        status = mlnx_vlan_sai_tagging_to_sx(attr_value->s32,
                                             &vlan_member_data->tagging,
                                             &vlan_member_data->prio_tagging);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    status = mlnx_vlan_member_object_create(vlan_member_data->vid, bridge_port->index, &vlan_member_data->oid);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

void mlnx_vlan_member_bulk_init()
{
    memset(&mlnx_vlan_member_bulk_data, 0, sizeof(mlnx_vlan_member_bulk_data));
}

static sai_status_t mlnx_vlan_member_bulk_pair_add(_In_ const mlnx_vlan_member_data_t *vlan_member_data,
                                                   _In_ uint32_t                       pair_index)
{
    uint32_t port_index, vlan_index;

    assert(vlan_member_data);

    vlan_index = vlan_member_data->vid;
    port_index = vlan_member_data->bport_index;

    if (MLNX_VLAN_MEMBER_BULK_PAIR_IS_USED(mlnx_vlan_member_bulk_data.pairs[port_index][vlan_index])) {
        SX_LOG_ERR("The vlan member for port %d and VLAN %d appears twice\n",
                   vlan_member_data->bport_index, vlan_member_data->vid);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + pair_index;
    }

    mlnx_vlan_member_bulk_data.pairs[port_index][vlan_index].state =
        MLNX_VLAN_MEMBER_BULK_PAIR_TAGGING_SET(vlan_member_data->tagging);
    mlnx_vlan_member_bulk_data.pairs[port_index][vlan_index].object_index = pair_index;

    mlnx_vlan_member_bulk_data.port_vlans[port_index]++;
    mlnx_vlan_member_bulk_data.vlan_ports[vlan_index]++;

    mlnx_vlan_member_bulk_data.prio_tag_data.ports[port_index].is_used      = true;
    mlnx_vlan_member_bulk_data.prio_tag_data.ports[port_index].prio_tagging = vlan_member_data->prio_tagging;

    return SAI_STATUS_SUCCESS;
}

/*
 * Puts in 'data' the longest sequence of VLANs belong to the same port or the opposite
 * Returns false when there is no sequnece to get
 */
static bool mlnx_vlan_member_bulk_find_next_sequence(_Out_ mlnx_vlan_member_bulk_sequence_data_t *data)
{
    const uint16_t *port_vlans, *vlan_ports;
    uint32_t        pid, vid;
    uint32_t        max_value, max_index;
    bool            is_port, is_empty;

    assert(data);

    memset(data, 0, sizeof(*data));

    port_vlans = mlnx_vlan_member_bulk_data.port_vlans;
    vlan_ports = mlnx_vlan_member_bulk_data.vlan_ports;

    max_index = 0;
    max_value = port_vlans[max_index];

    is_port  = true;
    is_empty = true;

    for (pid = 0; pid < MAX_BRIDGE_1Q_PORTS; pid++) {
        if (port_vlans[pid] > max_value) {
            max_value = port_vlans[pid];
            max_index = pid;
        }

        if (is_empty && (port_vlans[pid] > 0)) {
            is_empty = false;
        }
    }

    for (vid = 1; vid < MAX_VLANS; vid++) {
        if (vlan_ports[vid] > max_value) {
            max_value = vlan_ports[vid];
            max_index = vid;
            is_port   = false;
        }
    }

    data->index   = max_index;
    data->is_port = is_port;

    return !is_empty;
}

static void mlnx_vlan_member_bulk_fdb_ctrl_set(_In_ uint16_t vlan_id, _In_ uint32_t bport_index, _In_ bool is_set)
{
    if (is_set) {
        mlnx_vlan_member_bulk_data.flood_ctrl_data.vlan_ports_count[vlan_id]++;
    } else {
        mlnx_vlan_member_bulk_data.flood_ctrl_data.vlan_ports_count[vlan_id]--;
    }

    mlnx_vlan_member_bulk_data.flood_ctrl_data.vlan_port_present[bport_index][vlan_id] = is_set;
}

static void mlnx_vlan_member_bulk_db_port_vlan_set(_In_ uint16_t vid, _In_ mlnx_bridge_port_t *port, _In_ bool add)
{
    assert(port->index < MAX_BRIDGE_1Q_PORTS);
    assert(vid < MAX_VLANS);

    if (add && !mlnx_vlan_port_is_set(vid, port)) {
        array_bit_set(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        port->vlans++;
    } else if (!add && mlnx_vlan_port_is_set(vid, port)) {
        array_bit_clear(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        port->vlans--;
    }
}

static sai_status_t mlnx_vlan_memeber_bulk_fdb_ctrl_apply(_In_ bool create)
{
    sai_status_t      status;
    sx_port_log_id_t  sx_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t          ports_count, vlan_ports_count;
    uint32_t          vlan_id, bport_index;
    mlnx_port_event_t event;

    event = create ? MLNX_PORT_EVENT_ADD : MLNX_PORT_EVENT_DELETE;

    mlnx_vlan_id_foreach(vlan_id) {
        vlan_ports_count = mlnx_vlan_member_bulk_data.flood_ctrl_data.vlan_ports_count[vlan_id];
        if (vlan_ports_count > 0) {
            ports_count = 0;
            for (bport_index = 0; bport_index < MAX_BRIDGE_1Q_PORTS; bport_index++) {
                if (mlnx_vlan_member_bulk_data.flood_ctrl_data.vlan_port_present[bport_index][vlan_id]) {
                    sx_ports[ports_count] = g_sai_db_ptr->bridge_ports_db[bport_index].logical;
                    ports_count++;
                }
            }

            if (ports_count != vlan_ports_count) {
                SX_LOG_ERR("flood_ctrl_data.vlan_ports_count[%d] = %d, but ports_count = %d\n",
                           vlan_id, vlan_ports_count, ports_count);
                return SAI_STATUS_FAILURE;
            }

            status = mlnx_fid_flood_ctrl_port_event_handle(vlan_id, &mlnx_vlan_db_get_vlan(vlan_id)->flood_data,
                                                           sx_ports, ports_count, event);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_prio_tagging_state_set(uint32_t bport_index)
{
    sx_status_t              sx_status;
    sx_port_log_id_t         sx_port;
    sx_untagged_prio_state_t sx_prio_tagging_state;

    sx_prio_tagging_state = mlnx_vlan_member_bulk_data.prio_tag_data.ports[bport_index].prio_tagging;
    sx_port               = g_sai_db_ptr->bridge_ports_db[bport_index].logical;

    sx_status = sx_api_vlan_port_prio_tagged_set(gh_sdk, sx_port, sx_prio_tagging_state);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set prio tagging state to port %x - %s.\n", sx_port, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_DBG("Setting a prio tagging state a [%d] on port %x\n", sx_prio_tagging_state, sx_port);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_prio_tagging_state_apply(bool create)
{
    sai_status_t                                 status;
    const mlnx_vlan_member_prio_tag_port_data_t *ports_data;
    uint32_t                                     bport_index;

    /* We don't change port's prio taggin state when we remove vlan members */
    if (!create) {
        return SAI_STATUS_SUCCESS;
    }

    ports_data = mlnx_vlan_member_bulk_data.prio_tag_data.ports;

    for (bport_index = 0; bport_index < MAX_BRIDGE_1Q_PORTS; bport_index++) {
        if (ports_data[bport_index].is_used) {
            status = mlnx_vlan_member_bulk_prio_tagging_state_set(bport_index);
            if (SAI_ERR(status)) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_port_to_vlans_apply(_In_ uint32_t       port_index,
                                                              _Out_ sai_status_t *object_statuses,
                                                              _In_ bool           create)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    sx_status_t      sx_status;
    sx_port_log_id_t sx_port_log_id;
    sx_access_cmd_t  sx_cmd;
    sx_port_vlans_t *sx_port_vlans = NULL;
    uint32_t         vlan_id, vlan_count;
    uint32_t        *object_statuses_indexes = NULL;
    uint32_t         object_statuses_indexes_count, object_index, ii;

    object_statuses_indexes = calloc(MAX_VLANS, sizeof(uint32_t));
    if (!object_statuses_indexes) {
        SX_LOG_ERR("Failed to allocate memory for object_statuses_indexes\n");
        return SAI_STATUS_NO_MEMORY;
    }

    sx_port_vlans = calloc(MAX_VLANS, sizeof(sx_port_vlans_t));
    if (!sx_port_vlans) {
        SX_LOG_ERR("Failed to allocate memory for sx_port_vlans\n");
        free(object_statuses_indexes);
        return SAI_STATUS_NO_MEMORY;
    }

    object_statuses_indexes_count = vlan_count = 0;
    for (vlan_id = 1; vlan_id < MAX_VLANS; vlan_id++) {
        if (MLNX_VLAN_MEMBER_BULK_PAIR_IS_USED(mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id])) {
            /* Fetch the data for sx call */
            sx_port_vlans[vlan_count].vid         = vlan_id;
            sx_port_vlans[vlan_count].is_untagged = MLNX_VLAN_MEMBER_BULK_PAIR_TAGGING_GET(
                mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id]);
            vlan_count++;

            /* Update a DB */
            mlnx_vlan_member_bulk_data.vlan_ports[vlan_id]--;
            mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id].state = MLNX_VLAN_MEMBER_BULK_PAIR_STATE_NOT_USED;

            object_index = mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id].object_index;

            /*
             * We assume that sx call will success
             * But we keep a list of indexes in object_statuses so we can update the status if sx call fails
             */
            object_statuses[object_index]                          = SAI_STATUS_SUCCESS;
            object_statuses_indexes[object_statuses_indexes_count] = object_index;
            object_statuses_indexes_count++;

            mlnx_vlan_member_bulk_db_port_vlan_set(vlan_id, &g_sai_db_ptr->bridge_ports_db[port_index], create);
            mlnx_vlan_member_bulk_fdb_ctrl_set(vlan_id, port_index, true);
        }
    }

    mlnx_vlan_member_bulk_data.port_vlans[port_index] = 0;

    sx_port_log_id = g_sai_db_ptr->bridge_ports_db[port_index].logical;
    sx_cmd         = create ? SX_ACCESS_CMD_ADD : SX_ACCESS_CMD_DELETE;

    sx_status = sx_api_vlan_port_multi_vlan_set(gh_sdk, sx_cmd, sx_port_log_id, sx_port_vlans, vlan_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to add a port %x to %d VLAN%c - %s\n", sx_port_log_id, vlan_count, (vlan_count) ? 's' : ' ',
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);

        /* Update the statuses */
        for (ii = 0; ii < object_statuses_indexes_count; ii++) {
            object_index                  = object_statuses_indexes[ii];
            object_statuses[object_index] = status;
        }

        for (ii = 0; ii < vlan_count; ii++) {
            vlan_id = sx_port_vlans[ii].vid;
            mlnx_vlan_member_bulk_db_port_vlan_set(vlan_id, &g_sai_db_ptr->bridge_ports_db[port_index], !create);
            mlnx_vlan_member_bulk_fdb_ctrl_set(vlan_id, port_index, false);
        }
    }

    SX_LOG_NTC("%s port %x %d VLANs\n", SX_ACCESS_CMD_STR(sx_cmd), sx_port_log_id, vlan_count);

    free(sx_port_vlans);
    free(object_statuses_indexes);
    return status;
}

static sai_status_t mlnx_vlan_member_bulk_vlan_to_ports_apply(_In_ uint32_t       vlan_id,
                                                              _Out_ sai_status_t *object_statuses,
                                                              _In_ bool           create)
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    sai_status_t        rollback_status;
    sx_status_t         sx_status;
    sx_access_cmd_t     sx_cmd;
    sx_vlan_ports_t     sx_vlan_ports[MAX_BRIDGE_1Q_PORTS];
    mlnx_bridge_port_t *bridge_port;
    uint32_t            port_count, port_index;
    uint32_t            object_statuses_indexes[MAX_BRIDGE_1Q_PORTS];
    uint32_t            object_statuses_indexes_count, object_index, ii;

    memset(sx_vlan_ports, 0, sizeof(sx_vlan_ports));

    object_statuses_indexes_count = port_count = 0;
    for (port_index = 0; port_index < MAX_BRIDGE_1Q_PORTS; port_index++) {
        if (MLNX_VLAN_MEMBER_BULK_PAIR_IS_USED(mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id])) {
            /* Fetch the data for sx call */
            sx_vlan_ports[port_count].log_port    = g_sai_db_ptr->bridge_ports_db[port_index].logical;
            sx_vlan_ports[port_count].is_untagged =
                MLNX_VLAN_MEMBER_BULK_PAIR_TAGGING_GET(mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id]);
            port_count++;

            /* Update a DB */
            mlnx_vlan_member_bulk_data.port_vlans[port_index]--;
            mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id].state = MLNX_VLAN_MEMBER_BULK_PAIR_STATE_NOT_USED;

            object_index = mlnx_vlan_member_bulk_data.pairs[port_index][vlan_id].object_index;

            /*
             * We assume that sx call will success
             * But we keep a list of indexes in object_statuses so we can update the status if sx call fails
             */
            object_statuses[object_index]                          = SAI_STATUS_SUCCESS;
            object_statuses_indexes[object_statuses_indexes_count] = object_index;
            object_statuses_indexes_count++;

            mlnx_vlan_member_bulk_db_port_vlan_set(vlan_id, &g_sai_db_ptr->bridge_ports_db[port_index], create);
            mlnx_vlan_member_bulk_fdb_ctrl_set(vlan_id, port_index, true);
        }
    }

    mlnx_vlan_member_bulk_data.vlan_ports[vlan_id] = 0;

    sx_cmd = create ? SX_ACCESS_CMD_ADD : SX_ACCESS_CMD_DELETE;

    sx_status = sx_api_vlan_ports_set(gh_sdk, sx_cmd, DEFAULT_ETH_SWID, vlan_id, sx_vlan_ports, port_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set VLAN %d to %d port%c - %s\n", vlan_id, port_count, (port_count) ? 's' : ' ',
                   SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);

        /* Update the statuses */
        for (ii = 0; ii < object_statuses_indexes_count; ii++) {
            object_index                  = object_statuses_indexes[ii];
            object_statuses[object_index] = status;
        }

        for (ii = 0; ii < port_count; ii++) {
            rollback_status = mlnx_bridge_1q_port_by_log(sx_vlan_ports[ii].log_port, &bridge_port);
            if (SAI_ERR(rollback_status)) {
                SX_LOG_ERR("Failed to find a bridge port for rollback");
                break;
            }

            mlnx_vlan_member_bulk_db_port_vlan_set(vlan_id, bridge_port, !create);
            mlnx_vlan_member_bulk_fdb_ctrl_set(vlan_id, bridge_port->index, false);
        }
    }

    SX_LOG_NTC("%s %d ports VLAN %d\n", SX_ACCESS_CMD_STR(sx_cmd), port_count, vlan_id);

    return status;
}

static sai_status_t mlnx_vlan_member_bulk_sequence_apply(_In_ const mlnx_vlan_member_bulk_sequence_data_t *sequence,
                                                         _Out_ sai_status_t                               *object_statuses,
                                                         _In_ bool                                         create)
{
    assert(sequence);
    assert(object_statuses);

    if (sequence->is_port) {
        return mlnx_vlan_member_bulk_port_to_vlans_apply(sequence->index, object_statuses, create);
    } else {
        return mlnx_vlan_member_bulk_vlan_to_ports_apply(sequence->index, object_statuses, create);
    }
}

static sai_status_t mlnx_vlan_member_bulk_process(_Out_ sai_status_t *object_statuses,
                                                  _In_ bool           stop_on_error,
                                                  _In_ bool           create)
{
    sai_status_t                          status;
    mlnx_vlan_member_bulk_sequence_data_t sequnece;
    bool                                  more_sequences, failure;

    assert(object_statuses);

    failure = false;
    while (true) {
        more_sequences = mlnx_vlan_member_bulk_find_next_sequence(&sequnece);
        if (!more_sequences) {
            break;
        }

        status = mlnx_vlan_member_bulk_sequence_apply(&sequnece, object_statuses, create);
        if (SAI_ERR(status)) {
            failure = true;

            if (stop_on_error) {
                break;
            }
        }
    }

    status = mlnx_vlan_memeber_bulk_fdb_ctrl_apply(create);
    if (SAI_ERR(status)) {
        failure = true;
    }

    status = mlnx_vlan_member_bulk_prio_tagging_state_apply(create);
    if (SAI_ERR(status)) {
        failure = true;
    }

    return failure ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_bulk_create(_Out_ sai_status_t *object_statuses, _In_ bool stop_on_error)
{
    return mlnx_vlan_member_bulk_process(object_statuses, stop_on_error, true);
}

static sai_status_t mlnx_vlan_member_bulk_remove(_Out_ sai_status_t *object_statuses, _In_ bool stop_on_error)
{
    return mlnx_vlan_member_bulk_process(object_statuses, stop_on_error, false);
}

static sai_status_t mlnx_vlan_member_bulk_create_statuses_print(_In_ const sai_status_t *object_statuses,
                                                                _In_ uint32_t            object_count)
{
    return mlnx_bulk_statuses_print("VLAN Members", object_statuses, object_count, SAI_COMMON_API_BULK_CREATE);
}

static sai_status_t mlnx_vlan_member_bulk_remove_statuses_print(_In_ const sai_status_t *object_statuses,
                                                                _In_ uint32_t            object_count)
{
    return mlnx_bulk_statuses_print("VLAN Members", object_statuses, object_count, SAI_COMMON_API_BULK_REMOVE);
}

/**
 * @brief Bulk vlan members creation.
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
sai_status_t mlnx_create_vlan_members(_In_ sai_object_id_t          switch_id,
                                      _In_ uint32_t                 object_count,
                                      _In_ const uint32_t          *attr_count,
                                      _In_ const sai_attribute_t  **attr_list,
                                      _In_ sai_bulk_op_error_mode_t mode,
                                      _Out_ sai_object_id_t        *object_id,
                                      _Out_ sai_status_t           *object_statuses)
{
    sai_status_t            status;
    mlnx_vlan_member_data_t vlan_member_data;
    uint32_t                ii;
    bool                    stop_on_error, failure;

    SX_LOG_ENTER();

    status =
        mlnx_bulk_create_attrs_validate(object_count, attr_count, attr_list, mode, object_statuses, &stop_on_error);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (!object_id) {
        SX_LOG_ERR("object_id is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();

    mlnx_vlan_member_bulk_init();

    failure = false;
    for (ii = 0; ii < object_count; ii++) {
        status = mlnx_vlan_member_bulk_attrs_parse(attr_list[ii], attr_count[ii], &vlan_member_data);
        if (!SAI_ERR(status)) {
            status = mlnx_vlan_member_bulk_pair_add(&vlan_member_data, ii);
        }

        object_id[ii]       = vlan_member_data.oid;
        object_statuses[ii] = SAI_ERR(status) ? status : SAI_STATUS_NOT_EXECUTED;

        if (SAI_ERR(status)) {
            failure = true;
        }

        if (SAI_ERR(status) && stop_on_error) {
            break;
        }
    }

    if (SAI_ERR(status) && stop_on_error) {
        for (ii++; ii < object_count; ii++) {
            object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        }
    }

    status = mlnx_vlan_member_bulk_create(object_statuses, stop_on_error);
    if (SAI_ERR(status)) {
        failure = true;
        goto out;
    }

out:
    sai_db_unlock();

    mlnx_vlan_member_bulk_create_statuses_print(object_statuses, object_count);
    SX_LOG_EXIT();
    return failure ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
}

/**
 * @brief Bulk vlan members removal.
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
sai_status_t mlnx_remove_vlan_members(_In_ uint32_t                 object_count,
                                      _In_ const sai_object_id_t   *object_id,
                                      _In_ sai_bulk_op_error_mode_t mode,
                                      _Out_ sai_status_t           *object_statuses)
{
    sai_status_t            status;
    mlnx_vlan_member_data_t vlan_member_data;
    uint32_t                ii;
    bool                    stop_on_error, failure;

    SX_LOG_ENTER();

    status = mlnx_bulk_remove_attrs_validate(object_count, mode, object_statuses, &stop_on_error);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (!object_id) {
        SX_LOG_ERR("object_id is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();

    mlnx_vlan_member_bulk_init();

    failure = false;
    for (ii = 0; ii < object_count; ii++) {
        status = mlnx_vlan_member_bulk_oid_to_data(object_id[ii], &vlan_member_data);
        if (!SAI_ERR(status)) {
            status = mlnx_vlan_member_bulk_pair_add(&vlan_member_data, ii);
        }

        object_statuses[ii] = SAI_ERR(status) ? status : SAI_STATUS_NOT_EXECUTED;

        if (SAI_ERR(status)) {
            failure = true;
        }

        if (SAI_ERR(status) && stop_on_error) {
            break;
        }
    }

    if (SAI_ERR(status) && stop_on_error) {
        for (ii++; ii < object_count; ii++) {
            object_statuses[ii] = SAI_STATUS_NOT_EXECUTED;
        }
    }

    status = mlnx_vlan_member_bulk_remove(object_statuses, stop_on_error);
    if (SAI_ERR(status)) {
        failure = true;
        goto out;
    }

out:
    sai_db_unlock();

    mlnx_vlan_member_bulk_remove_statuses_print(object_statuses, object_count);
    SX_LOG_EXIT();
    return failure ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
}

/*
 *  \brief Set VLAN Member Attribute
 *  \param[in] vlan_member_id VLAN member ID
 *  \param[in] attr attribute structure containing ID and value
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_set_vlan_member_attribute(_In_ sai_object_id_t        vlan_member_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_vendor_attribs, attr);
}

/*
 *  \brief Get VLAN Member Attribute
 *  \param[in] vlan_member_id VLAN member ID
 *  \param[in] attr_count number of attributes
 *  \param[in,out] attr_list list of attribute structures containing ID and value
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_get_vlan_member_attribute(_In_ sai_object_id_t     vlan_member_id,
                                                   _In_ const uint32_t      attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_VLAN_MEMBER,
                              vlan_member_vendor_attribs,
                              attr_count,
                              attr_list);
}

/* VLAN ID [sai_vlan_t] */
/* logical port ID [sai_object_id_t] */
/* VLAN tagging mode [sai_vlan_tagging_mode_t] */
static sai_status_t mlnx_vlan_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    mlnx_bridge_port_t *port;
    mlnx_object_id_t    vlan_obj_id;
    uint16_t            vlan_id;
    sx_status_t         status;

    SX_LOG_ENTER();

    memset(&vlan_obj_id, 0, sizeof(vlan_obj_id));

    assert((SAI_VLAN_MEMBER_ATTR_VLAN_ID == (long)arg) ||
           (SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID == (long)arg));

    status = mlnx_vlan_member_oid_to_vlan_port(key->key.object_id, &vlan_id, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    switch ((long)arg) {
    case SAI_VLAN_MEMBER_ATTR_VLAN_ID:
        vlan_obj_id.id.vlan_id = vlan_id;

        status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID:
        status = mlnx_bridge_port_to_oid(port, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* VLAN tagging mode [sai_vlan_tagging_mode_t] */
static sai_status_t mlnx_vlan_member_tagging_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sx_status_t              sx_status;
    mlnx_bridge_port_t      *port;
    sai_status_t             status;
    sx_vlan_ports_t          sx_vlan_port_list;
    sx_untagged_prio_state_t sx_prio_tagging;
    uint16_t                 vlan;

    SX_LOG_ENTER();

    memset(&sx_vlan_port_list, 0, sizeof(sx_vlan_port_list));

    status = mlnx_vlan_member_oid_to_vlan_port(key->key.object_id, &vlan, &port);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_vlan_sai_tagging_to_sx(value->s32, &sx_vlan_port_list.is_untagged, &sx_prio_tagging);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_vlan_port_list.log_port = port->logical;

    if (SX_STATUS_SUCCESS !=
        (sx_status =
             sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, vlan, &sx_vlan_port_list, 1))) {
        SX_LOG_ERR("Failed to delete vlan ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status =
             sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vlan, &sx_vlan_port_list, 1))) {
        SX_LOG_ERR("Failed to delete vlan ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_vlan_port_prio_tagged_set(gh_sdk, port->logical, sx_prio_tagging);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set prio tagging state to port %x - %s.\n", port->logical, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_tagging_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t               status;
    sx_status_t                sx_status;
    sx_untagged_prio_state_t   sx_prio_tagging_state;
    sx_untagged_member_state_t sx_tagging_mode;
    mlnx_bridge_port_t        *port;
    uint16_t                   vlan;

    SX_LOG_ENTER();

    status = mlnx_vlan_member_oid_to_vlan_port(key->key.object_id, &vlan, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    sx_status = sx_api_vlan_port_prio_tagged_get(gh_sdk, port->logical, &sx_prio_tagging_state);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get prio tagging state for port %x - %s.\n", port->logical, SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    if (sx_prio_tagging_state == SX_PRIO_TAGGED_STATE) {
        value->s32 = SAI_VLAN_TAGGING_MODE_PRIORITY_TAGGED;
        status     = SAI_STATUS_SUCCESS;
        goto out;
    }

    status = mlnx_vlan_log_port_tagging_get(port->logical, vlan, &sx_tagging_mode);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->s32 = (sx_tagging_mode == SX_TAGGED_MEMBER) ? SAI_VLAN_TAGGING_MODE_TAGGED : SAI_VLAN_TAGGING_MODE_UNTAGGED;

out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_vlan_log_port_tagging_get(_In_ sx_port_log_id_t             sx_port_id,
                                            _In_ sx_vlan_id_t                 sx_vlan_id,
                                            _Out_ sx_untagged_member_state_t *sx_tagging_mode)
{
    sx_status_t     sx_status;
    sx_vlan_ports_t sx_vlan_port_list[MAX_BRIDGE_1Q_PORTS];
    uint32_t        vlan_ports_count = MAX_BRIDGE_1Q_PORTS, ii;

    assert(sx_tagging_mode);

    memset(sx_vlan_port_list, 0, sizeof(sx_vlan_port_list));

    sx_status = sx_api_vlan_ports_get(gh_sdk, DEFAULT_ETH_SWID, sx_vlan_id, sx_vlan_port_list, &vlan_ports_count);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get vlan members for vlan %d - %s\n", sx_vlan_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    for (ii = 0; ii < vlan_ports_count; ii++) {
        if (sx_vlan_port_list[ii].log_port == sx_port_id) {
            *sx_tagging_mode = sx_vlan_port_list[ii].is_untagged;
            break;
        }
    }

    if (ii == vlan_ports_count) {
        SX_LOG_ERR("Failed to find port %x in vlan %u, %u members\n", sx_port_id, sx_vlan_id, vlan_ports_count);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_list_stp_bind(_In_ const sx_vlan_id_t *vlan_ids,
                                     _In_ uint32_t            vlan_count,
                                     _In_ sx_mstp_inst_id_t   sx_stp_id)
{
    sx_status_t       sx_status;
    mlnx_mstp_inst_t *stp_db_entry;
    uint32_t          ii;

    assert(vlan_ids);

    if (vlan_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (mlnx_stp_is_initialized()) {
        sx_status = sx_api_mstp_inst_vlan_list_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                                   sx_stp_id, vlan_ids, vlan_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set STP to vlan %s.\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    stp_db_entry = get_stp_db_entry(sx_stp_id);


    for (ii = 0; ii < vlan_count; ii++) {
        /* Checking to avoid adding the same reference twice */
        if (mlnx_vlan_stp_id_get(vlan_ids[ii]) != sx_stp_id) {
            mlnx_vlan_stp_id_set(vlan_ids[ii], sx_stp_id);
            stp_db_entry->vlan_count += 1;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_stp_bind(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id)
{
    return mlnx_vlan_list_stp_bind(&vlan_id, 1, sx_stp_id);
}

sai_status_t mlnx_vlan_stp_unbind(sai_vlan_id_t vlan_id)
{
    sx_status_t       status;
    sx_mstp_inst_id_t sx_stp_id_curr;
    mlnx_mstp_inst_t *stp_db_entry;

    SX_LOG_ENTER();

    sx_stp_id_curr = mlnx_vlan_stp_id_get(vlan_id);

    if (mlnx_stp_is_initialized()) {
        SX_LOG_DBG("Unmapping VLAN [%u] from STP [%u]\n", vlan_id, sx_stp_id_curr);
        status = sx_api_mstp_inst_vlan_list_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                                sx_stp_id_curr, &vlan_id, 1);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to unmap VLAN [%u] from STP [%u]\n", vlan_id, sx_stp_id_curr);
            return sdk_to_sai(status);
        }
    }

    SX_LOG_DBG("Passed an SDK api (vlan_list_set)\n");
    /* Remove map VLAN:STP from database */
    mlnx_vlan_stp_id_set(vlan_id, SAI_INVALID_STP_INSTANCE);

    /* Decrement VLAN counter for that STP id */
    stp_db_entry = get_stp_db_entry(sx_stp_id_curr);
    if (stp_db_entry->vlan_count != 0) {
        (stp_db_entry->vlan_count)--;
    }
    SX_LOG_DBG("Decrement VLAN count (to %u) for STP=%u\n",
               stp_db_entry->vlan_count, sx_stp_id_curr);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_object_to_vlan(sai_object_id_t oid, uint16_t *vlan_id)
{
    mlnx_object_id_t vlan_obj_id;
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_VLAN, oid, &vlan_obj_id);
    if (SAI_ERR(status)) {
        return status;
    }
    if (vlan_obj_id.object_type != SAI_OBJECT_TYPE_VLAN) {
        SX_LOG_ERR("Invalid object type %u - must be %u\n",
                   vlan_obj_id.object_type, SAI_OBJECT_TYPE_VLAN);

        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    status = validate_vlan(vlan_obj_id.id.vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    *vlan_id = vlan_obj_id.id.vlan_id;
    return SAI_STATUS_SUCCESS;
}

sai_status_t validate_vlan(_In_ const sai_vlan_id_t vlan_id)
{
    SX_LOG_ENTER();

    if (!SXD_VID_CHECK_RANGE(vlan_id)) {
        SX_LOG_ERR("Invalid VLAN number: should be within a range [%u - %u]\n",
                   SXD_VID_MIN, SXD_VID_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_oid_create(_In_ sai_vlan_id_t vlan_id, _Out_ sai_object_id_t *vlan_oid)
{
    sai_status_t     status;
    mlnx_object_id_t vlan_obj_id;

    assert(vlan_oid);

    memset(&vlan_obj_id, 0, sizeof(vlan_obj_id));
    vlan_obj_id.id.vlan_id = vlan_id;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, vlan_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sx_mstp_inst_id_t mlnx_vlan_stp_id_get(sai_vlan_id_t vlan_id)
{
    return (g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].stp_id);
}

void mlnx_vlan_stp_id_set(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id)
{
    g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].stp_id = sx_stp_id;
}

mlnx_vlan_db_t* mlnx_vlan_db_get_vlan(_In_ sai_vlan_id_t vlan_id)
{
    return &g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN];
}

mlnx_vlan_db_t* mlnx_vlan_db_create_vlan(_In_ sai_vlan_id_t vlan_id)
{
    mlnx_vlan_db_t *vlan_db = mlnx_vlan_db_get_vlan(vlan_id);

    vlan_db->is_created = true;

    mlnx_fid_flood_ctrl_init(&vlan_db->flood_data);

    return vlan_db;
}

static void mlnx_vlan_db_remove_vlan(_In_ sai_vlan_id_t vlan_id)
{
    g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].is_created = false;
}

bool mlnx_vlan_is_created(_In_ sai_vlan_id_t vlan_id)
{
    return g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].is_created;
}

static sai_status_t mlnx_vlans_ports_get(_In_ sai_vlan_id_t      vlan_id,
                                         _Out_ sx_port_log_id_t *sx_ports,
                                         _Inout_ uint32_t       *ports_count)
{
    const mlnx_bridge_port_t *bport;
    uint32_t                  ii, count = 0;

    assert(sx_ports);
    assert(ports_count);
    assert(SAI_STATUS_SUCCESS == validate_vlan(vlan_id));

    mlnx_vlan_ports_foreach(vlan_id, bport, ii) {
        if (*ports_count < count) {
            SX_LOG_ERR("Insufficient buffer size %u\n", *ports_count);
            return SAI_STATUS_BUFFER_OVERFLOW;
        }

        sx_ports[count++] = bport->logical;
    }

    *ports_count = count;

    return SAI_STATUS_SUCCESS;
}

static mlnx_fid_flood_ctrl_type_t mlnx_vlan_flood_type_to_fid_type(_In_ sai_vlan_flood_control_type_t type)
{
    assert(type <= SAI_VLAN_FLOOD_CONTROL_TYPE_L2MC_GROUP);

    return (mlnx_fid_flood_ctrl_type_t)(type);
}

static mlnx_fid_flood_ctrl_attr_t mlnx_vlan_flood_ctrl_attr_to_fid_attr(_In_ sai_vlan_attr_t attr)
{
    switch (attr) {
    case SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE:
        return MLNX_FID_FLOOD_CTRL_ATTR_UC;

    case SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE:
        return MLNX_FID_FLOOD_CTRL_ATTR_MC;

    case SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE:
        return MLNX_FID_FLOOD_CTRL_ATTR_BC;

    default:
        SX_LOG_ERR("Unexpected flood ctrl attr - %d\n", attr);
        assert(false);
        return MLNX_FID_FLOOD_CTRL_ATTR_MAX;
    }
}

static mlnx_fid_flood_ctrl_attr_t mlnx_vlan_flood_ctrl_group_attr_to_fid_attr(_In_ sai_vlan_attr_t attr)
{
    switch (attr) {
    case SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP:
        return MLNX_FID_FLOOD_CTRL_ATTR_UC;

    case SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP:
        return MLNX_FID_FLOOD_CTRL_ATTR_MC;

    case SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP:
        return MLNX_FID_FLOOD_CTRL_ATTR_BC;

    default:
        SX_LOG_ERR("Unexpected flood ctrl group  attr - %d\n", attr);
        assert(false);
        return MLNX_FID_FLOOD_CTRL_ATTR_MAX;
    }
}

static sai_vlan_flood_control_type_t mlnx_fid_flood_type_to_vlan_type(_In_ mlnx_fid_flood_ctrl_type_t type)
{
    assert(type <= MLNX_FID_FLOOD_TYPE_L2MC_GROUP);

    return (sai_vlan_flood_control_type_t)(type);
}

void mlnx_fid_flood_ctrl_init(_In_ mlnx_fid_flood_data_t *data)
{
    assert(data);

    data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC] = MLNX_FID_FLOOD_CTRL_DATA_DEFAULT;
    data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC] = MLNX_FID_FLOOD_CTRL_DATA_DEFAULT;
    data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC] = MLNX_FID_FLOOD_CTRL_DATA_DEFAULT;
}

void mlnx_fid_flood_ctrl_l2mc_group_refs_inc(_In_ const mlnx_fid_flood_data_t *data)
{
    assert(data);

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_inc(data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC].l2mc_db_idx);
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_inc(data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC].l2mc_db_idx);
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_inc(data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC].l2mc_db_idx);
    }
}

void mlnx_fid_flood_ctrl_l2mc_group_refs_dec(_In_ const mlnx_fid_flood_data_t *data)
{
    assert(data);

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_dec(data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC].l2mc_db_idx);
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_dec(data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC].l2mc_db_idx);
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC].l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_dec(data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC].l2mc_db_idx);
    }
}

static sai_status_t mlnx_fid_uc_bc_flood_ctrl_apply(_In_ sx_fid_t                          sx_fid,
                                                    _In_ sx_flood_control_type_t           sx_flood_type,
                                                    _In_ const sx_port_log_id_t           *sx_fid_ports,
                                                    _In_ uint32_t                          fid_ports_count,
                                                    _In_ const mlnx_fid_flood_type_data_t *data)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t sx_l2mc_ports[MAX_BRIDGE_1Q_PORTS] = {0}, ports_to_block[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         l2mc_ports_count                   = MAX_BRIDGE_1Q_PORTS, ports_to_block_count, ii, jj;
    bool             block_port;

    assert(sx_fid_ports);
    assert(data);
    assert(data->type <= MLNX_FID_FLOOD_TYPE_L2MC_GROUP);

    if (data->type == MLNX_FID_FLOOD_TYPE_ALL) {
        sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_DELETE_ALL_PORTS,
                                                 DEFAULT_ETH_SWID, sx_fid, sx_flood_type,
                                                 0, NULL);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete fdb flood list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        SX_LOG_DBG("Deleted all the ports for fid %u flood control (%s)\n", sx_fid, "MLNX_FID_FLOOD_TYPE_ALL");
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_NONE) {
        if (fid_ports_count > 0) {
            sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_ADD_PORTS,
                                                     DEFAULT_ETH_SWID, sx_fid, sx_flood_type,
                                                     fid_ports_count, sx_fid_ports);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to add ports to fdb flood list for fid %u - %s.\n", sx_fid,
                           SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }

        SX_LOG_DBG("added %u ports (first %x) for fid %u flood control (%s)\n", fid_ports_count, sx_fid_ports[0],
                   sx_fid, "MLNX_FID_FLOOD_TYPE_NONE");
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) {
        if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->l2mc_db_idx)) {
            status = mlnx_l2mc_group_sx_ports_get(&l2mc_group_db(data->l2mc_db_idx), sx_l2mc_ports, &l2mc_ports_count);
            if (SAI_ERR(status)) {
                return status;
            }
        } else {
            SX_LOG_DBG("Flood control type is L2 MC group but group oid is not specified yet\n");
            l2mc_ports_count = 0;
        }

        ports_to_block_count = 0;
        /* block a port if it's not present in L2MC group */
        for (ii = 0; ii < fid_ports_count; ii++) {
            block_port = true;
            for (jj = 0; jj < l2mc_ports_count; jj++) {
                if (sx_l2mc_ports[jj] == sx_fid_ports[ii]) {
                    block_port = false;
                    break;
                }
            }

            if (block_port) {
                ports_to_block[ports_to_block_count] = sx_fid_ports[ii];
                ports_to_block_count++;
            }
        }

        SX_LOG_DBG("adding %u ports (first %x) to fid %u flood control (%s)\n",
                   ports_to_block_count,
                   ports_to_block[0],
                   sx_fid,
                   "MLNX_FID_FLOOD_TYPE_L2MC_GROUP");

        if (ports_to_block_count > 0) {
            sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_ADD_PORTS,
                                                     DEFAULT_ETH_SWID, sx_fid, sx_flood_type,
                                                     ports_to_block_count, ports_to_block);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to add ports to fdb flood list for fid %u - %s.\n", sx_fid,
                           SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fid_mc_flood_ctrl_apply(_In_ sx_fid_t                          sx_fid,
                                                 _In_ const sx_port_log_id_t           *sx_fid_ports,
                                                 _In_ uint32_t                          fid_ports_count,
                                                 _In_ const mlnx_fid_flood_type_data_t *data)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t sx_l2mc_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         l2mc_ports_count                   = MAX_BRIDGE_1Q_PORTS;

    assert(sx_fid_ports);
    assert(data);
    assert(data->type <= MLNX_FID_FLOOD_TYPE_L2MC_GROUP);

    if (data->type == MLNX_FID_FLOOD_TYPE_ALL) {
        sx_status = sx_api_fdb_unreg_mc_flood_mode_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, SX_FDB_UNREG_MC_FLOOD);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set fdb unreg mc flood mode for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status =
            sx_api_fdb_unreg_mc_flood_ports_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, sx_fid_ports, fid_ports_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set fdb unreg mc flood port list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(
                           sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_NONE) {
        sx_status = sx_api_fdb_unreg_mc_flood_mode_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, SX_FDB_UNREG_MC_PRUNE);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set fdb unreg mc flood mode for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_fdb_unreg_mc_flood_ports_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, NULL, 0);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to clear fdb unreg mc flood port list for fid %u - %s.\n", sx_fid,
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) {
        if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->l2mc_db_idx)) {
            status = mlnx_l2mc_group_sx_ports_get(&l2mc_group_db(data->l2mc_db_idx), sx_l2mc_ports, &l2mc_ports_count);
            if (SAI_ERR(status)) {
                return status;
            }
        } else {
            SX_LOG_DBG("Flood control type is L2 MC group but group oid is not specified yet\n");
            l2mc_ports_count = 0;
        }

        sx_status = sx_api_fdb_unreg_mc_flood_mode_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, SX_FDB_UNREG_MC_PRUNE);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set fdb unreg mc flood mode for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        sx_status = sx_api_fdb_unreg_mc_flood_ports_set(gh_sdk,
                                                        DEFAULT_ETH_SWID,
                                                        sx_fid,
                                                        sx_l2mc_ports,
                                                        l2mc_ports_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set fdb unreg mc flood port list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(
                           sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fid_flood_ctrl_update_prepare(_In_ sx_fid_t                          sx_fid,
                                                       _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                                       _In_ mlnx_fid_flood_ctrl_type_t        prev_type,
                                                       _In_ const mlnx_fid_flood_type_data_t *data)
{
    sx_status_t             sx_status;
    sx_flood_control_type_t sx_flood_control_type;

    assert(data);

    /* no need to clean ports since sx_api_fdb_unreg_mc_flood_ports_set resets it */
    if (attr == MLNX_FID_FLOOD_CTRL_ATTR_MC) {
        return SAI_STATUS_SUCCESS;
    }

    if ((prev_type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) || (data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP)) {
        SX_LOG_NTC("Deleting all the ports from fid %u flood control\n", sx_fid);

        sx_flood_control_type = (attr == MLNX_FID_FLOOD_CTRL_ATTR_UC) ? SX_FLOOD_CONTROL_TYPE_UNICAST_E :
                                SX_FLOOD_CONTROL_TYPE_BROADCAST_E;
        sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_DELETE_ALL_PORTS, DEFAULT_ETH_SWID, sx_fid,
                                                 sx_flood_control_type, 0, NULL);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete fdb flood list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static bool mlnx_fid_flood_ctrl_attr_is_fid_ports_needed(_In_ mlnx_fid_flood_ctrl_attr_t attr,
                                                         _In_ mlnx_fid_flood_ctrl_type_t type)
{
    assert(attr < MLNX_FID_FLOOD_CTRL_ATTR_MAX);
    assert(type < MLNX_FID_FLOOD_TYPE_MAX);

    if (((type == MLNX_FID_FLOOD_TYPE_NONE) || (type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP)) &&
        ((attr == MLNX_FID_FLOOD_CTRL_ATTR_UC) || (attr == MLNX_FID_FLOOD_CTRL_ATTR_BC))) {
        return true;
    }

    if ((type == MLNX_FID_FLOOD_TYPE_ALL) && (attr == MLNX_FID_FLOOD_CTRL_ATTR_MC)) {
        return true;
    }

    return false;
}

sai_status_t mlnx_fid_ports_get(_In_ sx_fid_t           sx_fid,
                                _Out_ sx_port_log_id_t *sx_ports,
                                _Inout_ uint32_t       *ports_count)
{
    if (sx_fid < MIN_SX_BRIDGE_ID) {
        return mlnx_vlans_ports_get(sx_fid, sx_ports, ports_count);
    } else {
        return mlnx_bridge_sx_ports_get(sx_fid, sx_ports, ports_count);
    }
}

static sai_status_t mlnx_fid_flood_ctrl_type_data_apply(_In_ sx_fid_t                          sx_fid,
                                                        _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                                        _In_ const mlnx_fid_flood_type_data_t *flood_data)
{
    sai_status_t     status;
    sx_port_log_id_t fid_ports[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         ports_count                    = 0;

    if (mlnx_fid_flood_ctrl_attr_is_fid_ports_needed(attr, flood_data->type)) {
        ports_count = MAX_BRIDGE_1Q_PORTS;
        status      = mlnx_fid_ports_get(sx_fid, fid_ports, &ports_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get fid %u ports\n", sx_fid);
            return status;
        }
    }

    switch (attr) {
    case MLNX_FID_FLOOD_CTRL_ATTR_UC:
        status = mlnx_fid_uc_bc_flood_ctrl_apply(sx_fid, SX_FLOOD_CONTROL_TYPE_UNICAST_E,
                                                 fid_ports, ports_count, flood_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update unknown uc flood control for VLAN %d\n", sx_fid);
            return status;
        }
        break;

    case MLNX_FID_FLOOD_CTRL_ATTR_BC:
        status = mlnx_fid_uc_bc_flood_ctrl_apply(sx_fid, SX_FLOOD_CONTROL_TYPE_BROADCAST_E,
                                                 fid_ports, ports_count, flood_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update broadcast flood control for VLAN %d\n", sx_fid);
            return status;
        }
        break;

    case MLNX_FID_FLOOD_CTRL_ATTR_MC:
        status = mlnx_fid_mc_flood_ctrl_apply(sx_fid, fid_ports, ports_count, flood_data);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update unknown mc flood control for VLAN %d\n", sx_fid);
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unexpected flood attribute - %d\n", attr);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fid_flood_ctrl_update(_In_ sx_fid_t                          sx_fid,
                                               _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                               _In_ mlnx_fid_flood_ctrl_type_t        prev_type,
                                               _In_ const mlnx_fid_flood_type_data_t *flood_data)
{
    sai_status_t status;

    status = mlnx_fid_flood_ctrl_update_prepare(sx_fid, attr, prev_type, flood_data);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_fid_flood_ctrl_type_data_apply(sx_fid, attr, flood_data);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fid_flood_ctrl_set_forward_after_drop(_In_ sx_fid_t                          sx_fid,
                                                        _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                                        _In_ const mlnx_fid_flood_type_data_t *flood_data)
{
    assert(attr < MLNX_FID_FLOOD_CTRL_ATTR_MAX);
    assert(flood_data);

    return mlnx_fid_flood_ctrl_update(sx_fid, attr, MLNX_FID_FLOOD_TYPE_NONE, flood_data);
}

sai_status_t mlnx_fid_flood_ctrl_set_drop(_In_ sx_fid_t                          sx_fid,
                                          _In_ mlnx_fid_flood_ctrl_attr_t        attr,
                                          _In_ const mlnx_fid_flood_type_data_t *flood_data)
{
    mlnx_fid_flood_type_data_t drop;

    assert(attr < MLNX_FID_FLOOD_CTRL_ATTR_MAX);
    assert(flood_data);

    drop.type        = MLNX_FID_FLOOD_TYPE_NONE;
    drop.l2mc_db_idx = MLNX_L2MC_GROUP_DB_IDX_INVALID;

    return mlnx_fid_flood_ctrl_update(sx_fid, attr, flood_data->type, &drop);
}

sai_status_t mlnx_fid_flood_ctrl_type_set(_In_ sx_fid_t                       sx_fid,
                                          _In_ mlnx_fid_flood_ctrl_attr_t     attr,
                                          _Inout_ mlnx_fid_flood_type_data_t *data,
                                          _In_ mlnx_fid_flood_ctrl_type_t     new_type)
{
    sx_status_t                status;
    mlnx_fid_flood_ctrl_type_t prev_type;

    if (new_type == data->type) {
        return SAI_STATUS_SUCCESS;
    }

    prev_type  = data->type;
    data->type = new_type;

    if (g_sai_db_ptr->flood_actions[attr] == SAI_PACKET_ACTION_DROP) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_fid_flood_ctrl_update(sx_fid, attr, prev_type, data);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fid_flood_ctrl_uc_bc_port_event_handle(_In_ sx_fid_t                          sx_fid,
                                                                _In_ sx_flood_control_type_t           sx_flood_type,
                                                                _In_ const mlnx_fid_flood_type_data_t *data,
                                                                _In_ const sx_port_log_id_t           *sx_ports,
                                                                _In_ uint32_t                          sx_ports_count,
                                                                _In_ mlnx_port_event_t                 event)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_access_cmd_t  sx_cmd;
    sx_port_log_id_t sx_l2mc_ports[MAX_BRIDGE_1Q_PORTS] = {0}, ports_to_update[MAX_BRIDGE_1Q_PORTS] = {0};
    uint32_t         l2mc_ports_count                   = MAX_BRIDGE_1Q_PORTS, ports_to_update_count, ii, jj;
    bool             block_port;

    assert(data);
    assert(sx_ports);

    if (data->type == MLNX_FID_FLOOD_TYPE_ALL) {
        /* flood control list is empty, default is 'ALL' */
        return SAI_STATUS_SUCCESS;
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_NONE) {
        sx_cmd    = (event == MLNX_PORT_EVENT_ADD) ? SX_ACCESS_CMD_ADD_PORTS : SX_ACCESS_CMD_DELETE_PORTS;
        sx_status = sx_api_fdb_flood_control_set(gh_sdk, sx_cmd, DEFAULT_ETH_SWID, sx_fid, sx_flood_type,
                                                 sx_ports_count, sx_ports);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add ports to fid %u flood control - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }

        SX_LOG_DBG("%s %u ports (first %x) for fid %u flood control (%s)\n", SX_ACCESS_CMD_STR(sx_cmd),
                   sx_ports_count, sx_ports[0], sx_fid, "MLNX_FID_FLOOD_TYPE_NONE event");
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) {
        if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->l2mc_db_idx)) {
            status = mlnx_l2mc_group_sx_ports_get(&l2mc_group_db(data->l2mc_db_idx), sx_l2mc_ports, &l2mc_ports_count);
            if (SAI_ERR(status)) {
                return status;
            }
        } else {
            SX_LOG_DBG("Flood control type is L2 MC group but group oid is not specified yet\n");
            l2mc_ports_count = 0;
        }

        /* update the ports that are not present in L2MC group */
        ports_to_update_count = 0;
        for (ii = 0; ii < sx_ports_count; ii++) {
            block_port = true;
            for (jj = 0; jj < l2mc_ports_count; jj++) {
                if (sx_l2mc_ports[jj] == sx_ports[ii]) {
                    block_port = false;
                    break;
                }
            }

            if (block_port) {
                ports_to_update[ports_to_update_count] = sx_ports[ii];
                ports_to_update_count++;
            }
        }

        sx_cmd = (event == MLNX_PORT_EVENT_ADD) ? SX_ACCESS_CMD_ADD_PORTS : SX_ACCESS_CMD_DELETE_PORTS;

        SX_LOG_DBG("%s %u ports (first %x) for fid %u flood control (%s)\n", SX_ACCESS_CMD_STR(sx_cmd),
                   ports_to_update_count, ports_to_update[0], sx_fid, "MLNX_FID_FLOOD_TYPE_L2MC_GROUP event");

        if (ports_to_update_count > 0) {
            sx_status = sx_api_fdb_flood_control_set(gh_sdk, sx_cmd,
                                                     DEFAULT_ETH_SWID, sx_fid, sx_flood_type,
                                                     ports_to_update_count, ports_to_update);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to add fdb flood list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fid_flood_ctrl_mc_port_event_handle(_In_ sx_fid_t                          sx_fid,
                                                             _In_ const mlnx_fid_flood_type_data_t *data,
                                                             _In_ const sx_port_log_id_t           *sx_ports,
                                                             _In_ uint32_t                          sx_port_count,
                                                             _In_ mlnx_port_event_t                 event)
{
    assert(data);
    assert(sx_ports);

    if ((data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) ||
        (data->type == MLNX_FID_FLOOD_TYPE_NONE)) {
        return SAI_STATUS_SUCCESS;
    }

    /* For MLNX_FID_FLOOD_TYPE_ALL we reapply a config.
     * It will fetch all the fid's ports (including/excluding a new ones from event)
     */
    return mlnx_fid_flood_ctrl_type_data_apply(sx_fid, MLNX_FID_FLOOD_CTRL_ATTR_MC, data);
}

sai_status_t mlnx_fid_flood_ctrl_port_event_handle(_In_ sx_fid_t                     sx_fid,
                                                   _In_ const mlnx_fid_flood_data_t *data,
                                                   _In_ const sx_port_log_id_t      *sx_ports,
                                                   _In_ uint32_t                     sx_port_count,
                                                   _In_ mlnx_port_event_t            event)
{
    sai_status_t                      status;
    const mlnx_fid_flood_type_data_t *data_to_apply;
    mlnx_fid_flood_type_data_t        drop_data;
    sai_packet_action_t               switch_action;

    assert((event == MLNX_PORT_EVENT_ADD) || (event == MLNX_PORT_EVENT_DELETE));
    assert(data);
    assert(sx_ports);

    drop_data.type        = MLNX_FID_FLOOD_TYPE_NONE;
    drop_data.l2mc_db_idx = MLNX_L2MC_GROUP_DB_IDX_INVALID;

    switch_action = g_sai_db_ptr->flood_actions[MLNX_FID_FLOOD_CTRL_ATTR_UC];
    if (switch_action == SAI_PACKET_ACTION_DROP) {
        data_to_apply = &drop_data;
    } else {
        data_to_apply = &data->types[MLNX_FID_FLOOD_CTRL_ATTR_UC];
    }

    status = mlnx_fid_flood_ctrl_uc_bc_port_event_handle(sx_fid, SX_FLOOD_CONTROL_TYPE_UNICAST_E,
                                                         data_to_apply, sx_ports, sx_port_count, event);
    if (SAI_ERR(status)) {
        return status;
    }

    switch_action = g_sai_db_ptr->flood_actions[MLNX_FID_FLOOD_CTRL_ATTR_BC];
    if (switch_action == SAI_PACKET_ACTION_DROP) {
        data_to_apply = &drop_data;
    } else {
        data_to_apply = &data->types[MLNX_FID_FLOOD_CTRL_ATTR_BC];
    }

    status = mlnx_fid_flood_ctrl_uc_bc_port_event_handle(sx_fid, SX_FLOOD_CONTROL_TYPE_BROADCAST_E,
                                                         data_to_apply, sx_ports, sx_port_count, event);
    if (SAI_ERR(status)) {
        return status;
    }

    switch_action = g_sai_db_ptr->flood_actions[MLNX_FID_FLOOD_CTRL_ATTR_MC];
    if (switch_action == SAI_PACKET_ACTION_DROP) {
        data_to_apply = &drop_data;
    } else {
        data_to_apply = &data->types[MLNX_FID_FLOOD_CTRL_ATTR_MC];
    }

    status = mlnx_fid_flood_ctrl_mc_port_event_handle(sx_fid, data_to_apply, sx_ports, sx_port_count, event);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fid_flood_ctrl_l2mc_group_set(_In_ sx_fid_t                       sx_fid,
                                                _In_ mlnx_fid_flood_ctrl_attr_t     attr,
                                                _Inout_ mlnx_fid_flood_type_data_t *data,
                                                _In_ sai_object_id_t                group_oid)
{
    sai_status_t status;
    uint32_t     new_l2mc_group_idx;

    assert(data);

    if (group_oid == SAI_NULL_OBJECT_ID) {
        new_l2mc_group_idx = MLNX_L2MC_GROUP_DB_IDX_INVALID;
    } else {
        status = mlnx_l2mc_group_oid_to_db_idx(group_oid, &new_l2mc_group_idx);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    if (new_l2mc_group_idx == data->l2mc_db_idx) {
        return SAI_STATUS_SUCCESS;
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(data->l2mc_db_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_dec(data->l2mc_db_idx);
    }

    data->l2mc_db_idx = new_l2mc_group_idx;

    if (g_sai_db_ptr->flood_actions[attr] == SAI_PACKET_ACTION_DROP) {
        if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(new_l2mc_group_idx)) {
            mlnx_l2mc_group_flood_ctrl_ref_inc(data->l2mc_db_idx);
        }

        return SAI_STATUS_SUCCESS;
    }

    if (data->type == MLNX_FID_FLOOD_TYPE_L2MC_GROUP) {
        status = mlnx_fid_flood_ctrl_update(sx_fid, attr, MLNX_FID_FLOOD_TYPE_L2MC_GROUP, data);
        if (SAI_ERR(status)) {
            return status;
        }
    }

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(new_l2mc_group_idx)) {
        mlnx_l2mc_group_flood_ctrl_ref_inc(data->l2mc_db_idx);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_flood_ctrl_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t                      status;
    uint16_t                          vlan_id;
    sai_vlan_attr_t                   attr;
    mlnx_fid_flood_ctrl_attr_t        flood_ctrl_attr;
    const mlnx_fid_flood_type_data_t *flood_ctrl_data;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE) ||
           (attr == SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE) ||
           (attr == SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE));

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();

    flood_ctrl_attr = mlnx_vlan_flood_ctrl_attr_to_fid_attr(attr);
    flood_ctrl_data = &mlnx_vlan_db_get_vlan(vlan_id)->flood_data.types[flood_ctrl_attr];

    value->s32 = mlnx_fid_flood_type_to_vlan_type(flood_ctrl_data->type);

    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_flood_ctrl_type_set(_In_ const sai_object_key_t      *key,
                                                  _In_ const sai_attribute_value_t *value,
                                                  void                             *arg)
{
    sai_status_t                status;
    uint16_t                    vlan_id;
    sai_vlan_attr_t             attr;
    mlnx_fid_flood_ctrl_attr_t  flood_ctrl_attr;
    mlnx_fid_flood_type_data_t *flood_ctrl_data;
    mlnx_fid_flood_ctrl_type_t  new_type;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE) ||
           (attr == SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE) ||
           (attr == SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE));

    new_type = mlnx_vlan_flood_type_to_fid_type(value->s32);

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();

    flood_ctrl_attr = mlnx_vlan_flood_ctrl_attr_to_fid_attr(attr);
    flood_ctrl_data = &mlnx_vlan_db_get_vlan(vlan_id)->flood_data.types[flood_ctrl_attr];

    status = mlnx_fid_flood_ctrl_type_set(vlan_id, flood_ctrl_attr, flood_ctrl_data, new_type);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_flood_ctrl_l2mc_group_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t                      status;
    uint16_t                          vlan_id;
    sai_vlan_attr_t                   attr;
    const mlnx_fid_flood_type_data_t *flood_ctrl_data;
    mlnx_fid_flood_ctrl_attr_t        flood_ctrl_attr;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP) ||
           (attr == SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP) ||
           (attr == SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP));

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_read_lock();

    flood_ctrl_attr = mlnx_vlan_flood_ctrl_group_attr_to_fid_attr(attr);
    flood_ctrl_data = &mlnx_vlan_db_get_vlan(vlan_id)->flood_data.types[flood_ctrl_attr];

    value->oid = SAI_NULL_OBJECT_ID;

    if (MLNX_L2MC_GROUP_DB_IDX_IS_VALID(flood_ctrl_data->l2mc_db_idx)) {
        status = mlnx_l2mc_group_oid_create(&l2mc_group_db(flood_ctrl_data->l2mc_db_idx), &value->oid);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            SX_LOG_EXIT();
            return status;
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_flood_ctrl_l2mc_group_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t                status;
    uint16_t                    vlan_id;
    sai_vlan_attr_t             attr;
    mlnx_fid_flood_type_data_t *flood_ctrl_data;
    mlnx_fid_flood_ctrl_attr_t  flood_ctrl_attr;

    SX_LOG_ENTER();

    attr = (long)(arg);

    assert((attr == SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP) ||
           (attr == SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP) ||
           (attr == SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP));

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();

    flood_ctrl_attr = mlnx_vlan_flood_ctrl_group_attr_to_fid_attr(attr);
    flood_ctrl_data = &mlnx_vlan_db_get_vlan(vlan_id)->flood_data.types[flood_ctrl_attr];

    status = mlnx_fid_flood_ctrl_l2mc_group_set(vlan_id, flood_ctrl_attr, flood_ctrl_data, value->oid);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_default_vlan_flood_ctrl_init(void)
{
    return mlnx_fid_flood_ctrl_type_data_apply(DEFAULT_VLAN, MLNX_FID_FLOOD_CTRL_ATTR_MC,
                                               &mlnx_vlan_db_get_vlan(DEFAULT_VLAN)->flood_data.types[
                                                   MLNX_FID_FLOOD_CTRL_ATTR_MC]);
}

sai_status_t mlnx_fid_flood_ctrl_clear(_In_ sx_fid_t sx_fid)
{
    sx_status_t sx_status;

    sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_DELETE_ALL_PORTS,
                                             DEFAULT_ETH_SWID, sx_fid, SX_FLOOD_CONTROL_TYPE_UNICAST_E,
                                             0, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete fdb unicast flood list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_fdb_flood_control_set(gh_sdk, SX_ACCESS_CMD_DELETE_ALL_PORTS,
                                             DEFAULT_ETH_SWID, sx_fid, SX_FLOOD_CONTROL_TYPE_BROADCAST_E,
                                             0, NULL);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to delete fdb broadcast flood list for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_fdb_unreg_mc_flood_mode_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, SX_FDB_UNREG_MC_PRUNE);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set fdb unreg mc flood mode for fid %u - %s.\n", sx_fid, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_fdb_unreg_mc_flood_ports_set(gh_sdk, DEFAULT_ETH_SWID, sx_fid, NULL, 0);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to clear fdb unreg mc flood port list for fid %u - %s.\n", sx_fid,
                   SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_vlan_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_vlan_api_t mlnx_vlan_api = {
    mlnx_create_vlan,
    mlnx_remove_vlan,
    mlnx_set_vlan_attribute,
    mlnx_get_vlan_attribute,
    mlnx_create_vlan_member,
    mlnx_remove_vlan_member,
    mlnx_set_vlan_member_attribute,
    mlnx_get_vlan_member_attribute,
    mlnx_create_vlan_members,
    mlnx_remove_vlan_members,
    mlnx_get_vlan_stats,
    mlnx_get_vlan_stats_ext,
    mlnx_clear_vlan_stats
};
