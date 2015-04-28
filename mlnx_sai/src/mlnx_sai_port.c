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
#define __MODULE__ SAI_PORT

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

sai_status_t mlnx_port_state_set(_In_ const sai_object_key_t      *key,
                                 _In_ const sai_attribute_value_t *value,
                                 void                             *arg);
sai_status_t mlnx_port_default_vlan_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
sai_status_t mlnx_port_default_vlan_prio_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
sai_status_t mlnx_port_ingress_filter_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);
sai_status_t mlnx_port_drop_tags_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg);
sai_status_t mlnx_port_internal_loopback_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg);
sai_status_t mlnx_port_fdb_learning_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
sai_status_t mlnx_port_stp_state_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg);
sai_status_t mlnx_port_mtu_set(_In_ const sai_object_key_t      *key,
                               _In_ const sai_attribute_value_t *value,
                               void                             *arg);
sai_status_t mlnx_port_speed_set(_In_ const sai_object_key_t      *key,
                                 _In_ const sai_attribute_value_t *value,
                                 void                             *arg);
sai_status_t mlnx_port_type_get(_In_ const sai_object_key_t   *key,
                                _Inout_ sai_attribute_value_t *value,
                                _In_ uint32_t                  attr_index,
                                _Inout_ vendor_cache_t        *cache,
                                void                          *arg);
sai_status_t mlnx_port_state_get(_In_ const sai_object_key_t   *key,
                                 _Inout_ sai_attribute_value_t *value,
                                 _In_ uint32_t                  attr_index,
                                 _Inout_ vendor_cache_t        *cache,
                                 void                          *arg);
sai_status_t mlnx_port_speed_get(_In_ const sai_object_key_t   *key,
                                 _Inout_ sai_attribute_value_t *value,
                                 _In_ uint32_t                  attr_index,
                                 _Inout_ vendor_cache_t        *cache,
                                 void                          *arg);
sai_status_t mlnx_port_default_vlan_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
sai_status_t mlnx_port_default_vlan_prio_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
sai_status_t mlnx_port_ingress_filter_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_port_drop_tags_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
sai_status_t mlnx_port_internal_loopback_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
sai_status_t mlnx_port_fdb_learning_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
sai_status_t mlnx_port_stp_state_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
sai_status_t mlnx_port_mtu_get(_In_ const sai_object_key_t   *key,
                               _Inout_ sai_attribute_value_t *value,
                               _In_ uint32_t                  attr_index,
                               _Inout_ vendor_cache_t        *cache,
                               void                          *arg);

static const sai_attribute_entry_t        port_attribs[] = {
    { SAI_PORT_ATTR_TYPE, false, false, false,
      "Port type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_OPER_STATUS, false, false, false,
      "Port operational status", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_SPEED, false, false, true,
      "Port speed", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_PORT_ATTR_ADMIN_STATE, false, false, true,
      "Port admin state", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_DEFAULT_VLAN, false, false, true,
      "Port default vlan", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY, false, false, true,
      "Port default vlan priority", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_PORT_ATTR_INGRESS_FILTERING, false, false, true,
      "Port ingress filtering", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_DROP_UNTAGGED, false, false, true,
      "Port drop untageed", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_DROP_TAGGED, false, false, true,
      "Port drop tageed", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_INTERNAL_LOOPBACK, false, false, true,
      "Port internal loopback", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_FDB_LEARNING, false, false, true,
      "Port fdb learning", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_STP_STATE, false, false, true,
      "Port stp state", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_UPDATE_DSCP, false, false, true,
      "Port update DSCP", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_MTU, false, false, true,
      "Port mtu", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_PORT_ATTR_SFLOW, false, false, true,
      "Port sflow", SAI_ATTR_VAL_TYPE_UNDETERMINED },
    { SAI_PORT_ATTR_FLOOD_STORM_CONTROL, false, false, true,
      "Port flood storm control", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_BROADCAST_STORM_CONTROL, false, false, true,
      "Port broadcast storm control", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_MULTICAST_STORM_CONTROL, false, false, true,
      "Port multicast storm control", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL, false, false, true,
      "Port global flow control", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_PORT_ATTR_MAX_LEARNED_ADDRESSES, false, false, true,
      "Port max learned addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION, false, false, true,
      "Port fdb learning limit violation", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t port_vendor_attribs[] = {
    { SAI_PORT_ATTR_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_type_get, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_OPER_STATUS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_port_state_get, (void*)SAI_PORT_ATTR_OPER_STATUS,
      NULL, NULL },
    { SAI_PORT_ATTR_SPEED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_speed_get, NULL,
      mlnx_port_speed_set, NULL },
    { SAI_PORT_ATTR_ADMIN_STATE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_state_get, (void*)SAI_PORT_ATTR_ADMIN_STATE,
      mlnx_port_state_set, NULL },
    { SAI_PORT_ATTR_DEFAULT_VLAN,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_default_vlan_get, NULL,
      mlnx_port_default_vlan_set, NULL },
    { SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_default_vlan_prio_get, NULL,
      mlnx_port_default_vlan_prio_set, NULL },
    { SAI_PORT_ATTR_INGRESS_FILTERING,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_ingress_filter_get, NULL,
      mlnx_port_ingress_filter_set, NULL },
    { SAI_PORT_ATTR_DROP_UNTAGGED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_drop_tags_get, (void*)SAI_PORT_ATTR_DROP_UNTAGGED,
      mlnx_port_drop_tags_set, (void*)SAI_PORT_ATTR_DROP_UNTAGGED },
    { SAI_PORT_ATTR_DROP_TAGGED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_drop_tags_get, (void*)SAI_PORT_ATTR_DROP_TAGGED,
      mlnx_port_drop_tags_set, (void*)SAI_PORT_ATTR_DROP_TAGGED },
    { SAI_PORT_ATTR_INTERNAL_LOOPBACK,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_internal_loopback_get, NULL,
      mlnx_port_internal_loopback_set, NULL },
    { SAI_PORT_ATTR_FDB_LEARNING,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_fdb_learning_get, NULL,
      mlnx_port_fdb_learning_set, NULL },
    { SAI_PORT_ATTR_STP_STATE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_stp_state_get, NULL,
      mlnx_port_stp_state_set, NULL },
    { SAI_PORT_ATTR_UPDATE_DSCP,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_MTU,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_port_mtu_get, NULL,
      mlnx_port_mtu_set, NULL },
    { SAI_PORT_ATTR_SFLOW,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_FLOOD_STORM_CONTROL,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_BROADCAST_STORM_CONTROL,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_MULTICAST_STORM_CONTROL,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_MAX_LEARNED_ADDRESSES,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL }
};

/* Admin Mode [bool] */
sai_status_t mlnx_port_state_set(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value, void *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_state_set(gh_sdk, port_id,
                                                             value->booldata ? SX_PORT_ADMIN_STATUS_UP :
                                                             SX_PORT_ADMIN_STATUS_DOWN))) {
        SX_LOG_ERR("Failed to set port admin state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VLAN [sai_vlan_id_t]
 *   Untagged ingress frames are tagged with default VLAN
 */
sai_status_t mlnx_port_default_vlan_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD, port_id, value->u16))) {
        SX_LOG_ERR("Failed to set port pvid - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VLAN Priority [uint8_t]
 *  (default to 0) */
sai_status_t mlnx_port_default_vlan_prio_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_cos_port_default_prio_set(gh_sdk, port_id, value->u8))) {
        SX_LOG_ERR("Failed to set port default prio - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Ingress Filtering (Drop Frames with Unknown VLANs) [bool] */
sai_status_t mlnx_port_ingress_filter_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_ingr_filter_set(gh_sdk, port_id,
                                                                        value->booldata ? SX_INGR_FILTER_ENABLE :
                                                                        SX_INGR_FILTER_DISABLE))) {
        SX_LOG_ERR("Failed to set port ingress filter - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dropping of untagged frames on ingress [bool] */
/* Dropping of tagged frames on ingress [bool] */
sai_status_t mlnx_port_drop_tags_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg)
{
    sai_status_t          status;
    const sai_port_id_t   port_id = key->port_id;
    sx_vlan_frame_types_t frame_types;

    SX_LOG_ENTER();

    assert((SAI_PORT_ATTR_DROP_UNTAGGED == (int64_t)arg) || (SAI_PORT_ATTR_DROP_TAGGED == (int64_t)arg));

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port_id, &frame_types))) {
        SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_PORT_ATTR_DROP_UNTAGGED == (int64_t)arg) {
        frame_types.allow_untagged = !(value->booldata);
    } else if (SAI_PORT_ATTR_DROP_TAGGED == (int64_t)arg) {
        frame_types.allow_tagged = !(value->booldata);
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_set(gh_sdk, port_id, &frame_types))) {
        SX_LOG_ERR("Failed to set port accepted frame types - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Internal loopback control [sai_port_loopback_mode_t] */
sai_status_t mlnx_port_internal_loopback_set(_In_ const sai_object_key_t      *key,
                                             _In_ const sai_attribute_value_t *value,
                                             void                             *arg)
{
    sai_status_t            status;
    const sai_port_id_t     port_id = key->port_id;
    sx_port_phys_loopback_t loop_val;

    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_PORT_INTERNAL_LOOPBACK_NONE:
        loop_val = SX_PORT_PHYS_LOOPBACK_DISABLE;
        break;

    case SAI_PORT_INTERNAL_LOOPBACK_PHY:
        SX_LOG_ERR("Port internal phy loopback not supported\n");
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;

    case SAI_PORT_INTERNAL_LOOPBACK_MAC:
        loop_val = SX_PORT_PHYS_LOOPBACK_ENABLE_INTERNAL;
        break;

    default:
        SX_LOG_ERR("Invalid port internal loopback value %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_port_phys_loopback_set(gh_sdk, port_id, loop_val))) {
        SX_LOG_ERR("Failed to set port physical loopback - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* FDB Learning mode [sai_port_fdb_learning_mode_t] */
sai_status_t mlnx_port_fdb_learning_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_fdb_learn_mode_t learn_mode;

    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_PORT_LEARN_MODE_DISABLE:
        learn_mode = SX_FDB_LEARN_MODE_DONT_LEARN;
        break;

    case SAI_PORT_LEARN_MODE_HW:
        learn_mode = SX_FDB_LEARN_MODE_AUTO_LEARN;
        break;

    default:
        SX_LOG_ERR("Invalid port fdb learning mode %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_port_learn_mode_set(gh_sdk, port_id, learn_mode))) {
        SX_LOG_ERR("Failed to set port learning mode - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Stp mode [sai_port_stp_state_t] */
sai_status_t mlnx_port_stp_state_set(_In_ const sai_object_key_t      *key,
                                     _In_ const sai_attribute_value_t *value,
                                     void                             *arg)
{
    sai_status_t              status;
    const sai_port_id_t       port_id = key->port_id;
    sx_mstp_inst_port_state_t stp_state;

    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_PORT_STP_STATE_DISCARDING:
        stp_state = SX_MSTP_INST_PORT_STATE_DISCARDING;
        break;

    case SAI_PORT_STP_STATE_LEARNING:
        stp_state = SX_MSTP_INST_PORT_STATE_LEARNING;
        break;

    case SAI_PORT_STP_STATE_FORWARDING:
        stp_state = SX_MSTP_INST_PORT_STATE_FORWARDING;
        break;

    /* TODO : translate these states */
    case SAI_PORT_STP_STATE_DISABLED:
    case SAI_PORT_STP_STATE_LISTENING:
    case SAI_PORT_STP_STATE_BLOCKING:
    default:
        SX_LOG_ERR("Invalid stp state %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_rstp_port_state_set(gh_sdk, port_id, stp_state))) {
        SX_LOG_ERR("Failed to set port stp state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* MTU [uint32_t] */
sai_status_t mlnx_port_mtu_set(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value, void *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_mtu_set(gh_sdk, port_id, (sx_port_mtu_t)value->u32))) {
        SX_LOG_ERR("Failed to set port mtu - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Speed in Mbps [uint32_t] */
sai_status_t mlnx_port_speed_set(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value, void *arg)
{
    sai_status_t               status;
    const sai_port_id_t        port_id = key->port_id;
    sx_port_speed_capability_t speed;

    SX_LOG_ENTER();

    memset(&speed, 0, sizeof(speed));

    /* Use values for copper cables, which are the default media type. TODO : support additional media types */
    switch (value->u32) {
    case PORT_SPEED_1:
        speed.mode_1GB_CX_SGMII = true;
        break;

    case PORT_SPEED_10:
        speed.mode_10GB_CX4_XAUI = true;
        break;

    case PORT_SPEED_20:
        speed.mode_20GB_KR2 = true;
        break;

    case PORT_SPEED_40:
        speed.mode_40GB_CR4 = true;
        break;

    case PORT_SPEED_56:
        speed.mode_56GB_KR4 = true;
        break;

    default:
        SX_LOG_ERR("Invalid speed %u\n", value->u32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_port_speed_admin_set(gh_sdk, port_id, &speed))) {
        SX_LOG_ERR("Failed to set port speed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Port type [sai_port_type_t] */
sai_status_t mlnx_port_type_get(_In_ const sai_object_key_t   *key,
                                _Inout_ sai_attribute_value_t *value,
                                _In_ uint32_t                  attr_index,
                                _Inout_ vendor_cache_t        *cache,
                                void                          *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_port_mode_t      port_mode;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_mode_get(gh_sdk, port_id, &port_mode))) {
        SX_LOG_ERR("Failed to get port mode - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (port_mode) {
    case SX_PORT_MODE_EXTERNAL:
        value->s32 = SAI_PORT_TYPE_LOGICAL;
        break;

    case SX_PORT_MODE_CPU:
        value->s32 = SAI_PORT_TYPE_CPU;
        break;

    /* TODO : add case for LAG */

    case SX_PORT_MODE_STACKING:
    case SX_PORT_MODE_TCA_CONNECTOR:
    default:
        SX_LOG_ERR("Unexpected port mode %d\n", port_mode);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Operational Status [sai_port_oper_status_t] */
/* Admin Mode [bool] */
sai_status_t mlnx_port_state_get(_In_ const sai_object_key_t   *key,
                                 _Inout_ sai_attribute_value_t *value,
                                 _In_ uint32_t                  attr_index,
                                 _Inout_ vendor_cache_t        *cache,
                                 void                          *arg)
{
    sai_status_t           status;
    const sai_port_id_t    port_id = key->port_id;
    sx_port_oper_state_t   state_oper;
    sx_port_admin_state_t  state_admin;
    sx_port_module_state_t state_module;

    SX_LOG_ENTER();

    assert((SAI_PORT_ATTR_OPER_STATUS == (int64_t)arg) || (SAI_PORT_ATTR_ADMIN_STATE == (int64_t)arg));

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_state_get(gh_sdk, port_id, &state_oper, &state_admin, &state_module))) {
        SX_LOG_ERR("Failed to get port state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_PORT_ATTR_OPER_STATUS == (int64_t)arg) {
        switch (state_oper) {
        case SX_PORT_OPER_STATUS_UP:
            value->s32 = SAI_PORT_OPER_STATUS_UP;
            break;

        case SX_PORT_OPER_STATUS_DOWN:
        case SX_PORT_OPER_STATUS_DOWN_BY_FAIL:
            value->s32 = SAI_PORT_OPER_STATUS_DOWN;
            break;

        default:
            value->s32 = SAI_PORT_OPER_STATUS_UNKNOWN;
        }
    } else {
        switch (state_admin) {
        case SX_PORT_ADMIN_STATUS_UP:
            value->booldata = true;
            break;

        case SX_PORT_ADMIN_STATUS_DOWN:
            value->booldata = false;
            break;

        default:
            SX_LOG_ERR("Unexpected port admin state %d\n", state_admin);
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Speed in Mbps [uint32_t] */
sai_status_t mlnx_port_speed_get(_In_ const sai_object_key_t   *key,
                                 _Inout_ sai_attribute_value_t *value,
                                 _In_ uint32_t                  attr_index,
                                 _Inout_ vendor_cache_t        *cache,
                                 void                          *arg)
{
    sai_status_t               status;
    const sai_port_id_t        port_id = key->port_id;
    sx_port_speed_capability_t speed_cap;
    sx_port_oper_speed_t       speed_oper;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_speed_get(gh_sdk, port_id, &speed_cap, &speed_oper))) {
        SX_LOG_ERR("Failed to get port speed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (speed_cap.mode_56GB_KX4 || speed_cap.mode_56GB_KR4) {
        value->u32 = PORT_SPEED_56;
    } else if (speed_cap.mode_40GB_KR4 || speed_cap.mode_40GB_CR4) {
        value->u32 = PORT_SPEED_40;
    } else if (speed_cap.mode_20GB_KR2) {
        value->u32 = PORT_SPEED_20;
    } else if (speed_cap.mode_10GB_KR || speed_cap.mode_10GB_KX4 || speed_cap.mode_10GB_CX4_XAUI) {
        value->u32 = PORT_SPEED_10;
    } else if (speed_cap.mode_1GB_CX_SGMII || speed_cap.mode_1GB_KX) {
        value->u32 = PORT_SPEED_1;
    } else {
        SX_LOG_ERR("Unexpected port speed\n");
        value->u32 = 0;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VLAN [sai_vlan_id_t]
 *   Untagged ingress frames are tagged with default VLAN
 */
sai_status_t mlnx_port_default_vlan_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_vid_t            pvid;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_pvid_get(gh_sdk, port_id, &pvid))) {
        SX_LOG_ERR("Failed to get port pvid - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u16 = pvid;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VLAN Priority [uint8_t]
 *  (default to 0) */
sai_status_t mlnx_port_default_vlan_prio_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_cos_priority_t   prio;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_cos_port_default_prio_get(gh_sdk, port_id, &prio))) {
        SX_LOG_ERR("Failed to get port default prio - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u8 = prio;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Ingress Filtering (Drop Frames with Unknown VLANs) [bool] */
sai_status_t mlnx_port_ingress_filter_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    sai_status_t          status;
    const sai_port_id_t   port_id = key->port_id;
    sx_ingr_filter_mode_t mode;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_ingr_filter_get(gh_sdk, port_id, &mode))) {
        SX_LOG_ERR("Failed to get port ingress filter - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->booldata = mode;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dropping of untagged frames on ingress [bool] */
/* Dropping of tagged frames on ingress [bool] */
sai_status_t mlnx_port_drop_tags_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    sai_status_t          status;
    const sai_port_id_t   port_id = key->port_id;
    sx_vlan_frame_types_t frame_types;

    SX_LOG_ENTER();

    assert((SAI_PORT_ATTR_DROP_UNTAGGED == (int64_t)arg) || (SAI_PORT_ATTR_DROP_TAGGED == (int64_t)arg));

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_port_accptd_frm_types_get(gh_sdk, port_id, &frame_types))) {
        SX_LOG_ERR("Failed to get port accepted frame types - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SAI_PORT_ATTR_DROP_UNTAGGED == (int64_t)arg) {
        value->booldata = !(frame_types.allow_untagged);
    } else {
        value->booldata = !(frame_types.allow_tagged);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Internal loopback control [sai_port_internal_loopback_mode_t] */
sai_status_t mlnx_port_internal_loopback_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg)
{
    sai_status_t            status;
    const sai_port_id_t     port_id = key->port_id;
    sx_port_phys_loopback_t loopback;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_phys_loopback_get(gh_sdk, port_id, &loopback))) {
        SX_LOG_ERR("Failed to get port physical loopback - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* is internal loopback enabled bool */
    if ((loopback == SX_PORT_PHYS_LOOPBACK_ENABLE_INTERNAL) || (loopback == SX_PORT_PHYS_LOOPBACK_ENABLE_BOTH)) {
        value->s32 = SAI_PORT_INTERNAL_LOOPBACK_MAC;
    } else {
        value->s32 = SAI_PORT_INTERNAL_LOOPBACK_NONE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* FDB Learning mode [sai_port_fdb_learning_mode_t] */
sai_status_t mlnx_port_fdb_learning_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_fdb_learn_mode_t learn_mode;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_port_learn_mode_get(gh_sdk, port_id, &learn_mode))) {
        SX_LOG_ERR("Failed to get port learning mode - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_FDB_LEARN_MODE_DONT_LEARN == learn_mode) {
        value->s32 = SAI_PORT_LEARN_MODE_DISABLE;
    } else {
        value->s32 = SAI_PORT_LEARN_MODE_HW;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Stp mode [sai_port_stp_state_t] */
sai_status_t mlnx_port_stp_state_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    sai_status_t              status;
    const sai_port_id_t       port_id = key->port_id;
    sx_mstp_inst_port_state_t stp_state;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_rstp_port_state_get(gh_sdk, port_id, &stp_state))) {
        SX_LOG_ERR("Failed to get port stp state - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (stp_state) {
    case SX_MSTP_INST_PORT_STATE_DISCARDING:
        value->s32 = SAI_PORT_STP_STATE_DISCARDING;
        break;

    case SX_MSTP_INST_PORT_STATE_LEARNING:
        value->s32 = SAI_PORT_STP_STATE_LEARNING;
        break;

    case SX_MSTP_INST_PORT_STATE_FORWARDING:
        value->s32 = SAI_PORT_STP_STATE_FORWARDING;
        break;

    default:
        SX_LOG_ERR("Unexpected stp state %d\n", stp_state);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* MTU [uint32_t] */
sai_status_t mlnx_port_mtu_get(_In_ const sai_object_key_t   *key,
                               _Inout_ sai_attribute_value_t *value,
                               _In_ uint32_t                  attr_index,
                               _Inout_ vendor_cache_t        *cache,
                               void                          *arg)
{
    sai_status_t        status;
    const sai_port_id_t port_id = key->port_id;
    sx_port_mtu_t       max_mtu;
    sx_port_mtu_t       oper_mtu;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_port_mtu_get(gh_sdk, port_id, &max_mtu, &oper_mtu))) {
        SX_LOG_ERR("Failed to get port mtu - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u32 = oper_mtu;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static void port_key_to_str(_In_ sai_port_id_t port_id, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "port %x", port_id);
}

/*
 * Routine Description:
 *   Set port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_port_attribute(_In_ sai_port_id_t port_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .port_id = port_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    return sai_set_attribute(&key, key_str, port_attribs, port_vendor_attribs, attr);
}


/*
 * Routine Description:
 *   Get port attribute value.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_port_attribute(_In_ sai_port_id_t       port_id,
                                     _In_ uint32_t            attr_count,
                                     _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .port_id = port_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    return sai_get_attributes(&key, key_str, port_attribs, port_vendor_attribs, attr_count, attr_list);
}

/*
 * Routine Description:
 *   Get port statistics counters.
 *
 * Arguments:
 *    [in] port_id - port id
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_port_stats(_In_ sai_port_id_t                  port_id,
                                 _In_ const sai_port_stat_counter_t *counter_ids,
                                 _In_ uint32_t                       number_of_counters,
                                 _Out_ uint64_t                    * counters)
{
    sai_status_t            status;
    sx_port_cntr_rfc_2863_t cnts_2863;
    sx_port_cntr_rfc_2819_t cnts_2819;
    uint32_t                ii;
    char                    key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    port_key_to_str(port_id, key_str);
    SX_LOG_NTC("Get port stats %s\n", key_str);

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_counter_rfc_2863_get(gh_sdk, SX_ACCESS_CMD_READ, port_id, &cnts_2863))) {
        SX_LOG_ERR("Failed to get port rfc 2863 counters - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_counter_rfc_2819_get(gh_sdk, SX_ACCESS_CMD_READ, port_id, &cnts_2819))) {
        SX_LOG_ERR("Failed to get port rfc 2819 counters - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    for (ii = 0; ii < number_of_counters; ii++) {
        switch (counter_ids[ii]) {
        case SAI_PORT_STAT_IF_IN_OCTETS:
            counters[ii] = cnts_2863.if_in_octets;
            break;

        case SAI_PORT_STAT_IF_IN_UCAST_PKTS:
            counters[ii] = cnts_2863.if_in_ucast_pkts;
            break;

        case SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS:
            counters[ii] = cnts_2863.if_in_broadcast_pkts + cnts_2863.if_in_multicast_pkts;
            break;

        case SAI_PORT_STAT_IF_IN_DISCARDS:
            counters[ii] = cnts_2863.if_in_discards;
            break;

        case SAI_PORT_STAT_IF_IN_ERRORS:
            counters[ii] = cnts_2863.if_in_errors;
            break;

        case SAI_PORT_STAT_IF_IN_UNKNOWN_PROTOS:
            counters[ii] = cnts_2863.if_in_unknown_protos;
            break;

        case SAI_PORT_STAT_IF_IN_BROADCAST_PKTS:
            counters[ii] = cnts_2863.if_in_broadcast_pkts;
            break;

        case SAI_PORT_STAT_IF_IN_MULTICAST_PKTS:
            counters[ii] = cnts_2863.if_in_multicast_pkts;
            break;

        case SAI_PORT_STAT_IF_OUT_OCTETS:
            counters[ii] = cnts_2863.if_out_octets;
            break;

        case SAI_PORT_STAT_IF_OUT_UCAST_PKTS:
            counters[ii] = cnts_2863.if_out_ucast_pkts;
            break;

        case SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS:
            counters[ii] = cnts_2863.if_out_broadcast_pkts + cnts_2863.if_out_multicast_pkts;
            break;

        case SAI_PORT_STAT_IF_OUT_DISCARDS:
            counters[ii] = cnts_2863.if_out_discards;
            break;

        case SAI_PORT_STAT_IF_OUT_ERRORS:
            counters[ii] = cnts_2863.if_out_errors;
            break;

        case SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS:
            counters[ii] = cnts_2863.if_out_broadcast_pkts;
            break;

        case SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS:
            counters[ii] = cnts_2863.if_out_multicast_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_DROP_EVENTS:
            counters[ii] = cnts_2819.ether_stats_drop_events;
            break;

        case SAI_PORT_STAT_ETHER_STATS_MULTICAST_PKTS:
            counters[ii] = cnts_2819.ether_stats_multicast_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_BROADCAST_PKTS:
            counters[ii] = cnts_2819.ether_stats_broadcast_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_UNDERSIZE_PKTS:
            counters[ii] = cnts_2819.ether_stats_undersize_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_FRAGMENTS:
            counters[ii] = cnts_2819.ether_stats_fragments;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_64_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts64octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_65_TO_127_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts65to127octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_128_TO_255_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts128to255octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_256_TO_511_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts256to511octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_512_TO_1023_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts512to1023octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS_1024_TO_1518_OCTETS:
            counters[ii] = cnts_2819.ether_stats_pkts1024to1518octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_OVERSIZE_PKTS:
            counters[ii] = cnts_2819.ether_stats_oversize_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_JABBERS:
            counters[ii] = cnts_2819.ether_stats_jabbers;
            break;

        case SAI_PORT_STAT_ETHER_STATS_OCTETS:
            counters[ii] = cnts_2819.ether_stats_octets;
            break;

        case SAI_PORT_STAT_ETHER_STATS_PKTS:
            counters[ii] = cnts_2819.ether_stats_pkts;
            break;

        case SAI_PORT_STAT_ETHER_STATS_COLLISIONS:
            counters[ii] = cnts_2819.ether_stats_collisions;
            break;

        case SAI_PORT_STAT_ETHER_STATS_CRC_ALIGN_ERRORS:
            counters[ii] = cnts_2819.ether_stats_crc_align_errors;
            break;

        case SAI_PORT_STAT_IF_IN_VLAN_DISCARDS:
        case SAI_PORT_STAT_IF_OUT_QLEN:
        case SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS:
        case SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS:
        case SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS:
        case SAI_PORT_STAT_ETHER_STATS_RX_NO_ERRORS:
        case SAI_PORT_STAT_IP_IN_RECEIVES:
        case SAI_PORT_STAT_IP_IN_OCTETS:
        case SAI_PORT_STAT_IP_IN_UCAST_PKTS:
        case SAI_PORT_STAT_IP_IN_NON_UCAST_PKTS:
        case SAI_PORT_STAT_IP_IN_DISCARDS:
        case SAI_PORT_STAT_IP_OUT_OCTETS:
        case SAI_PORT_STAT_IP_OUT_UCAST_PKTS:
        case SAI_PORT_STAT_IP_OUT_NON_UCAST_PKTS:
        case SAI_PORT_STAT_IP_OUT_DISCARDS:
        case SAI_PORT_STAT_IPV6_IN_RECEIVES:
        case SAI_PORT_STAT_IPV6_IN_OCTETS:
        case SAI_PORT_STAT_IPV6_IN_UCAST_PKTS:
        case SAI_PORT_STAT_IPV6_IN_NON_UCAST_PKTS:
        case SAI_PORT_STAT_IPV6_IN_MCAST_PKTS:
        case SAI_PORT_STAT_IPV6_IN_DISCARDS:
        case SAI_PORT_STAT_IPV6_OUT_OCTETS:
        case SAI_PORT_STAT_IPV6_OUT_UCAST_PKTS:
        case SAI_PORT_STAT_IPV6_OUT_NON_UCAST_PKTS:
        case SAI_PORT_STAT_IPV6_OUT_MCAST_PKTS:
        case SAI_PORT_STAT_IPV6_OUT_DISCARDS:
            return SAI_STATUS_NOT_IMPLEMENTED;

        default:
            SX_LOG_ERR("Invalid port counter %d\n", counter_ids[ii]);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_port_api_t port_api = {
    mlnx_set_port_attribute,
    mlnx_get_port_attribute,
    mlnx_get_port_stats
};
