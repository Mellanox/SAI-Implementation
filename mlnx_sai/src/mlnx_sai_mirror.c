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
#define __MODULE__ SAI_MIRROR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_mirror_session_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_mirror_session_monitor_port_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static sai_status_t mlnx_mirror_session_truncate_size_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_mirror_session_tc_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_mirror_session_vlan_tpid_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg);
static sai_status_t mlnx_mirror_session_vlan_id_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_mirror_session_vlan_pri_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_mirror_session_vlan_cfi_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_mirror_session_vlan_header_valid_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg);
static sai_status_t mlnx_mirror_session_encap_type_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_mirror_session_iphdr_version_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_mirror_session_tos_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_mirror_session_ttl_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_mirror_session_ip_address_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_mirror_session_mac_address_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_mirror_session_gre_protocol_type_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg);
static sai_status_t mlnx_mirror_session_policer_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_mirror_session_congestion_mode_set(_In_ const sai_object_key_t      *key,
                                                            _In_ const sai_attribute_value_t *value,
                                                            void                             *arg);
static sai_status_t mlnx_mirror_session_congestion_mode_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg);
static sai_status_t mlnx_mirror_session_sample_rate_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static sai_status_t mlnx_mirror_session_sample_rate_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_mirror_session_monitor_port_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg);
static sai_status_t mlnx_mirror_session_truncate_size_set(_In_ const sai_object_key_t      *key,
                                                          _In_ const sai_attribute_value_t *value,
                                                          void                             *arg);
static sai_status_t mlnx_mirror_session_tc_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_mirror_session_vlan_tpid_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg);
static sai_status_t mlnx_mirror_session_vlan_id_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_mirror_session_vlan_pri_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_mirror_session_vlan_cfi_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_mirror_session_vlan_header_valid_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg);
static sai_status_t mlnx_mirror_session_tos_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_mirror_session_ttl_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg);
static sai_status_t mlnx_mirror_session_ip_address_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_mirror_session_mac_address_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static sai_status_t mlnx_mirror_session_gre_protocol_type_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg);
static sai_status_t mlnx_mirror_session_policer_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);

/* is_implemented: create, remove, set, get
 *   is_supported: create, remove, set, get
 */
static const sai_vendor_attribute_entry_t mirror_vendor_attribs[] = {
    { SAI_MIRROR_SESSION_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_mirror_session_type_get, NULL,
      NULL, NULL },
    { SAI_MIRROR_SESSION_ATTR_MONITOR_PORT,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_monitor_port_get, NULL,
      mlnx_mirror_session_monitor_port_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_truncate_size_get, NULL,
      mlnx_mirror_session_truncate_size_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_TC,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_tc_get, NULL,
      mlnx_mirror_session_tc_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_VLAN_TPID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_vlan_tpid_get, NULL,
      mlnx_mirror_session_vlan_tpid_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_VLAN_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_vlan_id_get, NULL,
      mlnx_mirror_session_vlan_id_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_VLAN_PRI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_vlan_pri_get, NULL,
      mlnx_mirror_session_vlan_pri_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_VLAN_CFI,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_vlan_cfi_get, NULL,
      mlnx_mirror_session_vlan_cfi_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_vlan_header_valid_get, NULL,
      mlnx_mirror_session_vlan_header_valid_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_mirror_session_encap_type_get, NULL,
      NULL, NULL },
    { SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_mirror_session_iphdr_version_get, NULL,
      NULL, NULL },
    { SAI_MIRROR_SESSION_ATTR_TOS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_tos_get, NULL,
      mlnx_mirror_session_tos_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_TTL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_ttl_get, NULL,
      mlnx_mirror_session_ttl_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_ip_address_get, (void*)MIRROR_SRC_IP_ADDRESS,
      mlnx_mirror_session_ip_address_set, (void*)MIRROR_SRC_IP_ADDRESS },
    { SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_ip_address_get, (void*)MIRROR_DST_IP_ADDRESS,
      mlnx_mirror_session_ip_address_set, (void*)MIRROR_DST_IP_ADDRESS },
    { SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_mac_address_get, (void*)MIRROR_SRC_MAC_ADDRESS,
      mlnx_mirror_session_mac_address_set, (void*)MIRROR_SRC_MAC_ADDRESS },
    { SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_mac_address_get, (void*)MIRROR_DST_MAC_ADDRESS,
      mlnx_mirror_session_mac_address_set, (void*)MIRROR_DST_MAC_ADDRESS },
    { SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_gre_protocol_type_get, NULL,
      mlnx_mirror_session_gre_protocol_type_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_POLICER,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_policer_get, NULL,
      mlnx_mirror_session_policer_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_congestion_mode_get, NULL,
      mlnx_mirror_session_congestion_mode_set, NULL },
    { SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_mirror_session_sample_rate_get, NULL,
      mlnx_mirror_session_sample_rate_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t        mirror_session_enum_info[] = {
    [SAI_MIRROR_SESSION_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t          mlnx_mirror_session_obj_type_info =
{ mirror_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(mirror_session_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};
static void mirror_key_to_str(_In_ const sai_object_id_t sai_mirror_obj_id, _Out_ char *key_str)
{
    uint32_t sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai mirror obj ID %" PRIx64 "", sai_mirror_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "sai mirror obj ID %" PRIx64 ", sdk mirror obj ID %d",
                 sai_mirror_obj_id,
                 sdk_mirror_obj_id);
    }

    SX_LOG_EXIT();
}

sai_status_t mlnx_mirror_availability_get(_In_ sai_object_id_t        switch_id,
                                          _In_ uint32_t               attr_count,
                                          _In_ const sai_attribute_t *attr_list,
                                          _Out_ uint64_t             *count)
{
    sx_status_t sx_status;
    uint32_t    span_sessions_max = 0, span_sessions_exists = 0;

    assert(count);

    span_sessions_max = g_resource_limits.span_session_id_max_internal + 1;
    sx_status =
        sx_api_span_session_iter_get(gh_sdk, SX_ACCESS_CMD_GET, NULL, NULL, NULL, &span_sessions_exists);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to get count of SPAN sessions - %s\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    *count = (uint64_t)(span_sessions_max - span_sessions_exists);
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_mirror_policer_is_used(_In_ sai_object_id_t policer, _Out_ bool           *is_used)
{
    uint32_t ii;

    assert(is_used);

    for (ii = 0; ii < SPAN_SESSION_MAX; ii++) {
        if (g_sai_db_ptr->mirror_policer[ii].policer_oid == policer) {
            *is_used = true;
            return SAI_STATUS_SUCCESS;
        }
    }

    *is_used = false;
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_mirror_policer_sx_attrs_validate(_In_ const sx_policer_attributes_t *sx_attrs)
{
    assert(sx_attrs);

    if ((sx_attrs->rate_type != SX_POLICER_RATE_TYPE_SINGLE_RATE_E) ||
        (sx_attrs->ebs != 0)) {
        SX_LOG_ERR(
            "Policer type should be SAI_POLICER_MODE_STORM_CONTROL (with PBS = 0) to be used as mirror policer\n");
        return SAI_STATUS_FAILURE;
    }

    if (mlnx_chip_is_spc2or3or4()) {
        if (sx_attrs->color_aware != false) {
            SX_LOG_ERR("Span policer must be SAI_POLICER_COLOR_SOURCE_BLIND\n");
            return SAI_STATUS_FAILURE;
        }

        if (sx_attrs->red_action != SX_POLICER_ACTION_DISCARD) {
            SX_LOG_ERR("Span policer red action must be drop\n");
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_policer_validate(_In_ sai_object_id_t policer_oid)
{
    sai_status_t             status;
    mlnx_policer_db_entry_t *policer;

    status = db_get_sai_policer_data(policer_oid, &policer);
    if (SAI_ERR(status)) {
        return status;
    }

    /* TODO: Temporary hack for the Sonic release
     * Refer to "Bug SW #3177465" for more information */
    if (mlnx_chip_is_spc2or3or4()) {
        sai_object_key_t key = { .key.object_id = policer_oid };
        sai_attribute_t  attr;

        if (policer->sx_policer_attr.color_aware != false) {
            attr.id = SAI_POLICER_ATTR_COLOR_SOURCE;
            attr.value.s32 = SAI_POLICER_COLOR_SOURCE_BLIND;
            status = sai_policer_attr_set(&key,
                                          attr,
                                          "SAI_POLICER_ATTR_COLOR_SOURCE");
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to set mirror policer 0x%X color blind.\n", policer_oid);
                return status;
            }
            SX_LOG_NTC("Set mirror policer 0x%X COLOR BLIND.\n", policer_oid);
        }
        assert(policer->sx_policer_attr.color_aware == false);

        if (policer->sx_policer_attr.rate_type != SX_POLICER_RATE_TYPE_SINGLE_RATE_E) {
            attr.id = SAI_POLICER_ATTR_MODE;
            attr.value.s32 = SAI_POLICER_MODE_SR_TCM;
            status = sai_policer_attr_set(&key,
                                          attr,
                                          "SAI_POLICER_ATTR_MODE");
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to set mirror policer 0x%X single rate mode.\n", policer_oid);
                return status;
            }
            SX_LOG_NTC("Set mirror policer 0x%X mode SINGLE RATE.\n", policer_oid);
        }
        assert(policer->sx_policer_attr.rate_type == SX_POLICER_RATE_TYPE_SINGLE_RATE_E);

        if (policer->sx_policer_attr.red_action != SX_POLICER_ACTION_DISCARD) {
            attr.id = SAI_POLICER_ATTR_RED_PACKET_ACTION;
            attr.value.s32 = SAI_PACKET_ACTION_DROP;
            status = sai_policer_attr_set(&key,
                                          attr,
                                          "SAI_POLICER_ATTR_RED_PACKET_ACTION");
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to set mirror policer 0x%X red drop.\n", policer_oid);
                return status;
            }
            SX_LOG_NTC("Set mirror policer 0x%X RED DROP.\n", policer_oid);
        }
        assert(policer->sx_policer_attr.red_action == SX_POLICER_ACTION_DISCARD);
    }

    return mlnx_mirror_policer_sx_attrs_validate(&policer->sx_policer_attr);
}

static sai_status_t mlnx_get_sdk_mirror_obj_params(_In_ sai_object_id_t            sai_mirror_obj_id,
                                                   _Inout_ sx_span_session_id_t   *sdk_mirror_obj_id,
                                                   _Out_ sx_span_session_params_t *sdk_mirror_obj_params)
{
    uint32_t     sdk_mirror_obj_id_u32 = 0;
    sai_status_t status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id %" PRIx64 "\n", sai_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = (sdk_to_sai(sx_api_span_session_get(gh_sdk, sdk_mirror_obj_id_u32, sdk_mirror_obj_params))))) {
        SX_LOG_ERR("Error getting span session from sdk mirror session id %d\n", sdk_mirror_obj_id_u32);
        SX_LOG_EXIT();
        return status;
    }

    if (NULL != sdk_mirror_obj_id) {
        *sdk_mirror_obj_id = (sx_span_session_id_t)sdk_mirror_obj_id_u32;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_type_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_LOCAL_ETH_TYPE1:
        value->s32 = SAI_MIRROR_SESSION_TYPE_LOCAL;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->s32 = SAI_MIRROR_SESSION_TYPE_REMOTE;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->s32 = SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE;
        break;

    default:
        SX_LOG_ERR("Error: mirror type should be either SPAN or RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_monitor_port_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    uint32_t         sdk_mirror_obj_id = 0;
    sai_status_t     status = SAI_STATUS_FAILURE;
    sx_port_log_id_t sdk_analyzer_port_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id, NULL))) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = (sdk_to_sai(sx_api_span_session_analyzer_get(gh_sdk, sdk_mirror_obj_id, &sdk_analyzer_port_id))))) {
        SX_LOG_ERR("Error getting analyzer port from sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SX_PORT_TYPE_LAG == SX_PORT_TYPE_ID_GET(sdk_analyzer_port_id)) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_log_port_to_object(sdk_analyzer_port_id, &value->oid))) {
            SX_LOG_ERR("Error creating sdk analyzer port LAG object from analyzer port id %x\n", sdk_analyzer_port_id);
            SX_LOG_EXIT();
            return status;
        }
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, sdk_analyzer_port_id, NULL, &value->oid))) {
            SX_LOG_ERR("Error creating sdk analyzer port object from analyzer port id %x\n", sdk_analyzer_port_id);
            SX_LOG_EXIT();
            return status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_truncate_size_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (false == sdk_mirror_obj_params.truncate) {
        value->u16 = 0;
    } else {
        value->u16 = sdk_mirror_obj_params.truncate_size;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_tc_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_LOCAL_ETH_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.local_eth_type1.switch_prio;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.switch_prio;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.switch_prio;
        break;

    default:
        SX_LOG_ERR("Error: mirror type should be either SPAN or RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_tpid_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u16 = MLNX_MIRROR_VLAN_TPID;
        sai_db_read_lock();
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN TPID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
        sai_db_unlock();
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u16 = MLNX_MIRROR_VLAN_TPID;
        break;

    default:
        SX_LOG_ERR("Error: VLAN tpid is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_id_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u16 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.vid;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_read_lock();
        value->u16 = g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN ID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sai_db_unlock();

        assert(value->u16 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);

        break;

    default:
        SX_LOG_ERR("Error: VLAN id is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_pri_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.pcp;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_read_lock();
        value->u8 = g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN ID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sai_db_unlock();
        assert(value->u8 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp);
        break;

    default:
        SX_LOG_ERR("Error: VLAN pri is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_cfi_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.dei;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_read_lock();
        value->u8 = g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN ID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sai_db_unlock();
        assert(value->u8 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei);
        break;

    default:
        SX_LOG_ERR("Error: VLAN cfi is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_header_valid_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_read_lock();
        value->booldata = g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid;
        assert(value->booldata == (0 != sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid));
        sai_db_unlock();
        break;

    default:
        SX_LOG_ERR("Error: VLAN header valid is only valid for ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_encap_type_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->s32 = SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL;
        break;

    default:
        SX_LOG_ERR("Error: Encapsulate type is only valid for ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_iphdr_version_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (SX_IP_VERSION_IPV4 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip.version) {
            value->u8 = IPV4_HEADER_VERSION;
        } else if (SX_IP_VERSION_IPV6 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip.version) {
            value->u8 = IPV6_HEADER_VERSION;
        } else {
            SX_LOG_ERR("Error: IP header version should only be 4 or 6\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    default:
        SX_LOG_ERR("Error: IP header version is only valid for ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_tos_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8 = (sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dscp << DSCP_OFFSET) & DSCP_MASK;
        value->u8 |= (sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ecn & ~DSCP_MASK);
        SX_LOG_NTC("SAI TOS: %d, SDK DSCP: %d, SDK ECN: %d\n", value->u8,
                   sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dscp,
                   sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ecn);
        break;

    default:
        SX_LOG_ERR("Error: TOS is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_ttl_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ttl;
        break;

    default:
        SX_LOG_ERR("Error: TTL is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_ip_address_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_ip_addr_t            *sdk_ip_address = NULL;

    SX_LOG_ENTER();

    assert((MIRROR_SRC_IP_ADDRESS == (long)arg) || (MIRROR_DST_IP_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MIRROR_SRC_IP_ADDRESS == (long)arg) {
            sdk_ip_address = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.src_ip;
        } else if (MIRROR_DST_IP_ADDRESS == (long)arg) {
            sdk_ip_address = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sdk_ip_address_to_sai(sdk_ip_address, &value->ipaddr))) {
            SX_LOG_ERR("Error: IP address should only be IPv4 or IPv6\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Error: IP address is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_mac_address_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    assert((MIRROR_SRC_MAC_ADDRESS == (long)arg) || (MIRROR_DST_MAC_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MIRROR_SRC_MAC_ADDRESS == (long)arg) {
            memcpy(value->mac,
                   sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.smac.ether_addr_octet,
                   sizeof(value->mac));
        } else if (MIRROR_DST_MAC_ADDRESS == (long)arg) {
            memcpy(value->mac, sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.mac.ether_addr_octet,
                   sizeof(value->mac));
        }
        break;

    default:
        SX_LOG_ERR("Error: mac address is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_gre_protocol_type_get(_In_ const sai_object_key_t   *key,
                                                              _Inout_ sai_attribute_value_t *value,
                                                              _In_ uint32_t                  attr_index,
                                                              _Inout_ vendor_cache_t        *cache,
                                                              void                          *arg)
{
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u16 = MLNX_GRE_PROTOCOL_TYPE;
        break;

    default:
        SX_LOG_ERR("Error: GRE protocol type is only valid for ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_policer_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    sai_status_t status = SAI_STATUS_FAILURE;
    uint32_t     sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (sdk_mirror_obj_id >= SPAN_SESSION_MAX) {
        SX_LOG_ERR("Invalid sdk_mirror_obj_id %d > %d\n", sdk_mirror_obj_id, SPAN_SESSION_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_read_lock();

    value->oid = g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid;

    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_translate_congestion_mode_to_sdk(sai_mirror_session_congestion_mode_t congestion_mode,
                                                          sx_span_cng_mng_t                   *sx_congestion_mode)
{
    assert(sx_congestion_mode);

    switch (congestion_mode) {
    case SAI_MIRROR_SESSION_CONGESTION_MODE_INDEPENDENT:
        *sx_congestion_mode = SX_SPAN_CNG_MNG_DISCARD;
        break;

    case SAI_MIRROR_SESSION_CONGESTION_MODE_CORRELATED:
        *sx_congestion_mode = SX_SPAN_CNG_MNG_DONT_DISCARD;
        break;

    default:
        SX_LOG_ERR("Invalid congestion mode %d\n", congestion_mode);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/* Calls to this function should be guarded by lock */
static sai_status_t mlnx_delete_mirror_analyzer_port(_In_ sx_span_session_id_t sdk_mirror_obj_id)
{
    sai_status_t                   status = SAI_STATUS_FAILURE;
    sx_port_log_id_t               sdk_analyzer_port;
    sx_span_analyzer_port_params_t sdk_analyzer_port_params;
    mlnx_port_config_t            *port_config = NULL;

    memset(&sdk_analyzer_port_params, 0, sizeof(sx_span_analyzer_port_params_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = sdk_to_sai(sx_api_span_session_analyzer_get(gh_sdk, sdk_mirror_obj_id, &sdk_analyzer_port)))) {
        SX_LOG_ERR("Error getting analyzer port from sdk mirror obj id: %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = sdk_to_sai(sx_api_span_session_state_set(gh_sdk, sdk_mirror_obj_id, false)))) {
        SX_LOG_ERR("Error disabling mirror session state during setting sdk analyzer port, sdk mirror obj id: %d\n",
                   sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    sdk_analyzer_port_params.cng_mng = SX_SPAN_CNG_MNG_DISCARD;

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_analyzer_set(gh_sdk, SX_ACCESS_CMD_DELETE, sdk_analyzer_port,
                                                 &sdk_analyzer_port_params,
                                                 sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error deleting sdk analyzer port %d for sdk mirror obj id: %d\n",
                   sdk_analyzer_port,
                   sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_port_by_log_id(sdk_analyzer_port, &port_config);
    if (SAI_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Error getting port config from port log id 0x%x\n", sdk_analyzer_port);
        SX_LOG_EXIT();
        return status;
    }
    port_config->is_span_analyzer_port = false;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Calls to this function should be guarded by lock */
static sai_status_t mlnx_add_mirror_analyzer_port_impl(_In_ sx_span_session_id_t sx_mirror_session_id,
                                                       _In_ sx_port_log_id_t     analyzer_log_port,
                                                       _In_ sx_span_cng_mng_t    congestion_mode)
{
    sai_status_t                   status;
    sx_status_t                    sx_status;
    sx_span_analyzer_port_params_t sdk_analyzer_port_params;
    mlnx_port_config_t            *port_config = NULL;

    memset(&sdk_analyzer_port_params, 0, sizeof(sx_span_analyzer_port_params_t));
    SX_LOG_ENTER();

    sdk_analyzer_port_params.cng_mng = congestion_mode;

    sx_status = sx_api_span_analyzer_set(gh_sdk, SX_ACCESS_CMD_ADD, analyzer_log_port, &sdk_analyzer_port_params,
                                         sx_mirror_session_id);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error setting sdk analyzer port id %x on sdk mirror session id %x\n", analyzer_log_port,
                   sx_mirror_session_id);
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_span_session_state_set(gh_sdk, sx_mirror_session_id, true);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error enabling mirror session state during setting analyzer port, sdk mirror session id: %d\n",
                   sx_mirror_session_id);
        return sdk_to_sai(sx_status);
    }

    status = mlnx_port_by_log_id(analyzer_log_port, &port_config);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error getting port config from port log id 0x%x\n", analyzer_log_port);
        return status;
    }

    port_config->is_span_analyzer_port = true;

    return status;
}

/* Calls to this function should be guarded by lock */
static sai_status_t mlnx_add_mirror_analyzer_port(_In_ sx_span_session_id_t                 sdk_mirror_obj_id,
                                                  _In_ sai_object_id_t                      sai_analyzer_port_id,
                                                  _In_ sai_mirror_session_congestion_mode_t congestion_mode)
{
    sai_status_t      status = SAI_STATUS_FAILURE;
    uint32_t          sdk_analyzer_port_id = 0;
    sx_span_cng_mng_t sx_congestion_mode;

    SX_LOG_ENTER();

    status = mlnx_object_to_log_port(sai_analyzer_port_id, &sdk_analyzer_port_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid sai analyzer port id %" PRIx64 "\n", sai_analyzer_port_id);
        SX_LOG_EXIT();
        return status;
    }

    status = mlnx_translate_congestion_mode_to_sdk(congestion_mode, &sx_congestion_mode);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate congestion mode to SDK\n");
        return status;
    }

    status = mlnx_add_mirror_analyzer_port_impl(sdk_mirror_obj_id, sdk_analyzer_port_id, sx_congestion_mode);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to set mirror analyzer port to SDK\n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_monitor_port_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg)
{
    uint32_t     sdk_mirror_obj_id_u32 = 0;
    sai_status_t status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    sai_db_write_lock();

    if (MIRROR_CONGESTION_MODE_UNINITIALIZED(g_sai_db_ptr->mirror_congestion_mode[sdk_mirror_obj_id_u32])) {
        SX_LOG_ERR("Invalid congestion mode\n");
        sai_db_unlock();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_delete_mirror_analyzer_port((sx_span_session_id_t)sdk_mirror_obj_id_u32))) {
        sai_db_unlock();
        SX_LOG_ERR("Error deleting mirror analyzer port on sdk mirror obj id %d\n", sdk_mirror_obj_id_u32);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_add_mirror_analyzer_port((sx_span_session_id_t)sdk_mirror_obj_id_u32, value->oid,
                                           g_sai_db_ptr->mirror_congestion_mode[sdk_mirror_obj_id_u32]))) {
        sai_db_unlock();
        SX_LOG_ERR("Error adding mirror analyzer port %" PRIx64 " on sdk mirror obj id %d\n",
                   value->oid,
                   sdk_mirror_obj_id_u32);
        SX_LOG_EXIT();
        return status;
    }

    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_truncate_size_set(_In_ const sai_object_key_t      *key,
                                                          _In_ const sai_attribute_value_t *value,
                                                          void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    /* Min size SPC1 32, SPC2 48 bytes */
    if (0 == value->u16) {
        sdk_mirror_obj_params.truncate = false;
        sdk_mirror_obj_params.truncate_size = 0;
    } else {
        sdk_mirror_obj_params.truncate = true;
        sdk_mirror_obj_params.truncate_size = value->u16;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_tc_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_LOCAL_ETH_TYPE1:
        sdk_mirror_obj_params.span_type_format.local_eth_type1.switch_prio = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.switch_prio = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.switch_prio = value->u8;
        break;

    default:
        SX_LOG_ERR("Error: mirror type should be either SPAN or RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_tpid_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MLNX_MIRROR_VLAN_TPID != value->u16) {
            SX_LOG_ERR("VLAN TPID must be %x on set\n", MLNX_MIRROR_VLAN_TPID);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u16;
        }
        sai_db_write_lock();

        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN ID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sai_db_unlock();
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        if (MLNX_MIRROR_VLAN_TPID != value->u16) {
            SX_LOG_ERR("VLAN TPID must be %x on set\n", MLNX_MIRROR_VLAN_TPID);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u16;
        }
        break;

    default:
        SX_LOG_ERR("Error: VLAN tpid is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_id_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        if (MLNX_VLAN_ID_WHEN_TP_DISABLED == value->u16) {
            SX_LOG_ERR("VLAN ID cannot be %d for RSPAN on set\n", MLNX_VLAN_ID_WHEN_TP_DISABLED);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u16;
        }
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.vid = value->u16;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_write_lock();
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id = value->u16;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN ID in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }

        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid = value->u16;
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        sai_db_unlock();
        break;

    default:
        SX_LOG_ERR("Error: VLAN id is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_pri_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (MIRROR_VLAN_PRI_MAX < value->u8) {
        SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n", MIRROR_VLAN_PRI_MAX, value->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u8;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.pcp = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_write_lock();
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri = value->u8;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN PRI in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp = value->u8;
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        sai_db_unlock();
        break;

    default:
        SX_LOG_ERR("Error: VLAN pri is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_cfi_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (MIRROR_VLAN_CFI_MAX < value->u8) {
        SX_LOG_ERR("Error: VLAN cfi should be at most %d but getting %d\n", MIRROR_VLAN_CFI_MAX, value->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u8;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.dei = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_write_lock();
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi = value->u8;
        if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid) {
            assert(0 == sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid);
            SX_LOG_WRN("Need to set vlan header valid to true to update VLAN CFI in packet for ERSPAN \n");
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei = value->u8;
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        sai_db_unlock();
        break;

    default:
        SX_LOG_ERR("Error: VLAN cfi is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sai mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_vlan_header_valid_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sai_db_write_lock();
        if (g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid && !value->booldata) {
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid = 0;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_DISABLE;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp = 0;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei = 0;
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id = 0;
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri = 0;
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi = 0;
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid = false;
        } else if (!g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid && value->booldata) {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid = true;
            if (0 == g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id) {
                sai_db_unlock();
                SX_LOG_WRN("vlan id is still 0 for ERSPAN session\n");
                SX_LOG_EXIT();
                return SAI_STATUS_SUCCESS;
            }
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid =
                g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp =
                g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri;
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei =
                g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi;
        } else {
            sai_db_unlock();
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
        sai_db_unlock();
        break;

    default:
        SX_LOG_ERR("Error: VLAN cfi is only valid for RSPAN or ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sai mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_tos_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dscp =
            (value->u8 >> DSCP_OFFSET) & DSCP_MASK_AFTER_SHIFT;
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ecn = value->u8 & ~DSCP_MASK;
        SX_LOG_NTC("SAI TOS: %d, SDK DSCP: %d, SDK ECN: %d\n", value->u8,
                   sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dscp,
                   sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ecn);
        break;

    default:
        SX_LOG_ERR("Error: TOS is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror session id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_ttl_set(_In_ const sai_object_key_t      *key,
                                                _In_ const sai_attribute_value_t *value,
                                                void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.ttl = value->u8;
        break;

    default:
        SX_LOG_ERR("Error: TTL is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror session id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_check_mirror_ip_family(_In_ sai_ip_addr_family_t sai_ip_family,
                                                _In_ sx_ip_version_t      sdk_ip_version)
{
    switch (sai_ip_family) {
    case SAI_IP_ADDR_FAMILY_IPV4:
        if (SX_IP_VERSION_IPV4 != sdk_ip_version) {
            SX_LOG_ERR("IP version of existing sdk ip address is 6 but new sai ip address is 4\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    case SAI_IP_ADDR_FAMILY_IPV6:
        if (SX_IP_VERSION_IPV6 != sdk_ip_version) {
            SX_LOG_ERR("IP version of existing sdk ip address is 4 but new sai ip address is 6\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        break;

    default:
        SX_LOG_ERR("Wrong IP address family %d on set\n", sai_ip_family);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_ip_address_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_ip_version_t          sdk_ip_version_to_check = SX_IP_VERSION_IPV4;
    sx_ip_addr_t            *sdk_ip_address = NULL;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    assert((MIRROR_SRC_IP_ADDRESS == (long)arg) || (MIRROR_DST_IP_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MIRROR_SRC_IP_ADDRESS == (long)arg) {
            sdk_ip_version_to_check = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip.version;
            sdk_ip_address = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.src_ip;
        } else if (MIRROR_DST_IP_ADDRESS == (long)arg) {
            sdk_ip_version_to_check = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.src_ip.version;
            sdk_ip_address = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_check_mirror_ip_family(value->ipaddr.addr_family, sdk_ip_version_to_check))) {
            SX_LOG_ERR("Error: SAI IP address family does not match SDK IP address family\n");
            SX_LOG_EXIT();
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_ip_address_to_sdk(&value->ipaddr, sdk_ip_address))) {
            SX_LOG_ERR("Error: IP address should only be IPv4 or IPv6\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Error: IP address is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_mac_address_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    assert((MIRROR_SRC_MAC_ADDRESS == (long)arg) || (MIRROR_DST_MAC_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MIRROR_SRC_MAC_ADDRESS == (long)arg) {
            memcpy(sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.smac.ether_addr_octet,
                   value->mac,
                   sizeof(value->mac));
        } else if (MIRROR_DST_MAC_ADDRESS == (long)arg) {
            memcpy(sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.mac.ether_addr_octet, value->mac,
                   sizeof(value->mac));
        }
        break;

    default:
        SX_LOG_ERR("Error: mac address is only valid for ERSPAN, but getting %d\n", sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_EDIT, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting span session for sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_gre_protocol_type_set(_In_ const sai_object_key_t      *key,
                                                              _In_ const sai_attribute_value_t *value,
                                                              void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->key.object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MLNX_GRE_PROTOCOL_TYPE != value->u16) {
            SX_LOG_ERR("GRE protocol type must be %x on set but the given value is %x\n",
                       MLNX_GRE_PROTOCOL_TYPE,
                       value->u16);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u16;
        }
        break;

    default:
        SX_LOG_ERR("Error: GRE protocol type is only valid for ERSPAN, but getting %d\n",
                   sdk_mirror_obj_params.span_type);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_policer_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    sai_status_t    status = SAI_STATUS_FAILURE;
    uint32_t        sdk_mirror_obj_id = 0;
    sai_object_id_t prev_policer;

    SX_LOG_ENTER();

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (sdk_mirror_obj_id >= SPAN_SESSION_MAX) {
        SX_LOG_ERR("Invalid sdk_mirror_obj_id %d > %d\n", sdk_mirror_obj_id, SPAN_SESSION_MAX);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_write_lock();

    if (value->oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_mirror_policer_validate(value->oid);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    if (g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid == value->oid) {
        status = SAI_STATUS_SUCCESS;
        goto out;
    }

    prev_policer = g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid;
    g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid = value->oid;

    if (mlnx_chip_is_spc()) {
        status = mlnx_acl_mirror_action_policer_update(sdk_mirror_obj_id);
        if (SAI_ERR(status)) {
            SX_LOG_NTC("Failed to update policer for mirror session %lx that is used in ACL\n", key->key.object_id);
            goto out;
        }
    } else {
        status = mlnx_sai_update_span_session_policer(sdk_mirror_obj_id,
                                                      prev_policer,
                                                      value->oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update span session policer. Span session id - %d, policer - 0x%" PRIx64 "\n",
                       sdk_mirror_obj_id, value->oid);
            goto out;
        }
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_mirror_session_congestion_mode_set(_In_ const sai_object_key_t      *key,
                                                            _In_ const sai_attribute_value_t *value,
                                                            void                             *arg)
{
    sai_status_t      status;
    sx_status_t       sx_status;
    sx_port_log_id_t  analyzer_log_port;
    sx_span_cng_mng_t sx_congestion_mode;
    uint32_t          sx_mirror_session_id = 0;

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sx_mirror_session_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        return status;
    }

    sx_status = sx_api_span_session_analyzer_get(gh_sdk, (sx_span_session_id_t)sx_mirror_session_id,
                                                 &analyzer_log_port);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Error getting analyzer port from sdk mirror obj id %d\n", sx_mirror_session_id);
        return sdk_to_sai(sx_status);
    }

    sai_db_write_lock();

    if (MIRROR_CONGESTION_MODE_UNINITIALIZED(g_sai_db_ptr->mirror_congestion_mode[sx_mirror_session_id])) {
        SX_LOG_ERR("Congestion mode uninitialized\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    status = mlnx_translate_congestion_mode_to_sdk(value->u8, &sx_congestion_mode);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to translate congestion mode to SDK\n");
        goto out;
    }

    status = mlnx_delete_mirror_analyzer_port((sx_span_session_id_t)sx_mirror_session_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to delete mirror analyzer port\n");
        goto out;
    }

    status = mlnx_add_mirror_analyzer_port_impl((sx_span_session_id_t)sx_mirror_session_id, analyzer_log_port,
                                                sx_congestion_mode);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add mirror analyzer port\n");
        goto out;
    }

    g_sai_db_ptr->mirror_congestion_mode[sx_mirror_session_id] = value->u8;
out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_mirror_session_congestion_mode_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg)
{
    sai_status_t status;
    uint32_t     sx_mirror_session_id;

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sx_mirror_session_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        return status;
    }

    sai_db_read_lock();

    if (MIRROR_CONGESTION_MODE_UNINITIALIZED(g_sai_db_ptr->mirror_congestion_mode[sx_mirror_session_id])) {
        SX_LOG_ERR("Invalid mirror session - congestion mode uninitialized\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    value->u8 = g_sai_db_ptr->mirror_congestion_mode[sx_mirror_session_id];

out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_mirror_session_sample_rate_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t status;
    uint32_t     sx_mirror_session_id;

    SX_LOG_ENTER();

    if (mlnx_chip_is_spc()) {
        SX_LOG_ERR("Mirror sample rate is not supported for SCP1\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sx_mirror_session_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        return status;
    }

    if (sx_mirror_session_id >= SPAN_SESSION_MAX) {
        SX_LOG_ERR("Invalid mirror session id %d\n", sx_mirror_session_id);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    if (value->u32 > MLNX_MIRROR_SAMPLE_RATE_MAX) {
        SX_LOG_ERR("Sample rate %d is higher than maximum %d\n", value->u32, MLNX_MIRROR_SAMPLE_RATE_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_db_write_lock();
    if (value->u32 == g_sai_db_ptr->mirror_sample_rate[sx_mirror_session_id]) {
        goto out;
    }

    status = mlnx_acl_mirror_action_sample_rate_update(sx_mirror_session_id, value->u32);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update acl mirror sample rate for sx_span_session_id %d\n", sx_mirror_session_id);
        goto out;
    }

    g_sai_db_ptr->mirror_sample_rate[sx_mirror_session_id] = value->u32;

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_mirror_session_sample_rate_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t status;
    uint32_t     sx_mirror_session_id = 0;

    SX_LOG_ENTER();

    if (mlnx_chip_is_spc()) {
        SX_LOG_ERR("Mirror sample rate is not supported for SCP1\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sx_mirror_session_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid mirror session id %" PRIx64 "\n", key->key.object_id);
        return status;
    }

    if (sx_mirror_session_id >= SPAN_SESSION_MAX) {
        SX_LOG_ERR("Invalid mirror session id %d\n", sx_mirror_session_id);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_read_lock();

    value->u32 = g_sai_db_ptr->mirror_sample_rate[sx_mirror_session_id];

    sai_db_unlock();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_check_mirror_single_attribute_on_create(
    _In_ bool                          is_valid_mirror_type,
    _In_ uint32_t                      attr_count,
    _In_ const sai_attribute_t        *attr_list,
    _In_ sai_mirror_session_attr_t     attr_id,
    _In_ const char                   *attr_str,
    _In_ const char                   *valid_mirror_type_str,
    _In_ const sai_attribute_value_t **attr_value,
    _In_ bool                          is_mandatory,
    _In_ uint32_t                     *attr_index)
{
    sai_status_t status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    status = find_attrib_in_list(attr_count, attr_list, attr_id, attr_value, attr_index);

    if (is_mandatory && is_valid_mirror_type && (SAI_STATUS_SUCCESS != status)) {
        SX_LOG_ERR("Missing mandatory attribute %s on create\n", attr_str);
        SX_LOG_EXIT();
        return status;
    } else if (!is_valid_mirror_type && (SAI_STATUS_SUCCESS == status)) {
        SX_LOG_ERR("%s should not be used for mirror types other than %s on create\n", attr_str,
                   valid_mirror_type_str);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + *attr_index;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_check_mirror_attribute_on_create(_In_ uint32_t                       attr_count,
                                                          _In_ const sai_attribute_t         *attr_list,
                                                          _Out_ const sai_attribute_value_t **mirror_type,
                                                          _Out_ const sai_attribute_value_t **mirror_monitor_port,
                                                          _Out_ const sai_attribute_value_t **mirror_truncate_size,
                                                          _Out_ sai_status_t                 *status_truncate_size,
                                                          _Out_ const sai_attribute_value_t **mirror_tc,
                                                          _Out_ sai_status_t                 *status_tc,
                                                          _Out_ const sai_attribute_value_t **mirror_vlan_tpid,
                                                          _Out_ const sai_attribute_value_t **mirror_vlan_id,
                                                          _Out_ const sai_attribute_value_t **mirror_vlan_pri,
                                                          _Out_ const sai_attribute_value_t **mirror_vlan_cfi,
                                                          _Out_ const sai_attribute_value_t **mirror_vlan_header_valid,
                                                          _Out_ const sai_attribute_value_t **mirror_encap_type,
                                                          _Out_ const sai_attribute_value_t **mirror_iphdr_version,
                                                          _Out_ const sai_attribute_value_t **mirror_tos,
                                                          _Out_ const sai_attribute_value_t **mirror_ttl,
                                                          _Out_ sai_status_t                 *status_ttl,
                                                          _Out_ const sai_attribute_value_t **mirror_src_ip_address,
                                                          _Out_ const sai_attribute_value_t **mirror_dst_ip_address,
                                                          _Out_ const sai_attribute_value_t **mirror_src_mac_address,
                                                          _Out_ const sai_attribute_value_t **mirror_dst_mac_address,
                                                          _Out_ const sai_attribute_value_t **mirror_gre_protocol_type)
{
    uint32_t     index = 0;
    bool         RSPAN_OR_ERSPAN = false;
    bool         ERSPAN = false;
    sai_status_t status = SAI_STATUS_FAILURE;
    const bool   is_mandatory = true;
    char         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_vendor_attribs,
                                         SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Mirror: metadata check failed\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_MIRROR_SESSION, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create mirror, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TYPE, mirror_type, &index);
    assert(SAI_STATUS_SUCCESS == status);

    RSPAN_OR_ERSPAN = (SAI_MIRROR_SESSION_TYPE_REMOTE == (*mirror_type)->u32) ||
                      (SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE == (*mirror_type)->u32);
    ERSPAN = SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE == (*mirror_type)->u32;

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_MIRROR_SESSION_ATTR_MONITOR_PORT,
                                 mirror_monitor_port,
                                 &index);
    assert(SAI_STATUS_SUCCESS == status);

    *status_truncate_size = find_attrib_in_list(attr_count,
                                                attr_list,
                                                SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE,
                                                mirror_truncate_size,
                                                &index);

    *status_tc = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TC, mirror_tc, &index);

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_TPID,
                                                          "Vlan TPID",    "RSPAN or ERSPAN", mirror_vlan_tpid,
                                                          !is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Vlan TPID on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                                          "Vlan ID",  "RSPAN or ERSPAN", mirror_vlan_id,
                                                          !is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Vlan ID on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_PRI,
                                                          "Vlan PRI", "RSPAN or ERSPAN", mirror_vlan_pri,
                                                          !is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Vlan PRI on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_CFI,
                                                          "Vlan CFI", "RSPAN or ERSPAN", mirror_vlan_cfi,
                                                          !is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Vlan CFI on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID,
                                                          "Vlan header valid", "ERSPAN", mirror_vlan_header_valid,
                                                          !is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Vlan header valid on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE,
                                                          "Encapsulate type", "ERSPAN", mirror_encap_type,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking Encapsulate type on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION,
                                                          "IP header version", "ERSPAN", mirror_iphdr_version,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking IP header version on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TOS,
                                                          "TOS", "ERSPAN", mirror_tos,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking TOS on create\n");
        SX_LOG_EXIT();
        return status;
    }

    *status_ttl = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TTL, mirror_ttl, &index);

    if (!ERSPAN && (SAI_STATUS_SUCCESS == *status_ttl)) {
        SX_LOG_ERR("TTL should not be used for mirror types other than ERSPAN on create\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + index;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS,
                                                          "SRC IP address", "ERSPAN", mirror_src_ip_address,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking SRC IP address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS,
                                                          "DST IP address", "ERSPAN", mirror_dst_ip_address,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking DST IP address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS,
                                                          "SRC MAC address", "ERSPAN", mirror_src_mac_address,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking SRC MAC address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS,
                                                          "DST MAC address", "ERSPAN", mirror_dst_mac_address,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking DST MAC address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE,
                                                          "GRE protocol type", "ERSPAN", mirror_gre_protocol_type,
                                                          is_mandatory, &index))) {
        SX_LOG_ERR("Error checking GRE protocol type on create\n");
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_SPAN_session_param(_Out_ sx_span_session_params_t   *sdk_mirror_obj_params,
                                                _In_ const sai_attribute_value_t *mirror_tc,
                                                _In_ sai_status_t                 status_tc)
{
    SX_LOG_ENTER();

    sdk_mirror_obj_params->span_type = SX_SPAN_TYPE_LOCAL_ETH_TYPE1;
    sdk_mirror_obj_params->span_type_format.local_eth_type1.qos_mode = SX_SPAN_QOS_CONFIGURED;
    if (SAI_STATUS_SUCCESS == status_tc) {
        sdk_mirror_obj_params->span_type_format.local_eth_type1.switch_prio = mirror_tc->u8;
    } else {
        sdk_mirror_obj_params->span_type_format.local_eth_type1.switch_prio = MLNX_MIRROR_DEFAULT_SWITCH_PRIO;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_RSPAN_session_param(_Out_ sx_span_session_params_t   *sdk_mirror_obj_params,
                                                 _In_ const sai_attribute_value_t *mirror_tc,
                                                 _In_ sai_status_t                 status_tc,
                                                 _In_ const sai_attribute_value_t *mirror_vlan_tpid,
                                                 _In_ const sai_attribute_value_t *mirror_vlan_id,
                                                 _In_ const sai_attribute_value_t *mirror_vlan_pri,
                                                 _In_ const sai_attribute_value_t *mirror_vlan_cfi)
{
    uint16_t vlan_tpid = 0;
    uint8_t  vlan_pri = 0;
    uint8_t  vlan_cfi = 0;

    SX_LOG_ENTER();

    sdk_mirror_obj_params->span_type = SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1;
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.qos_mode = SX_SPAN_QOS_CONFIGURED;
    if (SAI_STATUS_SUCCESS == status_tc) {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.switch_prio = mirror_tc->u8;
    } else {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.switch_prio = MLNX_MIRROR_DEFAULT_SWITCH_PRIO;
    }

    if (NULL != mirror_vlan_id) {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.vid = mirror_vlan_id->u16;
    } else {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.vid = 0;
    }

    if (NULL != mirror_vlan_tpid) {
        vlan_tpid = mirror_vlan_tpid->u16;
    } else {
        vlan_tpid = MLNX_MIRROR_VLAN_TPID;
    }
    if (MLNX_MIRROR_VLAN_TPID != vlan_tpid) {
        SX_LOG_ERR("VLAN TPID must be %x on create, but getting %x\n", MLNX_MIRROR_VLAN_TPID, vlan_tpid);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_tpid;
    }

    if (NULL != mirror_vlan_pri) {
        vlan_pri = mirror_vlan_pri->u8;
    } else {
        vlan_pri = 0;
    }
    if (MIRROR_VLAN_PRI_MAX < vlan_pri) {
        SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n", MIRROR_VLAN_PRI_MAX, vlan_pri);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_pri;
    }

    if (NULL != mirror_vlan_cfi) {
        vlan_cfi = mirror_vlan_cfi->u8;
    } else {
        vlan_cfi = 0;
    }
    if (MIRROR_VLAN_CFI_MAX < vlan_cfi) {
        SX_LOG_ERR("Error: VLAN CFI should be at most %d but getting %d\n", MIRROR_VLAN_CFI_MAX, vlan_cfi);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_cfi;
    }
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.vlan_ethertype_id = MLNX_VLAN_ETHERTYPE_ID;
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.pcp = vlan_pri;
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.dei = vlan_cfi;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_ERSPAN_session_param(_Out_ sx_span_session_params_t   *sdk_mirror_obj_params,
                                                  _In_ const sai_attribute_value_t *mirror_tc,
                                                  _In_ sai_status_t                 status_tc,
                                                  _In_ const sai_attribute_value_t *mirror_vlan_tpid,
                                                  _In_ const sai_attribute_value_t *mirror_vlan_id,
                                                  _In_ const sai_attribute_value_t *mirror_vlan_pri,
                                                  _In_ const sai_attribute_value_t *mirror_vlan_cfi,
                                                  _In_ const sai_attribute_value_t *mirror_vlan_header_valid,
                                                  _In_ const sai_attribute_value_t *mirror_encap_type,
                                                  _In_ const sai_attribute_value_t *mirror_iphdr_version,
                                                  _In_ const sai_attribute_value_t *mirror_tos,
                                                  _In_ const sai_attribute_value_t *mirror_ttl,
                                                  _In_ sai_status_t                 status_ttl,
                                                  _In_ const sai_attribute_value_t *mirror_src_ip_address,
                                                  _In_ const sai_attribute_value_t *mirror_dst_ip_address,
                                                  _In_ const sai_attribute_value_t *mirror_src_mac_address,
                                                  _In_ const sai_attribute_value_t *mirror_dst_mac_address,
                                                  _In_ const sai_attribute_value_t *mirror_gre_protocol_type)
{
    sai_status_t status = SAI_STATUS_FAILURE;
    bool         vlan_header_valid = false;
    uint16_t     vlan_tpid = 0;
    uint16_t     vlan_id = 0;
    uint8_t      vlan_pri = 0;
    uint8_t      vlan_cfi = 0;

    SX_LOG_ENTER();

    if (SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL == mirror_encap_type->s32) {
        sdk_mirror_obj_params->span_type = SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.qos_mode = SX_SPAN_QOS_CONFIGURED;
        if (SAI_STATUS_SUCCESS == status_tc) {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.switch_prio = mirror_tc->u8;
        } else {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.switch_prio = MLNX_MIRROR_DEFAULT_SWITCH_PRIO;
        }
        if ((NULL == mirror_vlan_header_valid) || !mirror_vlan_header_valid->booldata) {
            vlan_header_valid = false;
        } else {
            assert(mirror_vlan_header_valid->booldata);
            vlan_header_valid = true;
        }

        if (vlan_header_valid) {
            if (NULL != mirror_vlan_tpid) {
                vlan_tpid = mirror_vlan_tpid->u16;
            } else {
                vlan_tpid = MLNX_MIRROR_VLAN_TPID;
            }
            if (NULL == mirror_vlan_id) {
                SX_LOG_ERR("Missing vlan id for ERSPAN when vlan header valid is true\n");
                SX_LOG_EXIT();
                return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            }
            if (0 == mirror_vlan_id->u16) {
                SX_LOG_ERR("Vlan id should not be 0 when vlan header valid is true\n");
                SX_LOG_EXIT();
                return SAI_STATUS_INVALID_ATTR_VALUE_0;
            }
            vlan_id = mirror_vlan_id->u16;
            if (NULL != mirror_vlan_pri) {
                vlan_pri = mirror_vlan_pri->u8;
            } else {
                vlan_pri = 0;
            }
            if (NULL != mirror_vlan_cfi) {
                vlan_cfi = mirror_vlan_cfi->u8;
            } else {
                vlan_cfi = 0;
            }
        } else {
            if (NULL != mirror_vlan_tpid) {
                SX_LOG_ERR("VLAN tpid is not valid when vlan header valid is false\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            if (NULL != mirror_vlan_id) {
                SX_LOG_ERR("VLAN id is not valid when vlan header valid is false\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            if (NULL != mirror_vlan_pri) {
                SX_LOG_ERR("VLAN pri is not valid when vlan header valid is false\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            if (NULL != mirror_vlan_cfi) {
                SX_LOG_ERR("VLAN cfi is not valid when vlan header valid is false\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            vlan_tpid = MLNX_MIRROR_VLAN_TPID;
            vlan_id = 0;
            vlan_pri = 0;
            vlan_cfi = 0;
        }
        if (MLNX_VLAN_ID_WHEN_TP_DISABLED == vlan_id) {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_DISABLE;
        } else {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        }
        if (MLNX_MIRROR_VLAN_TPID != vlan_tpid) {
            SX_LOG_ERR("VLAN TPID must be %x on create, but getting %x\n", MLNX_MIRROR_VLAN_TPID,
                       mirror_vlan_tpid->u16);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_tpid;
        }
        if (MIRROR_VLAN_PRI_MAX < vlan_pri) {
            SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n",
                       MIRROR_VLAN_PRI_MAX,
                       mirror_vlan_pri->u8);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_pri;
        }
        if (MIRROR_VLAN_CFI_MAX < vlan_cfi) {
            SX_LOG_ERR("Error: VLAN CFI should be at most %d but getting %d\n",
                       MIRROR_VLAN_CFI_MAX,
                       mirror_vlan_cfi->u8);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + vlan_cfi;
        }
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.vid = vlan_id;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.vlan_ethertype_id = MLNX_VLAN_ETHERTYPE_ID;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.pcp = vlan_pri;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.dei = vlan_cfi;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.dscp =
            (mirror_tos->u8 >> DSCP_OFFSET) & DSCP_MASK_AFTER_SHIFT;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.ecn = mirror_tos->u8 & ~DSCP_MASK;
        SX_LOG_NTC("SAI TOS: %d, SDK DSCP: %d, SDK ECN: %d\n", mirror_tos->u8,
                   sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.dscp,
                   sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.ecn);
        if (SAI_STATUS_SUCCESS == status_ttl) {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.ttl = mirror_ttl->u8;
        }
        memcpy(sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.mac.ether_addr_octet,
               mirror_dst_mac_address->mac,
               sizeof(mirror_dst_mac_address->mac));
        memcpy(sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.smac.ether_addr_octet,
               mirror_src_mac_address->mac,
               sizeof(mirror_src_mac_address->mac));
        if (IPV4_HEADER_VERSION == mirror_iphdr_version->u8) {
            if (SAI_IP_ADDR_FAMILY_IPV4 != mirror_dst_ip_address->ipaddr.addr_family) {
                SX_LOG_ERR("DST IP address must be IPv4\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            if (SAI_IP_ADDR_FAMILY_IPV4 != mirror_src_ip_address->ipaddr.addr_family) {
                SX_LOG_ERR("SRC IP address must be IPv4\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
        } else if (IPV6_HEADER_VERSION == mirror_iphdr_version->u8) {
            if (SAI_IP_ADDR_FAMILY_IPV6 != mirror_dst_ip_address->ipaddr.addr_family) {
                SX_LOG_ERR("DST IP address must be IPv6\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
            if (SAI_IP_ADDR_FAMILY_IPV6 != mirror_src_ip_address->ipaddr.addr_family) {
                SX_LOG_ERR("SRC IP address must be IPv6\n");
                SX_LOG_EXIT();
                return SAI_STATUS_FAILURE;
            }
        } else {
            SX_LOG_ERR("IP header must be either 4 or 6 on create\n");
            SX_LOG_EXIT();
            return SAI_STATUS_FAILURE;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_ip_address_to_sdk(&mirror_dst_ip_address->ipaddr,
                                                           &sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1
                                                           .dest_ip))) {
            SX_LOG_ERR("Error: DST IP address should only be IPv4 or IPv6\n");
            SX_LOG_EXIT();
            return status;
        }
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_translate_sai_ip_address_to_sdk(&mirror_src_ip_address->ipaddr,
                                                           &sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1
                                                           .src_ip))) {
            SX_LOG_ERR("Error: SRC IP address should only be IPv4 or IPv6\n");
            SX_LOG_EXIT();
            return status;
        }
        if (MLNX_GRE_PROTOCOL_TYPE != mirror_gre_protocol_type->u16) {
            SX_LOG_ERR("GRE protocol type must be %x on create, but getting %x\n",
                       MLNX_GRE_PROTOCOL_TYPE,
                       mirror_gre_protocol_type->u16);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_gre_protocol_type->u16;
        }
    } else {
        SX_LOG_ERR("Unsupported mirror encapsulate type %d\n", mirror_encap_type->s32);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_encap_type->s32;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_mirror_session(_Out_ sai_object_id_t      *sai_mirror_obj_id,
                                               _In_ sai_object_id_t        switch_id,
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *mirror_type = NULL, *mirror_monitor_port = NULL, *mirror_truncate_size =
        NULL, *mirror_tc = NULL;
    const sai_attribute_value_t *mirror_vlan_tpid = NULL, *mirror_vlan_id = NULL, *mirror_vlan_pri = NULL,
                                *mirror_vlan_cfi = NULL;
    const sai_attribute_value_t *mirror_vlan_header_valid = NULL;
    const sai_attribute_value_t *mirror_encap_type = NULL, *mirror_iphdr_version = NULL, *mirror_tos = NULL,
                                *mirror_ttl = NULL;
    const sai_attribute_value_t *mirror_src_ip_address = NULL, *mirror_dst_ip_address = NULL;
    const sai_attribute_value_t *mirror_src_mac_address = NULL, *mirror_dst_mac_address = NULL;
    const sai_attribute_value_t *mirror_gre_protocol_type = NULL;
    const sai_attribute_value_t *mirror_policer = NULL;
    const sai_attribute_value_t *congestion_mode_attr = NULL;
    const sai_attribute_value_t *sample_rate_attr = NULL;
    sai_status_t                 status = SAI_STATUS_FAILURE, status_truncate_size =
        SAI_STATUS_FAILURE;
    sai_status_t                         status_tc = SAI_STATUS_FAILURE, status_ttl = SAI_STATUS_FAILURE;
    sai_status_t                         status_remove = SAI_STATUS_FAILURE;
    sx_span_session_params_t             sdk_mirror_obj_params;
    sx_span_session_id_t                 sdk_mirror_obj_id = 0;
    bool                                 is_span_session_created = false, is_port_analyzer_added = false;
    bool                                 is_policer_bound = false;
    sai_object_id_t                      policer_oid = SAI_NULL_OBJECT_ID;
    uint32_t                             policer_attr_idx;
    uint32_t                             congestion_mode_idx;
    sai_mirror_session_congestion_mode_t congestion_mode;
    uint32_t                             sample_rate_idx;
    uint32_t                             sample_rate = MLNX_MIRROR_SAMPLE_RATE_DISABLE_SAMPLING;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_check_mirror_attribute_on_create(attr_count, attr_list,
                                                        &mirror_type, &mirror_monitor_port,
                                                        &mirror_truncate_size, &status_truncate_size,
                                                        &mirror_tc, &status_tc,
                                                        &mirror_vlan_tpid, &mirror_vlan_id, &mirror_vlan_pri,
                                                        &mirror_vlan_cfi,
                                                        &mirror_vlan_header_valid,
                                                        &mirror_encap_type, &mirror_iphdr_version, &mirror_tos,
                                                        &mirror_ttl, &status_ttl,
                                                        &mirror_src_ip_address, &mirror_dst_ip_address,
                                                        &mirror_src_mac_address, &mirror_dst_mac_address,
                                                        &mirror_gre_protocol_type))) {
        SX_LOG_ERR("Error checking mirror attributes on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if ((SAI_STATUS_SUCCESS != status_truncate_size) || (0 == mirror_truncate_size->u16)) {
        sdk_mirror_obj_params.truncate = false;
        sdk_mirror_obj_params.truncate_size = 0;
    } else {
        sdk_mirror_obj_params.truncate = true;
        sdk_mirror_obj_params.truncate_size = mirror_truncate_size->u16;
    }

    switch (mirror_type->s32) {
    case SAI_MIRROR_SESSION_TYPE_LOCAL:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_set_SPAN_session_param(&sdk_mirror_obj_params,
                                                  mirror_tc, status_tc))) {
            SX_LOG_ERR("Error setting SPAN session parameters on create\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    case SAI_MIRROR_SESSION_TYPE_REMOTE:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_set_RSPAN_session_param(&sdk_mirror_obj_params,
                                                   mirror_tc, status_tc,
                                                   mirror_vlan_tpid, mirror_vlan_id, mirror_vlan_pri,
                                                   mirror_vlan_cfi))) {
            SX_LOG_ERR("Error setting RSPAN session parameters on create\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    case SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_set_ERSPAN_session_param(&sdk_mirror_obj_params,
                                                    mirror_tc, status_tc,
                                                    mirror_vlan_tpid, mirror_vlan_id, mirror_vlan_pri, mirror_vlan_cfi,
                                                    mirror_vlan_header_valid,
                                                    mirror_encap_type, mirror_iphdr_version, mirror_tos, mirror_ttl,
                                                    status_ttl,
                                                    mirror_src_ip_address, mirror_dst_ip_address,
                                                    mirror_src_mac_address, mirror_dst_mac_address,
                                                    mirror_gre_protocol_type))) {
            SX_LOG_ERR("Error setting ERSPAN session parameters on create\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Unsupported mirror type\n");
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }

    find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_POLICER, &mirror_policer, &policer_attr_idx);
    if (mirror_policer) {
        policer_oid = mirror_policer->oid;
    }

    sai_db_write_lock();

    if (policer_oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_mirror_policer_validate(policer_oid);
        if (SAI_ERR(status)) {
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + policer_attr_idx;
            goto out;
        }
    }

    status = sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_mirror_obj_params, &sdk_mirror_obj_id);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Error creating mirror session - %s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }
    is_span_session_created = true;

    status = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE, &congestion_mode_attr,
                                 &congestion_mode_idx);
    if (SAI_OK(status)) {
        congestion_mode = congestion_mode_attr->u8;
    } else if (status == SAI_STATUS_ITEM_NOT_FOUND) {
        congestion_mode = SAI_MIRROR_SESSION_CONGESTION_MODE_INDEPENDENT;
    } else {
        SX_LOG_ERR("Failed to find congestion mode attribute\n");
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, &sample_rate_attr,
                                 &sample_rate_idx);
    if (SAI_OK(status)) {
        if (mlnx_chip_is_spc()) {
            SX_LOG_ERR("Mirror sample rate is not supported for SCP1\n");
            status = SAI_STATUS_NOT_SUPPORTED;
            goto out;
        }

        if (sample_rate_attr->u32 > MLNX_MIRROR_SAMPLE_RATE_MAX) {
            SX_LOG_ERR("Sample rate %d is higher than maximum %d\n", sample_rate_attr->u32,
                       MLNX_MIRROR_SAMPLE_RATE_MAX);
            status = SAI_STATUS_INVALID_ATTR_VALUE_0 + sample_rate_idx;
            goto out;
        }

        sample_rate = sample_rate_attr->u32;
    } else if (status != SAI_STATUS_ITEM_NOT_FOUND) {
        SX_LOG_ERR("Failed to find sample rate attribute\n");
        goto out;
    }

    status = mlnx_add_mirror_analyzer_port(sdk_mirror_obj_id, mirror_monitor_port->oid, congestion_mode);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Error adding mirror analyzer port %" PRIx64 " on sdk mirror obj id %d\n", mirror_monitor_port->oid,
                   sdk_mirror_obj_id);
        goto out;
    }
    is_port_analyzer_added = true;

    if (policer_oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_sai_update_span_session_policer(sdk_mirror_obj_id, SAI_NULL_OBJECT_ID, policer_oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update span session policer. Span session id - %d, policer - 0x%" PRIx64 "\n",
                       sdk_mirror_obj_id, policer_oid);
            goto out;
        }
        is_policer_bound = true;
    }

    SX_LOG_NTC("Created sdk mirror obj id: %d\n", sdk_mirror_obj_id);

    if ((SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE == mirror_type->s32) &&
        (NULL != mirror_vlan_header_valid) && (mirror_vlan_header_valid->booldata)) {
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid = true;
        if (NULL != mirror_vlan_id) {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id = mirror_vlan_id->u16;
        } else {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id = 0;
        }
        if (NULL != mirror_vlan_pri) {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri = mirror_vlan_pri->u8;
        } else {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri = 0;
        }
        if (NULL != mirror_vlan_cfi) {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi = mirror_vlan_cfi->u8;
        } else {
            g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi = 0;
        }
    } else {
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_header_valid = false;
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_id = 0;
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_pri = 0;
        g_sai_db_ptr->erspan_vlan_header[sdk_mirror_obj_id].vlan_cfi = 0;
    }

    g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid = policer_oid;

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, (uint32_t)sdk_mirror_obj_id, NULL,
                                sai_mirror_obj_id))) {
        SX_LOG_ERR("Error creating mirror session object\n");
        goto out;
    }

    g_sai_db_ptr->mirror_congestion_mode[sdk_mirror_obj_id] = congestion_mode;
    g_sai_db_ptr->mirror_sample_rate[sdk_mirror_obj_id] = sample_rate;

    SX_LOG_NTC("Created SAI mirror obj id: %" PRIx64 "\n", *sai_mirror_obj_id);

out:
    if (SAI_ERR(status)) {
        if (is_policer_bound) {
            status_remove = mlnx_sai_update_span_session_policer(sdk_mirror_obj_id, policer_oid, SAI_NULL_OBJECT_ID);
            if (SAI_ERR(status_remove)) {
                SX_LOG_ERR("Failed to update span session policer. Span session id - %d, policer - 0x%" PRIx64
                           " SAI status code - %d\n", sdk_mirror_obj_id, policer_oid, status_remove);
            }
        }

        if (is_port_analyzer_added) {
            status_remove = mlnx_delete_mirror_analyzer_port(sdk_mirror_obj_id);
            if (SAI_ERR(status_remove)) {
                SX_LOG_ERR("Failed to delete mirror analyzer port, sdk mirror obj id: %d, SAI status code - %d\n",
                           sdk_mirror_obj_id, status_remove);
            }
        }

        if (is_span_session_created) {
            status_remove = sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_mirror_obj_params,
                                                               &sdk_mirror_obj_id));
            if (SAI_ERR(status_remove)) {
                SX_LOG_ERR("Error destroying mirror session, sdk mirror obj id: %d, SAI status code - %d\n",
                           sdk_mirror_obj_id, status_remove);
            }
        }
    }

    sai_db_unlock();
    SX_LOG_EXIT();

    return status;
}

static sai_status_t mlnx_mirror_session_is_in_use(_In_ sx_span_session_id_t session,
                                                  _Out_ bool               *is_in_use)
{
    const mlnx_mirror_policer_t *mirror_policer;
    sx_acl_direction_t           sx_direction;

    assert(is_in_use);
    assert(session < SPAN_SESSION_MAX);

    mirror_policer = &g_sai_db_ptr->mirror_policer[session];

    for (sx_direction = SX_ACL_DIRECTION_INGRESS; sx_direction < SX_ACL_DIRECTION_LAST; sx_direction++) {
        if (mirror_policer->extra_acl[sx_direction].refs > 0) {
            SX_LOG_ERR("Mirror session %d is used in %d ACL entry(s) at SX direction %d\n",
                       sx_direction,
                       mirror_policer->extra_acl[sx_direction].refs,
                       sx_direction);
            *is_in_use = true;
            return SAI_STATUS_SUCCESS;
        }
    }

    *is_in_use = false;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_mirror_session(_In_ const sai_object_id_t sai_mirror_obj_id)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    uint32_t                 sdk_mirror_obj_id_u32 = 0;
    sai_status_t             status = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    bool                     is_in_use;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR_SESSION, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id: %" PRIx64 "\n", sai_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    sdk_mirror_obj_id = (sx_span_session_id_t)sdk_mirror_obj_id_u32;

    if (sdk_mirror_obj_id >= SPAN_SESSION_MAX) {
        SX_LOG_ERR("sai mirror obj id: %" PRIx64 " - session id %d\n", sai_mirror_obj_id, sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_db_write_lock();

    status = mlnx_mirror_session_is_in_use(sdk_mirror_obj_id, &is_in_use);
    if (SAI_ERR(status)) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return status;
    }

    if (is_in_use) {
        sai_db_unlock();
        SX_LOG_EXIT();
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid != SAI_NULL_OBJECT_ID) {
        status = mlnx_sai_update_span_session_policer(sdk_mirror_obj_id,
                                                      g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id].policer_oid,
                                                      SAI_NULL_OBJECT_ID);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unbind span session policer. Span session id - %d\n", sdk_mirror_obj_id);
            sai_db_unlock();
            SX_LOG_EXIT();
            return status;
        }
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_delete_mirror_analyzer_port(sdk_mirror_obj_id))) {
        sai_db_unlock();
        SX_LOG_ERR("Error deleting mirror analyzer port on sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    memset(&g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id], 0,
           sizeof(g_sai_db_ptr->mirror_policer[sdk_mirror_obj_id]));

    sai_db_unlock();

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error destroying mirror session, sdk mirror obj id: %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Removed SAI mirror obj id %" PRIx64 "\n", sai_mirror_obj_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_mirror_session_attribute(_In_ const sai_object_id_t  sai_mirror_obj_id,
                                                      _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = sai_mirror_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    mirror_key_to_str(sai_mirror_obj_id, key_str);

    status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_vendor_attribs, attr);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_mirror_session_attribute(_In_ const sai_object_id_t sai_mirror_obj_id,
                                                      _In_ uint32_t              attr_count,
                                                      _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .key.object_id = sai_mirror_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    mirror_key_to_str(sai_mirror_obj_id, key_str);

    status = sai_get_attributes(&key,
                                key_str,
                                SAI_OBJECT_TYPE_MIRROR_SESSION,
                                mirror_vendor_attribs,
                                attr_count,
                                attr_list);

    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_mirror_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_span_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_mirror_api_t mlnx_mirror_api = {
    mlnx_create_mirror_session,
    mlnx_remove_mirror_session,
    mlnx_set_mirror_session_attribute,
    mlnx_get_mirror_session_attribute
};
