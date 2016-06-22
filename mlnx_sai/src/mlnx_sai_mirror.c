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
#define __MODULE__ SAI_MIRROR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/* mandatory_on_create, valid_for_create, valid_for_set, valid_for_get */
static const sai_attribute_entry_t mirror_attribs[] = {
    { SAI_MIRROR_SESSION_ATTR_TYPE, true, true, false, true,
      "Mirror session attr type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, true, true, true, true,
      "Mirror session attr monitor port", SAI_ATTR_VAL_TYPE_OID },
    { SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, false, true, true, true,
      "Mirror session attr truncate size", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_MIRROR_SESSION_ATTR_TC, false, true, true, true,
      "Mirror session attr tc", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_VLAN_TPID, false, true, true, true,
      "Mirror session attr vlan tpid", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_MIRROR_SESSION_ATTR_VLAN_ID, false, true, true, true,
      "Mirror session attr vlan id", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_MIRROR_SESSION_ATTR_VLAN_PRI, false, true, true, true,
      "Mirror session attr vlan pri", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_VLAN_CFI, false, true, true, true,
      "Mirror session attr vlan cfi", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE, false, true, false, true,
      "Mirror session attr encap type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION, false, true, false, true,
      "Mirror session attr iphdr version", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_TOS, false, true, true, true,
      "Mirror session attr tos", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_TTL, false, true, true, true,
      "Mirror session attr ttl", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, false, true, true, true,
      "Mirror session attr src ip address", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, false, true, true, true,
      "Mirror session attr dst ip address", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, false, true, true, true,
      "Mirror session attr src mac address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, false, true, true, true,
      "Mirror session attr dst mac address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE, false, true, true, true,
      "Mirror session attr gre protocol type", SAI_ATTR_VAL_TYPE_U16 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
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
    { SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE,
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
};
static void mirror_key_to_str(_In_ const sai_object_id_t sai_mirror_obj_id, _Out_ char *key_str)
{
    uint32_t sdk_mirror_obj_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR, &sdk_mirror_obj_id, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid sai mirror obj ID %" PRId64 "", sai_mirror_obj_id);
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "sai mirror obj ID %" PRId64 ", sdk mirror obj ID %d",
                 sai_mirror_obj_id,
                 sdk_mirror_obj_id);
    }

    SX_LOG_EXIT();
}

static sai_status_t mlnx_get_sdk_mirror_obj_params(_In_ sai_object_id_t            sai_mirror_obj_id,
                                                   _Inout_ sx_span_session_id_t   *sdk_mirror_obj_id,
                                                   _Out_ sx_span_session_params_t *sdk_mirror_obj_params)
{
    uint32_t     sdk_mirror_obj_id_u32 = 0;
    sai_status_t status                = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id %" PRId64 "\n", sai_mirror_obj_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_LOCAL_ETH_TYPE1:
        value->s32 = SAI_MIRROR_TYPE_LOCAL;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->s32 = SAI_MIRROR_TYPE_REMOTE;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->s32 = SAI_MIRROR_TYPE_ENHANCED_REMOTE;
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
    uint32_t         sdk_mirror_obj_id    = 0;
    sai_status_t     status               = SAI_STATUS_FAILURE;
    sx_port_log_id_t sdk_analyzer_port_id = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_MIRROR, &sdk_mirror_obj_id, NULL))) {
        SX_LOG_ERR("Invalid mirror session id %" PRId64 "\n", key->object_id);
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
            (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, sdk_analyzer_port_id, NULL, &value->oid))) {
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
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

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u16 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.vid;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u16 = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid;
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

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.pcp;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp;
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

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.dei;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8 = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei;
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->s32 = SAI_MIRROR_L3_GRE_TUNNEL;
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        value->u8  = (sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dscp << DSCP_OFFSET) & DSCP_MASK;
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, NULL, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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

static sai_status_t mlnx_delete_mirror_analyzer_port(_In_ sx_span_session_id_t sdk_mirror_obj_id)
{
    sai_status_t                   status = SAI_STATUS_FAILURE;
    sx_port_log_id_t               sdk_analyzer_port;
    sx_span_analyzer_port_params_t sdk_analyzer_port_params;

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

    sdk_analyzer_port_params.cng_mng = SX_SPAN_CNG_MNG_DONT_DISCARD;

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

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_add_mirror_analyzer_port(_In_ sx_span_session_id_t sdk_mirror_obj_id,
                                                  _In_ sai_object_id_t      sai_analyzer_port_id)
{
    sai_status_t                   status               = SAI_STATUS_FAILURE;
    uint32_t                       sdk_analyzer_port_id = 0;
    sx_span_analyzer_port_params_t sdk_analyzer_port_params;

    memset(&sdk_analyzer_port_params, 0, sizeof(sx_span_analyzer_port_params_t));
    SX_LOG_ENTER();

    switch (sai_object_type_query(sai_analyzer_port_id)) {
    case SAI_OBJECT_TYPE_PORT:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(sai_analyzer_port_id, SAI_OBJECT_TYPE_PORT, &sdk_analyzer_port_id, NULL))) {
            SX_LOG_ERR("Invalid sai analyzer port id %" PRId64 "\n", sai_analyzer_port_id);
            SX_LOG_EXIT();
            return status;
        }
        break;

    case SAI_OBJECT_TYPE_LAG:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(sai_analyzer_port_id, SAI_OBJECT_TYPE_LAG, &sdk_analyzer_port_id, NULL))) {
            SX_LOG_ERR("Invalid sai analyzer port id %" PRId64 "\n", sai_analyzer_port_id);
            SX_LOG_EXIT();
            return status;
        }
        break;

    default:
        SX_LOG_ERR("Invalid sai analyzer port id %" PRId64 "\n", sai_analyzer_port_id);
        SX_LOG_EXIT();
        return status;
        break;
    }

    sdk_analyzer_port_params.cng_mng = SX_SPAN_CNG_MNG_DONT_DISCARD;

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_analyzer_set(gh_sdk, SX_ACCESS_CMD_ADD, (sx_port_log_id_t)sdk_analyzer_port_id,
                                                 &sdk_analyzer_port_params,
                                                 (sx_span_session_id_t)sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error setting sdk analyzer port id %x on sdk mirror obj id %x\n",
                   sdk_analyzer_port_id,
                   sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = sdk_to_sai(sx_api_span_session_state_set(gh_sdk, (sx_span_session_id_t)sdk_mirror_obj_id, true)))) {
        SX_LOG_ERR("Error enabling mirror session state during setting analyzer port, sdk mirror obj id: %d\n",
                   sdk_mirror_obj_id);
        SX_LOG_EXIT();
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
    sai_status_t status                = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_MIRROR, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_delete_mirror_analyzer_port((sx_span_session_id_t)sdk_mirror_obj_id_u32))) {
        SX_LOG_ERR("Error deleting mirror analyzer port on sdk mirror obj id %d\n", sdk_mirror_obj_id_u32);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_add_mirror_analyzer_port((sx_span_session_id_t)sdk_mirror_obj_id_u32, value->oid))) {
        SX_LOG_ERR("Error adding mirror analyzer port %" PRIx64 " on sdk mirror obj id %d\n",
                   value->oid,
                   sdk_mirror_obj_id_u32);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_mirror_session_truncate_size_set(_In_ const sai_object_key_t      *key,
                                                          _In_ const sai_attribute_value_t *value,
                                                          void                             *arg)
{
    sx_span_session_id_t     sdk_mirror_obj_id = 0;
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    if (0 == value->u16) {
        sdk_mirror_obj_params.truncate      = false;
        sdk_mirror_obj_params.truncate_size = 0;
    } else {
        sdk_mirror_obj_params.truncate      = true;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_LOCAL_ETH_TYPE1:
        sdk_mirror_obj_params.span_type_format.local_eth_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
        sdk_mirror_obj_params.span_type_format.local_eth_type1.switch_prio = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.switch_prio = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
        if (MLNX_VLAN_ID_WHEN_TP_DISABLED == value->u16) {
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_DISABLE;
        } else {
            sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        }
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.vid = value->u16;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (MIRROR_VLAN_PRI_MAX < value->u8) {
        SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n", MIRROR_VLAN_PRI_MAX, value->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u8;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.pcp = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.pcp = value->u8;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (MIRROR_VLAN_CFI_MAX < value->u8) {
        SX_LOG_ERR("Error: VLAN cfi should be at most %d but getting %d\n", MIRROR_VLAN_CFI_MAX, value->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + value->u8;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_vlan_type1.dei = value->u8;
        break;

    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dei = value->u8;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
    sx_span_session_id_t     sdk_mirror_obj_id       = 0;
    sai_status_t             status                  = SAI_STATUS_FAILURE;
    sx_ip_version_t          sdk_ip_version_to_check = SX_IP_VERSION_IPV4;
    sx_ip_addr_t            *sdk_ip_address          = NULL;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    assert((MIRROR_SRC_IP_ADDRESS == (long)arg) || (MIRROR_DST_IP_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
        SX_LOG_EXIT();
        return status;
    }

    switch (sdk_mirror_obj_params.span_type) {
    case SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1:
        if (MIRROR_SRC_IP_ADDRESS == (long)arg) {
            sdk_ip_version_to_check = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip.version;
            sdk_ip_address          = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.src_ip;
        } else if (MIRROR_DST_IP_ADDRESS == (long)arg) {
            sdk_ip_version_to_check = sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.src_ip.version;
            sdk_ip_address          = &sdk_mirror_obj_params.span_type_format.remote_eth_l3_type1.dest_ip;
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    assert((MIRROR_SRC_MAC_ADDRESS == (long)arg) || (MIRROR_DST_MAC_ADDRESS == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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
    sai_status_t             status            = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));
    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_get_sdk_mirror_obj_params(key->object_id, &sdk_mirror_obj_id, &sdk_mirror_obj_params))) {
        SX_LOG_ERR("Error getting mirror session params from sai mirror obj id %" PRId64 "\n", key->object_id);
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

static sai_status_t mlnx_check_mirror_single_attribute_on_create(
    _In_ bool                          is_valid_mirror_type,
    _In_ uint32_t                      attr_count,
    _In_ const sai_attribute_t        *attr_list,
    _In_ sai_mirror_session_attr_t     attr_id,
    _In_ const char                   *attr_str,
    _In_ const char                   *valid_mirror_type_str,
    _In_ const sai_attribute_value_t **attr_value,
    _In_ uint32_t                     *attr_index)
{
    sai_status_t status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    status = find_attrib_in_list(attr_count, attr_list, attr_id, attr_value, attr_index);

    if (is_valid_mirror_type && (SAI_STATUS_SUCCESS != status)) {
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
    uint32_t     index           = 0;
    bool         RSPAN_OR_ERSPAN = false;
    bool         ERSPAN          = false;
    sai_status_t status          = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = check_attribs_metadata(attr_count, attr_list, mirror_attribs, mirror_vendor_attribs,
                                         SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Mirror: metadata check failed\n");
        SX_LOG_EXIT();
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TYPE, mirror_type, &index);
    assert(SAI_STATUS_SUCCESS == status);

    RSPAN_OR_ERSPAN = (SAI_MIRROR_TYPE_REMOTE == (*mirror_type)->u32) ||
                      (SAI_MIRROR_TYPE_ENHANCED_REMOTE == (*mirror_type)->u32);
    ERSPAN = SAI_MIRROR_TYPE_ENHANCED_REMOTE == (*mirror_type)->u32;

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
                                                          &index))) {
        SX_LOG_ERR("Error checking Vlan TPID on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                                          "Vlan ID",  "RSPAN or ERSPAN", mirror_vlan_id,
                                                          &index))) {
        SX_LOG_ERR("Error checking Vlan ID on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_PRI,
                                                          "Vlan PRI", "RSPAN or ERSPAN", mirror_vlan_pri,
                                                          &index))) {
        SX_LOG_ERR("Error checking Vlan PRI on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(RSPAN_OR_ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_VLAN_CFI,
                                                          "Vlan CFI", "RSPAN or ERSPAN", mirror_vlan_cfi,
                                                          &index))) {
        SX_LOG_ERR("Error checking Vlan CFI on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE,
                                                          "Encapsulate type", "ERSPAN", mirror_encap_type,
                                                          &index))) {
        SX_LOG_ERR("Error checking Encapsulate type on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION,
                                                          "IP header version", "ERSPAN", mirror_iphdr_version,
                                                          &index))) {
        SX_LOG_ERR("Error checking IP header version on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TOS,
                                                          "TOS", "ERSPAN", mirror_tos, &index))) {
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
                                                          &index))) {
        SX_LOG_ERR("Error checking SRC IP address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS,
                                                          "DST IP address", "ERSPAN", mirror_dst_ip_address,
                                                          &index))) {
        SX_LOG_ERR("Error checking DST IP address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS,
                                                          "SRC MAC address", "ERSPAN", mirror_src_mac_address,
                                                          &index))) {
        SX_LOG_ERR("Error checking SRC MAC address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS,
                                                          "DST MAC address", "ERSPAN", mirror_dst_mac_address,
                                                          &index))) {
        SX_LOG_ERR("Error checking DST MAC address on create\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_check_mirror_single_attribute_on_create(ERSPAN, attr_count, attr_list,
                                                          SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE,
                                                          "GRE protocol type", "ERSPAN", mirror_gre_protocol_type,
                                                          &index))) {
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
    if (SAI_STATUS_SUCCESS == status_tc) {
        sdk_mirror_obj_params->span_type_format.local_eth_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
        sdk_mirror_obj_params->span_type_format.local_eth_type1.switch_prio = mirror_tc->u8;
    } else {
        sdk_mirror_obj_params->span_type_format.local_eth_type1.qos_mode    = SX_SPAN_QOS_MAINTAIN;
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
    SX_LOG_ENTER();

    sdk_mirror_obj_params->span_type = SX_SPAN_TYPE_REMOTE_ETH_VLAN_TYPE1;
    if (SAI_STATUS_SUCCESS == status_tc) {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.switch_prio = mirror_tc->u8;
    } else {
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.qos_mode    = SX_SPAN_QOS_MAINTAIN;
        sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.switch_prio = MLNX_MIRROR_DEFAULT_SWITCH_PRIO;
    }
    if (MLNX_VLAN_ID_WHEN_TP_DISABLED == mirror_vlan_id->u16) {
        SX_LOG_ERR("VLAN ID cannot be %d for RSPAN on create\n", MLNX_VLAN_ID_WHEN_TP_DISABLED);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_id->u16;
    }
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.vid = mirror_vlan_id->u16;
    if (MLNX_MIRROR_VLAN_TPID != mirror_vlan_tpid->u16) {
        SX_LOG_ERR("VLAN TPID must be %x on create, but getting %x\n", MLNX_MIRROR_VLAN_TPID, mirror_vlan_tpid->u16);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_tpid->u16;
    }
    if (MIRROR_VLAN_PRI_MAX < mirror_vlan_pri->u8) {
        SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n", MIRROR_VLAN_PRI_MAX, mirror_vlan_pri->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_pri->u8;
    }
    if (MIRROR_VLAN_CFI_MAX < mirror_vlan_cfi->u8) {
        SX_LOG_ERR("Error: VLAN CFI should be at most %d but getting %d\n", MIRROR_VLAN_CFI_MAX, mirror_vlan_cfi->u8);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_cfi->u8;
    }
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.vlan_ethertype_id = MLNX_VLAN_ETHERTYPE_ID;
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.pcp               = mirror_vlan_pri->u8;
    sdk_mirror_obj_params->span_type_format.remote_eth_vlan_type1.dei               = mirror_vlan_cfi->u8;

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

    SX_LOG_ENTER();

    if (SAI_MIRROR_L3_GRE_TUNNEL == mirror_encap_type->s32) {
        sdk_mirror_obj_params->span_type = SX_SPAN_TYPE_REMOTE_ETH_L3_TYPE1;
        if (SAI_STATUS_SUCCESS == status_tc) {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.qos_mode    = SX_SPAN_QOS_CONFIGURED;
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.switch_prio = mirror_tc->u8;
        } else {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.qos_mode    = SX_SPAN_QOS_MAINTAIN;
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.switch_prio = MLNX_MIRROR_DEFAULT_SWITCH_PRIO;
        }
        if (MLNX_VLAN_ID_WHEN_TP_DISABLED == mirror_vlan_id->u16) {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_DISABLE;
        } else {
            sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.tp = MLNX_MIRROR_TP_ENABLE;
        }
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.vid = mirror_vlan_id->u16;
        if (MLNX_MIRROR_VLAN_TPID != mirror_vlan_tpid->u16) {
            SX_LOG_ERR("VLAN TPID must be %x on create, but getting %x\n", MLNX_MIRROR_VLAN_TPID,
                       mirror_vlan_tpid->u16);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_tpid->u16;
        }
        if (MIRROR_VLAN_PRI_MAX < mirror_vlan_pri->u8) {
            SX_LOG_ERR("Error: VLAN PRI should be at most %d but getting %d\n",
                       MIRROR_VLAN_PRI_MAX,
                       mirror_vlan_pri->u8);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_pri->u8;
        }
        if (MIRROR_VLAN_CFI_MAX < mirror_vlan_cfi->u8) {
            SX_LOG_ERR("Error: VLAN CFI should be at most %d but getting %d\n",
                       MIRROR_VLAN_CFI_MAX,
                       mirror_vlan_cfi->u8);
            SX_LOG_EXIT();
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + mirror_vlan_cfi->u8;
        }
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.vlan_ethertype_id = MLNX_VLAN_ETHERTYPE_ID;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.pcp               = mirror_vlan_pri->u8;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.dei               = mirror_vlan_cfi->u8;
        sdk_mirror_obj_params->span_type_format.remote_eth_l3_type1.dscp              =
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
                                               _In_ uint32_t               attr_count,
                                               _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *mirror_type              = NULL, *mirror_monitor_port = NULL, *mirror_truncate_size =
        NULL, *mirror_tc                                  = NULL;
    const sai_attribute_value_t *mirror_vlan_tpid         = NULL, *mirror_vlan_id = NULL, *mirror_vlan_pri = NULL,
    *mirror_vlan_cfi                                      = NULL;
    const sai_attribute_value_t *mirror_encap_type        = NULL, *mirror_iphdr_version = NULL, *mirror_tos = NULL,
    *mirror_ttl                                           = NULL;
    const sai_attribute_value_t *mirror_src_ip_address    = NULL, *mirror_dst_ip_address = NULL;
    const sai_attribute_value_t *mirror_src_mac_address   = NULL, *mirror_dst_mac_address = NULL;
    const sai_attribute_value_t *mirror_gre_protocol_type = NULL;
    sai_status_t                 status                   = SAI_STATUS_FAILURE, status_truncate_size =
        SAI_STATUS_FAILURE;
    sai_status_t             status_tc = SAI_STATUS_FAILURE, status_ttl = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;
    sx_span_session_id_t     sdk_mirror_obj_id = 0;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_check_mirror_attribute_on_create(attr_count, attr_list,
                                                        &mirror_type, &mirror_monitor_port,
                                                        &mirror_truncate_size, &status_truncate_size,
                                                        &mirror_tc, &status_tc,
                                                        &mirror_vlan_tpid, &mirror_vlan_id, &mirror_vlan_pri,
                                                        &mirror_vlan_cfi,
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
        sdk_mirror_obj_params.truncate      = false;
        sdk_mirror_obj_params.truncate_size = 0;
    } else {
        sdk_mirror_obj_params.truncate      = true;
        sdk_mirror_obj_params.truncate_size = mirror_truncate_size->u16;
    }

    switch (mirror_type->s32) {
    case SAI_MIRROR_TYPE_LOCAL:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_set_SPAN_session_param(&sdk_mirror_obj_params,
                                                  mirror_tc, status_tc))) {
            SX_LOG_ERR("Error setting SPAN session parameters on create\n");
            SX_LOG_EXIT();
            return status;
        }
        break;

    case SAI_MIRROR_TYPE_REMOTE:
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

    case SAI_MIRROR_TYPE_ENHANCED_REMOTE:
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_set_ERSPAN_session_param(&sdk_mirror_obj_params,
                                                    mirror_tc, status_tc,
                                                    mirror_vlan_tpid, mirror_vlan_id, mirror_vlan_pri, mirror_vlan_cfi,
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

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error creating mirror session\n");
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_add_mirror_analyzer_port(sdk_mirror_obj_id, mirror_monitor_port->oid))) {
        SX_LOG_ERR("Error adding mirror analyzer port %" PRIx64 " on sdk mirror obj id %d\n",
                   mirror_monitor_port->oid,
                   sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Created sdk mirror obj id: %d\n", sdk_mirror_obj_id);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_MIRROR, (uint32_t)sdk_mirror_obj_id, NULL, sai_mirror_obj_id))) {
        SX_LOG_ERR("Error creating mirror session object\n");
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Created SAI mirror obj id: %" PRId64 "\n", *sai_mirror_obj_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_mirror_session(_In_ const sai_object_id_t sai_mirror_obj_id)
{
    sx_span_session_id_t     sdk_mirror_obj_id     = 0;
    uint32_t                 sdk_mirror_obj_id_u32 = 0;
    sai_status_t             status                = SAI_STATUS_FAILURE;
    sx_span_session_params_t sdk_mirror_obj_params;

    memset(&sdk_mirror_obj_params, 0, sizeof(sx_span_session_params_t));

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(sai_mirror_obj_id, SAI_OBJECT_TYPE_MIRROR, &sdk_mirror_obj_id_u32, NULL))) {
        SX_LOG_ERR("Invalid sai mirror obj id: %" PRId64 "\n", sai_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    sdk_mirror_obj_id = (sx_span_session_id_t)sdk_mirror_obj_id_u32;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_delete_mirror_analyzer_port(sdk_mirror_obj_id))) {
        SX_LOG_ERR("Error deleting mirror analyzer port on sdk mirror obj id %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             sdk_to_sai(sx_api_span_session_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_mirror_obj_params,
                                                &sdk_mirror_obj_id)))) {
        SX_LOG_ERR("Error destorying mirror session, sdk mirror obj id: %d\n", sdk_mirror_obj_id);
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_NTC("Removed SAI mirror obj id %" PRId64 "\n", sai_mirror_obj_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_mirror_session_attribute(_In_ const sai_object_id_t  sai_mirror_obj_id,
                                                      _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = sai_mirror_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    mirror_key_to_str(sai_mirror_obj_id, key_str);

    status = sai_set_attribute(&key, key_str, mirror_attribs, mirror_vendor_attribs, attr);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_get_mirror_session_attribute(_In_ const sai_object_id_t sai_mirror_obj_id,
                                                      _In_ uint32_t              attr_count,
                                                      _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .object_id = sai_mirror_obj_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status = SAI_STATUS_FAILURE;

    SX_LOG_ENTER();

    mirror_key_to_str(sai_mirror_obj_id, key_str);

    status = sai_get_attributes(&key, key_str, mirror_attribs, mirror_vendor_attribs, attr_count, attr_list);

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
