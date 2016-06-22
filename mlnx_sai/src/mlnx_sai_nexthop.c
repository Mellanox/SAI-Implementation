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
#define __MODULE__ SAI_NEXT_HOP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t next_hop_attribs[] = {
    { SAI_NEXT_HOP_ATTR_TYPE, true, true, false, true,
      "Next hop entry type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_NEXT_HOP_ATTR_IP, true, true, false, true,
      "Next hop entry IP address", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, true, true, false, true,
      "Next hop entry router interface ID", SAI_ATTR_VAL_TYPE_OID },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_next_hop_attr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static const sai_vendor_attribute_entry_t next_hop_vendor_attribs[] = {
    { SAI_NEXT_HOP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TYPE,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_IP,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_IP,
      NULL, NULL },
    { SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
      NULL, NULL },
};
static void next_hop_key_to_str(_In_ sai_object_id_t next_hop_id, _Out_ char *key_str)
{
    uint32_t nexthop_data;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &nexthop_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid next hop id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "next hop id %u", nexthop_data);
    }
}

static sai_status_t mlnx_translate_sdk_next_hop_entry_to_sai(_In_ const sx_next_hop_t  *next_hop,
                                                             _Out_ sai_next_hop_type_t *type,
                                                             _Out_ sai_ip_address_t    *next_hop_ip,
                                                             _Out_ sai_object_id_t     *rif_id)
{
    sai_status_t status;

    if (SX_NEXT_HOP_TYPE_IP != next_hop->next_hop_key.type) {
        SX_LOG_ERR("Invalid next hop type %d\n", next_hop->next_hop_key.type);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *type = SAI_NEXT_HOP_IP;

    if (SAI_STATUS_SUCCESS != (status =
                                   mlnx_translate_sdk_ip_address_to_sai(&next_hop->next_hop_key.next_hop_key_entry.
                                                                        ip_next_hop.address, next_hop_ip))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object(SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                                next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif,
                                NULL, rif_id))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_translate_sai_next_hop_to_sdk(_In_ sai_next_hop_type_t     type,
                                                       _In_ const sai_ip_address_t *next_hop_ip,
                                                       _In_ sai_object_id_t         rif_id,
                                                       _Out_ sx_next_hop_t         *next_hop)
{
    sai_status_t status;
    uint32_t     rif_data;

    if (SAI_NEXT_HOP_IP != type) {
        SX_LOG_ERR("Invalid next hop type %d\n", type);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    next_hop->next_hop_key.type = SX_NEXT_HOP_TYPE_IP;

    if (SAI_STATUS_SUCCESS != (status =
                                   mlnx_translate_sai_ip_address_to_sdk(next_hop_ip,
                                                                        &next_hop->next_hop_key.next_hop_key_entry.
                                                                        ip_next_hop.address))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(rif_id, SAI_OBJECT_TYPE_ROUTER_INTERFACE, &rif_data, NULL))) {
        return status;
    }

    next_hop->next_hop_key.next_hop_key_entry.ip_next_hop.rif = (sx_router_interface_t)rif_data;
    next_hop->next_hop_data.action                            = SX_ROUTER_ACTION_FORWARD;
    next_hop->next_hop_data.trap_attr.prio                    = SX_TRAP_PRIORITY_MED;
    next_hop->next_hop_data.weight                            = 1;

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Create next hop
 *
 * Arguments:
 *    [out] next_hop_id - next hop id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 * Note: IP address expected in Network Byte Order.
 */
static sai_status_t mlnx_create_next_hop(_Out_ sai_object_id_t      *next_hop_id,
                                         _In_ uint32_t               attr_count,
                                         _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *type, *ip, *rif;
    uint32_t                     type_index, ip_index, rif_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_next_hop_t                sdk_next_hop;
    sx_ecmp_id_t                 sdk_ecmp_id;
    uint32_t                     next_hop_cnt;

    SX_LOG_ENTER();

    memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));

    if (NULL == next_hop_id) {
        SX_LOG_ERR("NULL next hop id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, next_hop_attribs, next_hop_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, next_hop_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create next hop, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_TYPE, &type, &type_index));
    assert(SAI_STATUS_SUCCESS == find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_IP, &ip, &ip_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, &rif, &rif_index));

    if (SAI_NEXT_HOP_IP != type->s32) {
        SX_LOG_ERR("Invalid next hop type %d on create\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }

    if ((SAI_IP_ADDR_FAMILY_IPV4 != ip->ipaddr.addr_family) && (SAI_IP_ADDR_FAMILY_IPV6 != ip->ipaddr.addr_family)) {
        SX_LOG_ERR("Invalid next hop ip address %d family on create\n", ip->ipaddr.addr_family);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + ip_index;
    }
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_next_hop_to_sdk(type->s32, &ip->ipaddr, rif->oid, &sdk_next_hop))) {
        return status;
    }

    next_hop_cnt = 1;
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_CREATE, &sdk_ecmp_id, &sdk_next_hop, &next_hop_cnt))) {
        SX_LOG_ERR("Failed to create ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_NEXT_HOP, sdk_ecmp_id, NULL, next_hop_id))) {
        return status;
    }
    next_hop_key_to_str(*next_hop_id, key_str);
    SX_LOG_NTC("Created next hop %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove next hop
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_next_hop(_In_ sai_object_id_t next_hop_id)
{
    sai_status_t status;
    sx_ecmp_id_t sdk_ecmp_id;
    char         key_str[MAX_KEY_STR_LEN];
    uint32_t     next_hop_cnt = 0;

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    SX_LOG_NTC("Remove next hop %s\n", key_str);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(next_hop_id, SAI_OBJECT_TYPE_NEXT_HOP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_set(gh_sdk, SX_ACCESS_CMD_DESTROY, &sdk_ecmp_id, NULL, &next_hop_cnt))) {
        SX_LOG_ERR("Failed to destroy ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set Next Hop attribute
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_next_hop_attribute(_In_ sai_object_id_t next_hop_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = next_hop_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    return sai_set_attribute(&key, key_str, next_hop_attribs, next_hop_vendor_attribs, attr);
}


/*
 * Routine Description:
 *    Get Next Hop attribute
 *
 * Arguments:
 *    [in] next_hop_id - next hop id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_next_hop_attribute(_In_ sai_object_id_t     next_hop_id,
                                                _In_ uint32_t            attr_count,
                                                _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = next_hop_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    next_hop_key_to_str(next_hop_id, key_str);
    return sai_get_attributes(&key, key_str, next_hop_attribs, next_hop_vendor_attribs, attr_count, attr_list);
}

/* Next hop entry type [sai_next_hop_type_t] */
/* Next hop entry ipv4 address [sai_ip_address_t] */
/* Next hop entry router interface id [sai_object_id_t] (MANDATORY_ON_CREATE|CREATE_ONLY) */
static sai_status_t mlnx_next_hop_attr_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t        status;
    long                attr = (long)arg;
    sx_next_hop_t       sdk_next_hop;
    uint32_t            sdk_next_hop_cnt;
    sx_ecmp_id_t        sdk_ecmp_id;
    sai_next_hop_type_t next_hop_type;
    sai_ip_address_t    next_hop_ip;
    sai_object_id_t     rif;

    SX_LOG_ENTER();

    memset(&sdk_next_hop, 0, sizeof(sdk_next_hop));

    assert((SAI_NEXT_HOP_ATTR_TYPE == attr) ||
           (SAI_NEXT_HOP_ATTR_IP == attr) ||
           (SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID == attr));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_NEXT_HOP, &sdk_ecmp_id, NULL))) {
        return status;
    }

    sdk_next_hop_cnt = 1;
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_ecmp_get(gh_sdk, sdk_ecmp_id, &sdk_next_hop, &sdk_next_hop_cnt))) {
        SX_LOG_ERR("Failed to get ecmp - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (1 != sdk_next_hop_cnt) {
        SX_LOG_ERR("Invalid next hosts count %u\n", sdk_next_hop_cnt);
        return SAI_STATUS_FAILURE;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sdk_next_hop_entry_to_sai(&sdk_next_hop, &next_hop_type, &next_hop_ip, &rif))) {
        return status;
    }

    switch (attr) {
    case SAI_NEXT_HOP_ATTR_TYPE:
        value->s32 = next_hop_type;
        break;

    case SAI_NEXT_HOP_ATTR_IP:
        memcpy(&value->ipaddr, &next_hop_ip, sizeof(value->ipaddr));
        break;

    case SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID:
        value->oid = rif;
        break;

    default:
        return SAI_STATUS_INVALID_ATTRIBUTE_0 + attr_index;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_nexthop_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_next_hop_api_t mlnx_next_hop_api = {
    mlnx_create_next_hop,
    mlnx_remove_next_hop,
    mlnx_set_next_hop_attribute,
    mlnx_get_next_hop_attribute
};
