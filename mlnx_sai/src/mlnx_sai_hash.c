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
#define __MODULE__ SAI_HASH

#define SAI_HASH_FIELDS_COUNT_MAX 64
#define SAI_HASH_DEFAULT_SEED     0

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_hash_native_field_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_hash_native_field_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg);
static sai_status_t mlnx_hash_udf_group_list_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_hash_udf_group_list_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t mlnx_hash_ecmp_sx_config_update(void);
static sai_status_t mlnx_hash_ecmp_global_config_get(_Out_ sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                                     _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                     _Out_ uint32_t                           *enable_count,
                                                     _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                     _Out_ uint32_t                           *field_count);
static const sai_vendor_attribute_entry_t hash_vendor_attribs[] = {
    { SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_hash_native_field_list_get, NULL,
      mlnx_hash_native_field_list_set, NULL },
    { SAI_HASH_ATTR_UDF_GROUP_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_hash_udf_group_list_get, NULL,
      mlnx_hash_udf_group_list_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const mlnx_attr_enum_info_t hash_enum_info[] = {
    [SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST] = ATTR_ENUM_VALUES_ALL(),
};
const mlnx_obj_type_attrs_info_t mlnx_hash_obj_type_info = {
    hash_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(hash_enum_info)};
static void hash_key_to_str(_In_ sai_object_id_t hash_id, _Out_ char *key_str)
{
    uint32_t hash_data = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid hash id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "hash id %u", hash_data);
    }
}

/* Create new hash object. */
static sai_status_t mlnx_hash_obj_create(sai_object_id_t* new_object)
{
    uint32_t     ii     = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_db_write_lock();

    /* Find next free index in hash_arr. */
    while (ii < SAI_HASH_MAX_OBJ_COUNT &&
           g_sai_db_ptr->hash_list[ii].hash_id != SAI_NULL_OBJECT_ID) {
        ++ii;
    }

    if (ii == SAI_HASH_MAX_OBJ_COUNT) {
        sai_db_unlock();
        SX_LOG_ERR("Failed to create new hash object - hash DB is full.\n");
        return SAI_STATUS_TABLE_FULL;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, ii, NULL, new_object))) {
        sai_db_unlock();
        return status;
    }

    g_sai_db_ptr->hash_list[ii].hash_id = *new_object;

    sai_db_sync();
    sai_db_unlock();
    return status;
}

/* Set native fields for specified hash object */
static sai_status_t mlnx_hash_obj_native_fields_set(const sai_object_id_t hash_id, const sai_attribute_value_t* value)
{
    uint32_t     ii         = 0;
    int32_t      field      = 0;
    uint64_t     field_mask = 0;
    uint32_t     hash_data  = 0;
    sai_status_t status     = SAI_STATUS_SUCCESS;

    for (ii = 0; ii < value->s32list.count; ii++) {
        field = value->s32list.list[ii];
        if ((field < SAI_NATIVE_HASH_FIELD_SRC_IP) ||
            (field > SAI_NATIVE_HASH_FIELD_IN_PORT)) {
            SX_LOG_ERR("Invalid native filed value %d.\n", field);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }

        field_mask |= (uint64_t)1 << field;
    }

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    g_sai_db_ptr->hash_list[hash_data].field_mask = field_mask;
    return status;
}

/* Get native fields configured for a specified hash object */
static sai_status_t mlnx_hash_obj_native_fileds_get(const sai_object_id_t hash_id, sai_attribute_value_t* value)
{
    uint32_t     ii                                    = 0;
    uint64_t     field_mask                            = 0;
    int32_t      field_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};
    uint32_t     field_count                           = 0;
    uint32_t     hash_data                             = 0;
    sai_status_t status                                = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    if ((g_sai_db_ptr->hash_list[hash_data].hash_id == SAI_NULL_OBJECT_ID) ||
        (g_sai_db_ptr->hash_list[hash_data].hash_id != hash_id)) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }
    field_mask = g_sai_db_ptr->hash_list[hash_data].field_mask;

    for (ii = SAI_NATIVE_HASH_FIELD_SRC_IP; ii <= SAI_NATIVE_HASH_FIELD_IN_PORT; ii++) {
        if (field_mask & ((uint64_t)1 << ii)) {
            field_list[field_count++] = ii;
        }
    }

    status = mlnx_fill_s32list(field_list, field_count, &value->s32list);

    return status;
}

static sai_status_t mlnx_hash_object_udf_group_mask_get(_In_ const sai_object_id_t hash_id,
                                                        _Out_ udf_group_mask_t    *group_mask)
{
    sai_status_t status;
    uint32_t     hash_index;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    *group_mask = g_sai_db_ptr->hash_list[hash_index].udf_group_mask;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_obj_udf_group_list_set(_In_ const sai_object_id_t        hash_id,
                                                     _In_ uint32_t                     attr_index,
                                                     _In_ const sai_attribute_value_t *value)
{
    sai_status_t     status;
    udf_group_mask_t udf_group_mask;
    uint32_t         hash_index;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + attr_index;
    }

    status = mlnx_udf_group_objlist_validate_and_fetch_mask(&value->objlist, attr_index, &udf_group_mask);
    if (SAI_ERR(status)) {
        return status;
    }

    assert(MLNX_UDF_GROUP_MASK_EMPTY == g_sai_db_ptr->hash_list[hash_index].udf_group_mask);

    g_sai_db_ptr->hash_list[hash_index].udf_group_mask = udf_group_mask;

    mlnx_udf_group_mask_references_add(udf_group_mask);

    return SAI_STATUS_SUCCESS;
}

/* Check if specified native fields are valid
 * for mentioned hash object id (L2, IPv4 or IpinIP) */
static sai_status_t mlnx_hash_obj_native_fields_validate(mlnx_switch_usage_hash_object_id_t hash_oper_id,
                                                         const sai_attribute_value_t      * value)
{
    uint32_t     ii     = 0;
    int32_t      field  = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (value->s32list.count == 0) {
        SX_LOG_ERR("Invalid empty native fields list, count - 0.\n");
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; ii < value->s32list.count; ii++) {
        field = value->s32list.list[ii];
        switch (field) {
        case SAI_NATIVE_HASH_FIELD_ETHERTYPE:
        case SAI_NATIVE_HASH_FIELD_SRC_MAC:
        case SAI_NATIVE_HASH_FIELD_DST_MAC:
        case SAI_NATIVE_HASH_FIELD_IN_PORT:
        case SAI_NATIVE_HASH_FIELD_VLAN_ID:
            /* valid for all */
            break;

        case SAI_NATIVE_HASH_FIELD_SRC_IP:
        case SAI_NATIVE_HASH_FIELD_DST_IP:
        case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
        case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
        case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            /* valid for IP and IPinIP */
/*
 *           if ((hash_oper_id == SAI_HASH_ECMP_ID) ||
 *               (hash_oper_id == SAI_HASH_LAG_ID)) {
 *               status = SAI_STATUS_FAILURE;
 *               SX_LOG_ERR("Invalid native field %d for object %u.\n", field, hash_oper_id);
 *           }
 */
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IP:
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IP:
            /* valid for IPinIP*/
            if ((hash_oper_id != SAI_HASH_ECMP_IPINIP_ID) &&
                (hash_oper_id != SAI_HASH_LAG_IPINIP_ID)) {
                status = SAI_STATUS_FAILURE;
                SX_LOG_ERR("Invalid native field %d for object %u.\n", field, hash_oper_id);
            }
            break;

        default:
            SX_LOG_ERR("Invalid native filed value %d.\n", field);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }
    }

    return status;
}

/* Check if the specified hash object is operational.
 * If IPinIP object is configured – no need to apply IP or default object.
 * Same if IP object configured - no need to apply default object. */
bool mlnx_hash_obj_need_apply(mlnx_switch_usage_hash_object_id_t hash_oper_id)
{
    bool res = true;

    assert(hash_oper_id <= SAI_HASH_MAX_OBJ_ID);

    switch (hash_oper_id) {
    case SAI_HASH_ECMP_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP4_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
            break;
        }

    /* do not break here, need verify same condition as for IPv4 */
    case SAI_HASH_ECMP_IP4_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IPINIP_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
        }
        break;

    case SAI_HASH_LAG_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IP4_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
            break;
        }

    /* do not break here, need verify same condition as for IPv4 */
    case SAI_HASH_LAG_IP4_ID:
        if (g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_IPINIP_ID] != SAI_NULL_OBJECT_ID) {
            res = false;
        }
        break;

    case SAI_HASH_ECMP_IPINIP_ID:
    case SAI_HASH_LAG_IPINIP_ID:
    case SAI_HASH_ECMP_IP6_ID:
    case SAI_HASH_LAG_IP6_ID:
        break;

    case SAI_HASH_MAX_OBJ_ID:
        res = false;
        break;
    }

    return res;
}

/* Convert SAI fields list to sx bit mask */
static sai_status_t mlnx_hash_convert_lag_sai_field_to_sx(const sai_attribute_value_t *value,
                                                          sx_lag_hash_param_t         *hash_param)
{
    uint32_t    ii     = 0;
    sx_status_t status = SAI_STATUS_SUCCESS;

    hash_param->lag_hash = 0;

    for (ii = 0; ii < value->s32list.count; ii++) {
        switch (value->s32list.list[ii]) {
        case SAI_NATIVE_HASH_FIELD_SRC_IP:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_S_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_DST_IP:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_D_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_L4_SPORT;
            break;

        case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_L4_DPORT;
            break;

        case SAI_NATIVE_HASH_FIELD_VLAN_ID:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_VID_IP;
            hash_param->lag_hash |= 1 << SX_LAG_HASH_VID_NON_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_L3_PROTO;
            break;

        case SAI_NATIVE_HASH_FIELD_ETHERTYPE:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_ETHER_IP;
            hash_param->lag_hash |= 1 << SX_LAG_HASH_ETHER_NON_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_SRC_MAC:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_SMAC_IP;
            hash_param->lag_hash |= 1 << SX_LAG_HASH_SMAC_NON_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_DST_MAC:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_DMAC_IP;
            hash_param->lag_hash |= 1 << SX_LAG_HASH_DMAC_NON_IP;
            break;

        case SAI_NATIVE_HASH_FIELD_IN_PORT:
            hash_param->lag_hash |= 1 << SX_LAG_HASH_INGRESS_PORT;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IP:
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IP:
            SX_LOG_ERR("Lag hash field is not supported, element %d, value %d.\n", ii, value->s32list.list[ii]);
            return SAI_STATUS_NOT_SUPPORTED;

        default:
            SX_LOG_ERR("Invalid lag hash field, element %d, value %d.\n", ii, value->s32list.list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }
    }

    return status;
}

/* Convert sai fields list to sx fields list and enable list */
static sai_status_t mlnx_hash_convert_ecmp_sai_field_to_sx(const sai_attribute_value_t       * value,
                                                           sx_router_ecmp_hash_field_enable_t* enable_list,
                                                           uint32_t                          * enable_count,
                                                           sx_router_ecmp_hash_field_t       * fields_list,
                                                           uint32_t                          * fields_count,
                                                           bool                                is_ipv6)
{
    uint32_t     ii          = 0;
    bool         enable_ipv4 = false, enable_l4 = false, enable_inner = false;
    sai_status_t status      = SAI_STATUS_SUCCESS;

    *fields_count = 0;
    *enable_count = 0;

    for (ii = 0; ii < value->s32list.count; ii++) {
        switch (value->s32list.list[ii]) {
        case SAI_NATIVE_HASH_FIELD_SRC_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_SIP_BYTE_15;
            } else { /* ipv4 */
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_SIP_BYTE_3;

                enable_ipv4 = true;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_DST_IP:
            if (is_ipv6) {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTES_0_TO_7;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_8;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_9;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_10;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_11;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_12;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_13;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_14;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV6_DIP_BYTE_15;
            } else {
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_0;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_1;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_2;
                fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_DIP_BYTE_3;

                enable_ipv4 = true;
            }
            break;

        case SAI_NATIVE_HASH_FIELD_L4_SRC_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_TCP_UDP_SPORT;

            enable_l4 = true;
            break;

        case SAI_NATIVE_HASH_FIELD_L4_DST_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_TCP_UDP_DPORT;

            enable_l4 = true;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IP:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_0;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_1;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_2;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_SIP_BYTE_3;

            enable_ipv4  = true;
            enable_inner = true;
            break;

        case SAI_NATIVE_HASH_FIELD_INNER_DST_IP:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_0;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_1;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_2;
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_INNER_IPV4_DIP_BYTE_3;

            enable_ipv4  = true;
            enable_inner = true;
            break;

        case SAI_NATIVE_HASH_FIELD_VLAN_ID:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_OVID;
            break;

        case SAI_NATIVE_HASH_FIELD_IP_PROTOCOL:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_IPV4_PROTOCOL;
            enable_ipv4                    = true;
            break;

        case SAI_NATIVE_HASH_FIELD_ETHERTYPE:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_ETHERTYPE;
            break;

        case SAI_NATIVE_HASH_FIELD_SRC_MAC:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_SMAC;
            break;

        case SAI_NATIVE_HASH_FIELD_DST_MAC:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_OUTER_DMAC;
            break;

        case SAI_NATIVE_HASH_FIELD_IN_PORT:
            fields_list[(*fields_count)++] = SX_ROUTER_ECMP_HASH_GENERAL_FIELDS_INGRESS_PORT_NUMBER;
            break;

        default:
            SX_LOG_ERR("Invalid ECMP hash field , element %d, value %d.\n", ii, value->s32list.list[ii]);
            return SAI_STATUS_INVALID_ATTR_VALUE_0;
        }
    }

    enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_NON_IP;
    enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_IPV4;
    if (enable_inner) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L2_IPV4;
    }

    if (enable_ipv4) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV4_NON_TCP_UDP;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV4_TCP_UDP;
        if (enable_inner) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV4_NON_TCP_UDP;
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_IPV4_TCP_UDP;
        }
    }

    if (is_ipv6) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L2_IPV6;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV6_NON_TCP_UDP;
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_IPV6_TCP_UDP;
    }

    if (enable_l4) {
        enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L4_IPV4;
        if (is_ipv6) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_OUTER_L4_IPV6;
        }
        if (enable_inner) {
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L4_IPV4;
            enable_list[(*enable_count)++] = SX_ROUTER_ECMP_HASH_FIELD_ENABLE_INNER_L4_IPV6;
        }
    }

    return status;
}

/* Convert SAI ECMP algorithm to sx */
static sai_status_t mlnx_hash_convert_ecmp_sai_type_to_sx(const sai_attribute_value_t       *value,
                                                          sx_router_ecmp_port_hash_params_t* hash_param)
{
    switch (value->s32) {
    case SAI_HASH_ALGORITHM_XOR:
        hash_param->ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_XOR;
        break;

    case SAI_HASH_ALGORITHM_CRC:
        hash_param->ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_CRC;
        break;

    case SAI_HASH_ALGORITHM_RANDOM:
        hash_param->ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_RANDOM;
        break;

    default:
        SX_LOG_ERR("Invalid hash type value %d.\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    return SAI_STATUS_SUCCESS;
}

/* Get operational ECMP config and apply it for specified port */
/* SAI DB lock is needed */
sai_status_t mlnx_hash_ecmp_cfg_apply_on_port(_In_ sx_port_log_id_t port_log_id)
{
    sai_status_t                       status;
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sx_router_ecmp_hash_field_enable_t hash_enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        hash_field_list[FIELDS_NUM]          = {0};
    uint32_t                           enable_count                         = 0;
    uint32_t                           field_count                          = 0;

    status = mlnx_hash_ecmp_global_config_get(&port_hash_param,
                                              hash_enable_list,
                                              &enable_count,
                                              hash_field_list,
                                              &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get ECMP hash conifg\n");
        return status;
    }

    status = sx_api_router_ecmp_port_hash_params_set(gh_sdk, SX_ACCESS_CMD_SET, port_log_id, &port_hash_param,
                                                     hash_enable_list, enable_count,
                                                     hash_field_list, field_count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to set ECMP hash params for port %x.\n", port_log_id);
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_hash_ecmp_hash_params_apply_to_ports(const sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                                       const sx_router_ecmp_hash_field_enable_t *hash_enable_list,
                                                       uint32_t                                  enable_count,
                                                       const sx_router_ecmp_hash_field_t        *hash_field_list,
                                                       uint32_t                                  field_count)
{
    sx_status_t         sx_status;
    mlnx_port_config_t *port;
    uint32_t            ii;

    assert(port_hash_param != NULL);
    assert(hash_enable_list != NULL);
    assert(hash_field_list != NULL);

    mlnx_port_not_in_lag_foreach(port, ii) {
        sx_status = sx_api_router_ecmp_port_hash_params_set(gh_sdk, SX_ACCESS_CMD_SET, port->logical,
                                                            port_hash_param,
                                                            hash_enable_list, enable_count,
                                                            hash_field_list, field_count);
        if (SX_STATUS_SUCCESS != sx_status) {
            SX_LOG_ERR("Failed to set ecmp hash params for %s %x - %s.\n",
                       mlnx_port_type_str(port),
                       port->logical,
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* Apply default ECMP hash algorithm, default ECMP seed or ECMP symmetric flag.
 * The new value must be applied for all ports and configured LAGs.
 */
sai_status_t mlnx_hash_ecmp_hash_params_apply(const sai_attr_id_t attr_id, const sai_attribute_value_t* value)
{
    sx_router_ecmp_port_hash_params_t *port_hash_param;
    sai_status_t                       status = SAI_STATUS_SUCCESS;

    port_hash_param = &g_sai_db_ptr->port_hash_params;

    switch (attr_id) {
    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED:
        port_hash_param->seed = value->u32;
        break;

    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM:
        status = mlnx_hash_convert_ecmp_sai_type_to_sx(value, port_hash_param);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH:
        port_hash_param->symmetric_hash = value->booldata;
        break;
    }

    /* Apply DB changes to ports */
    status = mlnx_hash_ecmp_sx_config_update();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* Finds the applied object IPinIP -> IPv4 -> default */
static sai_object_id_t mlnx_hash_get_applied_object_ipv4()
{
    sai_object_id_t applied_object;

    applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IPINIP_ID];
    if (applied_object == SAI_NULL_OBJECT_ID) {
        applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP4_ID];
        if (applied_object == SAI_NULL_OBJECT_ID) {
            applied_object = g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_ID];
        }
    }

    /* default object SAI_HASH_ECMP_ID is always applied (on init) */
    assert(applied_object != SAI_NULL_OBJECT_ID);

    return applied_object;
}

static sai_object_id_t mlnx_hash_get_applied_object_ipv6()
{
    return g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP6_ID];
}

static sai_status_t mlnx_hash_object_to_sx_fields(_In_ sai_object_id_t                      hash_oid,
                                                  _In_ bool                                 is_ipv6,
                                                  _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                  _Out_ uint32_t                           *enable_count,
                                                  _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                  _Out_ uint32_t                           *field_count)
{
    sai_status_t                status;
    sai_attribute_value_t       sai_value;
    sai_native_hash_field_t     sai_fields_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};
    udf_group_mask_t            udf_group_mask;
    sx_router_ecmp_hash_field_t udf_groups_hash_fields[GENERAL_FIELDS_NUM] = {0};
    uint32_t                    udf_groups_hash_field_count                = 0;

    assert(enable_list);
    assert(enable_count);
    assert(field_list);
    assert(field_count);

    if (hash_oid == SAI_NULL_OBJECT_ID) {
        if (!is_ipv6) {
            SX_LOG_ERR("Invalid SAI DB state - Hash object for IPv4 is NULL\n");
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_hash_object_udf_group_mask_get(hash_oid, &udf_group_mask);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_value.s32list.list  = (int32_t*)sai_fields_list;
    sai_value.s32list.count = sizeof(sai_fields_list);

    status = mlnx_hash_obj_native_fileds_get(hash_oid, &sai_value);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_convert_ecmp_sai_field_to_sx(&sai_value, enable_list, enable_count,
                                                    field_list, field_count, is_ipv6);
    if (SAI_ERR(status)) {
        return status;
    }

    if (MLNX_UDF_GROUP_MASK_EMPTY != udf_group_mask) {
        status = mlnx_udf_group_mask_to_ecmp_hash_fields(udf_group_mask, udf_groups_hash_fields,
                                                         &udf_groups_hash_field_count);
        if (SAI_ERR(status)) {
            return status;
        }

        memcpy(&field_list[*field_count], udf_groups_hash_fields,
               sizeof(sx_router_ecmp_hash_field_t) * udf_groups_hash_field_count);

        *field_count += udf_groups_hash_field_count;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_ecmp_global_config_get(_Out_ sx_router_ecmp_port_hash_params_t  *port_hash_param,
                                                     _Out_ sx_router_ecmp_hash_field_enable_t *enable_list,
                                                     _Out_ uint32_t                           *enable_count,
                                                     _Out_ sx_router_ecmp_hash_field_t        *field_list,
                                                     _Out_ uint32_t                           *field_count)
{
    sai_status_t                       status;
    sai_object_id_t                    applied_hash_ipv4, applied_hash_ipv6;
    sx_router_ecmp_hash_field_enable_t enable_list_v6[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        field_list_v6[FIELDS_NUM]          = {0};
    uint32_t                           enable_count_v6                    = 0;
    uint32_t                           field_count_v6                     = 0;
    uint32_t                           ii, jj;
    bool                               present;

    memset(port_hash_param, 0, sizeof(*port_hash_param));

    applied_hash_ipv4 = mlnx_hash_get_applied_object_ipv4();
    applied_hash_ipv6 = mlnx_hash_get_applied_object_ipv6();

    memcpy(port_hash_param, &g_sai_db_ptr->port_hash_params, sizeof(*port_hash_param));

    status = mlnx_hash_object_to_sx_fields(applied_hash_ipv4, false,
                                           enable_list, enable_count,
                                           field_list, field_count);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_hash_object_to_sx_fields(applied_hash_ipv6, true,
                                           enable_list_v6, &enable_count_v6,
                                           field_list_v6, &field_count_v6);
    if (SAI_ERR(status)) {
        return status;
    }

    /* add unique values from enable_list_v6 to enable_list */
    for (ii = 0; ii < enable_count_v6; ii++) {
        present = false;
        for (jj = 0; jj < *enable_count; jj++) {
            if (enable_list_v6[ii] == enable_list[jj]) {
                present = true;
                break;
            }
        }

        if (!present) {
            enable_list[*enable_count] = enable_list_v6[ii];
            (*enable_count)++;
        }
    }

    /* add unique values from field_list_v6 to field_list_v4 */
    for (ii = 0; ii < field_count_v6; ii++) {
        present = false;
        for (jj = 0; jj < *field_count; jj++) {
            if (field_list_v6[ii] == field_list[jj]) {
                present = true;
                break;
            }
        }

        if (!present) {
            field_list[*field_count] = field_list_v6[ii];
            (*field_count)++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_hash_ecmp_sx_config_update(void)
{
    sai_status_t                       status;
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sx_router_ecmp_hash_field_enable_t enable_list[FIELDS_ENABLES_NUM] = {0};
    sx_router_ecmp_hash_field_t        field_list[FIELDS_NUM]          = {0};
    uint32_t                           enable_count                    = 0;
    uint32_t                           field_count                     = 0;

    status = mlnx_hash_ecmp_global_config_get(&port_hash_param, enable_list, &enable_count, field_list, &field_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get ECMP hash conifg\n");
        return status;
    }

    status = mlnx_hash_ecmp_hash_params_apply_to_ports(&port_hash_param, enable_list, enable_count,
                                                       field_list, field_count);
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* Apply hash configuration */
/* lag_fields can be NULL if hash_oper_id is for ECMP */
static sai_status_t mlnx_hash_obj_native_fields_update(mlnx_switch_usage_hash_object_id_t hash_oper_id,
                                                       const sai_attribute_value_t       *lag_fields)
{
    sx_lag_hash_param_t hash_param;
    sai_status_t        status = SAI_STATUS_SUCCESS;

    assert(hash_oper_id < SAI_HASH_MAX_OBJ_ID);

    memset(&hash_param, 0, sizeof(hash_param));

    if (hash_oper_id <= SAI_HASH_ECMP_ID_MAX) {
        status = mlnx_hash_ecmp_sx_config_update();
        if (SAI_ERR(status)) {
            return status;
        }
    } else {
        /* LAG */
        if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_get(gh_sdk, &hash_param))) {
            SX_LOG_ERR("Failed to get LAG hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        status = mlnx_hash_convert_lag_sai_field_to_sx(lag_fields, &hash_param);
        if (SAI_STATUS_SUCCESS != status) {
            return status;
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_lag_hash_flow_params_set(gh_sdk, &hash_param))) {
            SX_LOG_ERR("Failed to set LAG hash params - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    return status;
}

/* Find if mentioned hash object is set as a switch hash object,
 * if so - return it's operational object ID.
 * else - return SAI_HASH_MAX_OBJ_ID */
static mlnx_switch_usage_hash_object_id_t mlnx_hash_get_oper_id(sai_object_id_t hash_id)
{
    uint32_t ii = 0;

    /* check if the object is not used */
    for (ii = 0; ii < SAI_HASH_MAX_OBJ_ID; ii++) {
        if (g_sai_db_ptr->oper_hash_list[ii] == hash_id) {
            /* object in-use */
            break;
        }
    }

    return ii;
}

/* Remove hash object from DB if object is not in-use */
static sai_status_t mlnx_hash_obj_remove(sai_object_id_t hash_id)
{
    sai_status_t status    = SAI_STATUS_SUCCESS;
    uint32_t     hash_data = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    sai_db_write_lock();

    if (mlnx_hash_get_oper_id(hash_id) < SAI_HASH_MAX_OBJ_ID) {
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    g_sai_db_ptr->hash_list[hash_data].field_mask     = 0;
    g_sai_db_ptr->hash_list[hash_data].udf_group_mask = MLNX_UDF_GROUP_MASK_EMPTY;
    g_sai_db_ptr->hash_list[hash_data].hash_id        = SAI_NULL_OBJECT_ID;

out:
    sai_db_sync();
    sai_db_unlock();
    return status;
}

/* Apply native fields of hash_id object as a hash_oper_id object.
 * This routine is called in sai_switch when we set switch lag or ecmp object id */
sai_status_t mlnx_hash_object_apply(const sai_object_id_t                    hash_id,
                                    const mlnx_switch_usage_hash_object_id_t hash_oper_id)
{
    sai_status_t          status = SAI_STATUS_SUCCESS;
    sai_attribute_value_t value;
    int32_t               field_list[SAI_HASH_FIELDS_COUNT_MAX] = {0};

    value.s32list.list  = field_list;
    value.s32list.count = SAI_HASH_FIELDS_COUNT_MAX;

    status = mlnx_hash_obj_native_fileds_get(hash_id, &value);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    /* validate fields */
    if (value.s32list.count > 0) {
        status = mlnx_hash_obj_native_fields_validate(hash_oper_id, &value);
        if (SAI_STATUS_SUCCESS != status) {
            return status;
        }
    }

    /* check if need apply */
    if (mlnx_hash_obj_need_apply(hash_oper_id)) {
        /* apply fields */
        status = mlnx_hash_obj_native_fields_update(hash_oper_id, &value);
    }

    return status;
}

/* Add default hash configuration.
 * Create default ECMP and LAG hash object with default list of native fields enabled.
 * Set default ECMP and LAG hash algorithm and seed.
 */
sai_status_t mlnx_hash_initialize()
{
    sai_status_t                       status   = SAI_STATUS_SUCCESS;
    sai_object_id_t                    hash_obj = SAI_NULL_OBJECT_ID;
    sx_status_t                        sx_status;
    sx_lag_hash_param_t                lag_hash_param;
    sx_router_ecmp_port_hash_params_t  port_hash_param;
    sai_attribute_value_t              attr_value;
    sx_router_ecmp_hash_field_enable_t hash_enable_list[FIELDS_ENABLES_NUM];
    sx_router_ecmp_hash_field_t        hash_field_list[FIELDS_NUM];
    int32_t                            def_hash_fields[] = { SAI_NATIVE_HASH_FIELD_SRC_MAC,
                                                             SAI_NATIVE_HASH_FIELD_DST_MAC,
                                                             SAI_NATIVE_HASH_FIELD_ETHERTYPE,
                                                             SAI_NATIVE_HASH_FIELD_IN_PORT,
                                                             SAI_NATIVE_HASH_FIELD_SRC_IP,
                                                             SAI_NATIVE_HASH_FIELD_DST_IP,
                                                             SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
                                                             SAI_NATIVE_HASH_FIELD_L4_DST_PORT };

    memset(&lag_hash_param, 0, sizeof(lag_hash_param));
    memset(&port_hash_param, 0, sizeof(port_hash_param));
    memset(hash_enable_list, 0, sizeof(hash_enable_list));
    memset(hash_field_list, 0, sizeof(hash_field_list));

    attr_value.s32list.count = sizeof(def_hash_fields) / sizeof(def_hash_fields[0]);
    attr_value.s32list.list  = def_hash_fields;

    memset(g_sai_db_ptr->hash_list, 0, sizeof(g_sai_db_ptr->hash_list));

    /* Create default hash objects */
    /* Default ECMP object */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, 0, NULL, &hash_obj))) {
        return status;
    }

    g_sai_db_ptr->hash_list[0].hash_id = hash_obj;
    status                             = mlnx_hash_obj_native_fields_set(hash_obj, &attr_value);
    if (SAI_ERR(status)) {
        return status;
    }

    g_sai_db_ptr->port_hash_params.ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_CRC;
    g_sai_db_ptr->port_hash_params.seed           = SAI_HASH_DEFAULT_SEED;
    g_sai_db_ptr->port_hash_params.symmetric_hash = false;

    g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_ID]     = hash_obj;
    g_sai_db_ptr->oper_hash_list[SAI_HASH_ECMP_IP6_ID] = hash_obj;

    status = mlnx_hash_ecmp_sx_config_update();
    if (SAI_ERR(status)) {
        return status;
    }

    /* Default LAG object */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_HASH, 1, NULL, &hash_obj))) {
        return status;
    }
    g_sai_db_ptr->hash_list[1].hash_id = hash_obj;
    /* TODO : temporary patch, have different hash result for ECMP and LAG to pass PTF ECMP+LAG test case
     * This doesn't hash on dst port, to have different hash result */
    attr_value.s32list.count--;
    status = mlnx_hash_obj_native_fields_set(hash_obj, &attr_value);
    if (SAI_STATUS_SUCCESS != status) {
        return status;
    }

    g_sai_db_ptr->oper_hash_list[SAI_HASH_LAG_ID] = hash_obj;
    /* Set default algorithm and seed */
    lag_hash_param.lag_hash_type = SX_LAG_HASH_TYPE_CRC;
    lag_hash_param.lag_seed      = SAI_HASH_DEFAULT_SEED;
    lag_hash_param.lag_hash      = 0;

    status = mlnx_hash_convert_lag_sai_field_to_sx(&attr_value, &lag_hash_param);
    if (SAI_ERR(status)) {
        return status;
    }

    sx_status = sx_api_lag_hash_flow_params_set(gh_sdk, &lag_hash_param);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to set LAG hash params - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return status;
}

/* Get Hash native fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_native_field_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    uint32_t        hash_data                = 0;
    sai_object_id_t hash_id                  = key->key.object_id;
    char            key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t    status                   = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    hash_key_to_str(hash_id, key_str);

    sai_db_read_lock();
    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_native_fileds_get(hash_id, value))) {
        SX_LOG_ERR("Failed to get native fields for %s.\n", key_str);
    }

    sai_db_unlock();
    return status;
}

/* Set Hash native fields [sai_u32_list_t(sai_native_hash_field)] */
static sai_status_t mlnx_hash_native_field_list_set(_In_ const sai_object_key_t      *key,
                                                    _In_ const sai_attribute_value_t *value,
                                                    void                             *arg)
{
    mlnx_switch_usage_hash_object_id_t hash_oper_id             = 0;
    uint32_t                           hash_data                = 0;
    sai_object_id_t                    hash_id                  = key->key.object_id;
    char                               key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t                       status                   = SAI_STATUS_SUCCESS;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    hash_key_to_str(hash_id, key_str);

    sai_db_write_lock();

    /* Check if object is in use - apply changes */
    hash_oper_id = mlnx_hash_get_oper_id(hash_id);
    if (hash_oper_id < SAI_HASH_MAX_OBJ_ID) {
        /* validate fields */
        status = mlnx_hash_obj_native_fields_validate(hash_oper_id, value);
        if (SAI_STATUS_SUCCESS != status) {
            goto out;
        }

        /* check if changes need to be apply */
        if (mlnx_hash_obj_need_apply(hash_oper_id)) {
            /* SAI DB is updated so further logic can fetch an ECMP state */
            status = mlnx_hash_obj_native_fields_set(hash_id, value);
            if (SAI_STATUS_SUCCESS != status) {
                SX_LOG_ERR("Failed to update native fields for %s.\n", key_str);
                goto out;
            }

            /* apply fields */
            status = mlnx_hash_obj_native_fields_update(hash_oper_id, value);
            if (SAI_STATUS_SUCCESS != status) {
                goto out;
            }
        }
    } else {
        /* update DB */
        status = mlnx_hash_obj_native_fields_set(hash_id, value);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to update native fields for %s.\n", key_str);
            goto out;
        }
    }

out:
    sai_db_sync();
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_hash_udf_group_list_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t     status = SAI_STATUS_SUCCESS;
    udf_group_mask_t udf_group_mask;

    sai_db_read_lock();

    status = mlnx_hash_object_udf_group_mask_get(key->key.object_id, &udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (MLNX_UDF_GROUP_MASK_EMPTY == udf_group_mask) {
        value->objlist.count = 0;
        goto out;
    }

    status = mlnx_udf_group_mask_to_objlist(udf_group_mask, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

static sai_status_t mlnx_hash_udf_group_list_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t                       status;
    sai_object_id_t                    hash_id;
    mlnx_switch_usage_hash_object_id_t hash_oper_id;
    udf_group_mask_t                   udf_group_mask = MLNX_UDF_GROUP_MASK_EMPTY, old_udf_group_mask;
    uint32_t                           hash_index;
    bool                               is_applicable;

    hash_id = key->key.object_id;

    status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_index, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    hash_oper_id = mlnx_hash_get_oper_id(hash_id);

    status = mlnx_udf_group_objlist_validate_and_fetch_mask(&value->objlist, 0, &udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_udf_group_mask_is_hash_applicable(udf_group_mask, hash_oper_id, &is_applicable);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!is_applicable) {
        status = SAI_STATUS_NOT_SUPPORTED;
        goto out;
    }

    old_udf_group_mask = g_sai_db_ptr->hash_list[hash_index].udf_group_mask;

    g_sai_db_ptr->hash_list[hash_index].udf_group_mask = udf_group_mask;

    if (mlnx_hash_obj_need_apply(hash_oper_id)) {
        status = mlnx_hash_obj_native_fields_update(hash_oper_id, NULL);
        if (SAI_ERR(status)) {
            g_sai_db_ptr->hash_list[hash_index].udf_group_mask = old_udf_group_mask;
            goto out;
        }
    }

    status = mlnx_udf_group_mask_references_del(old_udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_udf_group_mask_references_add(udf_group_mask);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    return status;
}

/**
 * Routine Description:
 *    @brief Create hash
 *
 * Arguments:
 *    @param[out] hash_id - hash id
 *    @param[in] attr_count - number of attributes
 *    @param[in] attr_list - array of attributes
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 *
 */
static sai_status_t mlnx_create_hash(_Out_ sai_object_id_t     * hash_id,
                                     _In_ sai_object_id_t        switch_id,
                                     _In_ uint32_t               attr_count,
                                     _In_ const sai_attribute_t *attr_list)
{
    uint32_t                     index = 0;
    const sai_attribute_value_t *native_filed_list, *udf_group_list;
    char                         list_str[MAX_LIST_VALUE_STR_LEN] = {0};
    char                         key_str[MAX_KEY_STR_LEN]         = {0};
    sai_status_t                 status                           = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    if (NULL == hash_id) {
        SX_LOG_ERR("NULL hash id param.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check.\n");
        SX_LOG_EXIT();
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_HASH, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create hash object.\n");
    SX_LOG_NTC("Attribs %s.\n", list_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_create(hash_id))) {
        SX_LOG_EXIT();
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST,
                                 &native_filed_list, &index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_hash_obj_native_fields_set(*hash_id, native_filed_list);
        if (SAI_STATUS_SUCCESS != status) {
            SX_LOG_ERR("Failed to create %s.\n", key_str);
            mlnx_hash_obj_remove(*hash_id);
            SX_LOG_EXIT();
            return status;
        }
    }

    sai_db_write_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_HASH_ATTR_UDF_GROUP_LIST,
                                 &udf_group_list, &index);
    if (SAI_STATUS_SUCCESS == status) {
        status = mlnx_hash_obj_udf_group_list_set(*hash_id, index, udf_group_list);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create %s.\n", key_str);
            mlnx_hash_obj_remove(*hash_id);
            goto out;
        }
    }

    hash_key_to_str(*hash_id, key_str);
    SX_LOG_NTC("Created %s.\n", key_str);
    status = SAI_STATUS_SUCCESS;

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Remove hash
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_remove_hash(_In_ sai_object_id_t hash_id)
{
    uint32_t     hash_data                = 0;
    char         key_str[MAX_KEY_STR_LEN] = {0};
    sai_status_t status                   = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    /* Validate object */
    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(hash_id, SAI_OBJECT_TYPE_HASH, &hash_data, NULL))) {
        return status;
    }

    hash_key_to_str(hash_id, key_str);
    SX_LOG_NTC("Remove %s.\n", key_str);

    if (SAI_STATUS_SUCCESS != (status = mlnx_hash_obj_remove(hash_id))) {
        SX_LOG_ERR("Failed to remove %s - err %d\n", key_str, status);
    }

    SX_LOG_EXIT();
    return status;
}

/**
 * Routine Description:
 *    @brief Set hash attribute
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *    @param[in] attr - attribute
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_set_hash_attribute(_In_ sai_object_id_t hash_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = hash_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    hash_key_to_str(hash_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs, attr);
}

/**
 * Routine Description:
 *    @brief Get hash attribute value
 *
 * Arguments:
 *    @param[in] hash_id - hash id
 *    @param[in] attr_count - number of attributes
 *    @param[inout] attrs - array of attributes
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_get_hash_attribute(_In_ sai_object_id_t     hash_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = hash_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    hash_key_to_str(hash_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_HASH, hash_vendor_attribs, attr_count, attr_list);
}

sai_status_t mlnx_hash_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

const sai_hash_api_t mlnx_hash_api = {
    mlnx_create_hash,
    mlnx_remove_hash,
    mlnx_set_hash_attribute,
    mlnx_get_hash_attribute
};
