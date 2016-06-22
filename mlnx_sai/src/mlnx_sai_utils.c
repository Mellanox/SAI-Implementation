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
#include "inttypes.h"
#ifndef WIN32
#include <arpa/inet.h>
#else
#include <Ws2tcpip.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_UTILS

static sai_status_t sai_qos_map_to_str_oid(_In_ sai_object_id_t       qos_map_id,
                                           _In_ sai_attribute_value_t value,
                                           _In_ uint32_t              max_length,
                                           _Out_ char                *value_str);
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t sdk_to_sai(sx_status_t status)
{
    switch (status) {
    case SX_STATUS_SUCCESS:
        return SAI_STATUS_SUCCESS;

    case SX_STATUS_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_MODULE_UNINITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_SDK_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_INVALID_HANDLE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_COMM_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_NO_RESOURCES:
        return SAI_STATUS_INSUFFICIENT_RESOURCES;

    case SX_STATUS_NO_MEMORY:
        return SAI_STATUS_NO_MEMORY;

    case SX_STATUS_MEMORY_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_ERROR:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_INCOMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_CMD_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_CMD_UNPERMITTED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARAM_NULL:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_ERROR:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_PARAM_EXCEEDS_RANGE:
        return SAI_STATUS_INVALID_PARAMETER;

    case SX_STATUS_MESSAGE_SIZE_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_MESSAGE_SIZE_EXCEEDS_LIMIT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_DB_ALREADY_INITIALIZED:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_DB_NOT_INITIALIZED:
        return SAI_STATUS_UNINITIALIZED;

    case SX_STATUS_DB_NOT_EMPTY:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_END_OF_DB:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_NOT_FOUND:
        return SAI_STATUS_ITEM_NOT_FOUND;

    case SX_STATUS_ENTRY_ALREADY_EXISTS:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;

    case SX_STATUS_ENTRY_NOT_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_ENTRY_ALREADY_BOUND:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_WRONG_POLICER_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNEXPECTED_EVENT_TYPE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TRAP_ID_NOT_CONFIGURED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_INT_COMM_CLOSE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_RESOURCE_IN_USE:
        return SAI_STATUS_OBJECT_IN_USE;

    case SX_STATUS_EVENT_TRAP_ALREADY_ASSOCIATED:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_TIMEOUT:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_UNSUPPORTED:
        return SAI_STATUS_NOT_SUPPORTED;

    case SX_STATUS_SX_UTILS_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_PARTIALLY_COMPLETE:
        return SAI_STATUS_FAILURE;

    case SX_STATUS_SXD_RETURNED_NON_ZERO:
        return SAI_STATUS_FAILURE;

    default:
        SX_LOG_NTC("Unexpected status code %d, mapping to failure\n", status);
        return SAI_STATUS_FAILURE;
    }
}

static sai_status_t find_functionality_attrib_index(_In_ const sai_attr_id_t          id,
                                                    _In_ const sai_attribute_entry_t *functionality_attr,
                                                    _Out_ uint32_t                   *index)
{
    uint32_t curr_index;

    SX_LOG_ENTER();

    if (NULL == functionality_attr) {
        SX_LOG_ERR("NULL value functionality attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_FUNCTIONALITY_ATTRIBS_ID != functionality_attr[curr_index].id; curr_index++) {
        if (id == functionality_attr[curr_index].id) {
            *index = curr_index;
            SX_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}


sai_status_t check_attribs_metadata(_In_ uint32_t                            attr_count,
                                    _In_ const sai_attribute_t              *attr_list,
                                    _In_ const sai_attribute_entry_t        *functionality_attr,
                                    _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                    _In_ sai_common_api_t                    oper)
{
    uint32_t functionality_attr_count, ii, index;
    bool    *attr_present;

    SX_LOG_ENTER();

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_attr) {
        SX_LOG_ERR("NULL value functionality attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_COMMON_API_MAX <= oper) {
        SX_LOG_ERR("Invalid operation %d\n", oper);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_COMMON_API_REMOVE == oper) {
        /* No attributes expected for remove at this point */
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (SAI_COMMON_API_SET == oper) {
        if (1 != attr_count) {
            SX_LOG_ERR("Set operation supports only single attribute\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (functionality_attr_count = 0;
         END_FUNCTIONALITY_ATTRIBS_ID != functionality_attr[functionality_attr_count].id;
         functionality_attr_count++) {
        if (functionality_attr[functionality_attr_count].id !=
            functionality_vendor_attr[functionality_attr_count].id) {
            SX_LOG_ERR("Mismatch between functionality attribute and vendor attribute index %u %u %u\n",
                       functionality_attr_count, functionality_attr[functionality_attr_count].id,
                       functionality_vendor_attr[functionality_attr_count].id);
            return SAI_STATUS_FAILURE;
        }
    }

    attr_present = (bool*)calloc(functionality_attr_count, sizeof(bool));
    if (NULL == attr_present) {
        SX_LOG_ERR("Can't allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (SAI_STATUS_SUCCESS != find_functionality_attrib_index(attr_list[ii].id, functionality_attr, &index)) {
            SX_LOG_ERR("Invalid attribute %d\n", attr_list[ii].id);
            free(attr_present);
            return SAI_STATUS_UNKNOWN_ATTRIBUTE_0 + ii;
        }

        if ((SAI_COMMON_API_CREATE == oper) &&
            (!(functionality_attr[index].valid_for_create))) {
            SX_LOG_ERR("Invalid attribute %s for create\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if ((SAI_COMMON_API_SET == oper) &&
            (!(functionality_attr[index].valid_for_set))) {
            SX_LOG_ERR("Invalid attribute %s for set\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if ((SAI_COMMON_API_GET == oper) &&
            (!(functionality_attr[index].valid_for_get))) {
            SX_LOG_ERR("Invalid attribute %s for get\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if (!(functionality_vendor_attr[index].is_supported[oper])) {
            SX_LOG_ERR("Not supported attribute %s\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + ii;
        }

        if (!(functionality_vendor_attr[index].is_implemented[oper])) {
            SX_LOG_ERR("Not implemented attribute %s\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        if (attr_present[index]) {
            SX_LOG_ERR("Attribute %s appears twice in attribute list at index %d\n",
                       functionality_attr[index].attrib_name,
                       ii);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if (((SAI_ATTR_VAL_TYPE_OBJLIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.objlist.list)) ||
            ((SAI_ATTR_VAL_TYPE_U8LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.u8list.list)) ||
            ((SAI_ATTR_VAL_TYPE_S8LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.s8list.list)) ||
            ((SAI_ATTR_VAL_TYPE_U16LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.u16list.list)) ||
            ((SAI_ATTR_VAL_TYPE_S16LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.s16list.list)) ||
            ((SAI_ATTR_VAL_TYPE_U32LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.u32list.list)) ||
            ((SAI_ATTR_VAL_TYPE_S32LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.s32list.list)) ||
            ((SAI_ATTR_VAL_TYPE_VLANPORTLIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.vlanportlist.list)) ||
            ((SAI_ATTR_VAL_TYPE_PORTBREAKOUT == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.portbreakout.port_list.list)) ||
            ((SAI_ATTR_VAL_TYPE_VLANLIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.vlanlist.list)) ||
            ((SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.aclfield.data.objlist.list)) ||
            ((SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.aclfield.data.u8list.list)) ||
            ((SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.aclfield.mask.u8list.list)) ||
            ((SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.aclaction.parameter.objlist.list)) ||
            ((SAI_ATTR_VAL_TYPE_TUNNELMAP == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.tunnelmap.list)) ||
            ((SAI_ATTR_VAL_TYPE_QOSMAP == functionality_attr[index].type) &&
             (NULL == attr_list[ii].value.qosmap.list))) {
            SX_LOG_ERR("Null list attribute %s at index %d\n",
                       functionality_attr[index].attrib_name,
                       ii);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + ii;
        }

        if (SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == functionality_attr[index].type) {
            if (attr_list[ii].value.aclfield.data.u8list.count != attr_list[ii].value.aclfield.mask.u8list.count) {
                SX_LOG_ERR("Mismatch between data list count %u and mask list count %u attribute %s at index %d\n",
                           attr_list[ii].value.aclfield.data.u8list.count,
                           attr_list[ii].value.aclfield.mask.u8list.count,
                           functionality_attr[index].attrib_name,
                           ii);
                free(attr_present);
                return SAI_STATUS_INVALID_ATTR_VALUE_0 + ii;
            }
        }

        attr_present[index] = true;
    }

    if (SAI_COMMON_API_CREATE == oper) {
        for (ii = 0; ii < functionality_attr_count; ii++) {
            if ((functionality_attr[ii].mandatory_on_create) &&
                (!attr_present[ii])) {
                SX_LOG_ERR("Missing mandatory attribute %s on create\n", functionality_attr[ii].attrib_name);
                free(attr_present);
                return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            }
        }
    }

    free(attr_present);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t set_dispatch_attrib_handler(_In_ const sai_attribute_t              *attr,
                                                _In_ const sai_attribute_entry_t        *functionality_attr,
                                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                                _In_ const sai_object_key_t             *key,
                                                _In_ const char                         *key_str)
{
    uint32_t     index;
    sai_status_t err;
    char         value_str[MAX_VALUE_STR_LEN];

    SX_LOG_ENTER();

    if (NULL == attr) {
        SX_LOG_ERR("NULL value attr\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_attr) {
        SX_LOG_ERR("NULL value functionality attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    assert(SAI_STATUS_SUCCESS == find_functionality_attrib_index(attr->id, functionality_attr, &index));

    if (!functionality_vendor_attr[index].setter) {
        SX_LOG_ERR("Attribute %s not implemented on set and defined incorrectly\n",
                   functionality_attr[index].attrib_name);
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0;
    }

    if (functionality_attr[index].type == SAI_ATTR_VAL_TYPE_QOSMAP) {
        sai_qos_map_to_str_oid(key->object_id, attr->value, MAX_VALUE_STR_LEN, value_str);
    } else {
        sai_value_to_str(attr->value, functionality_attr[index].type, MAX_VALUE_STR_LEN, value_str);
    }
    SX_LOG_NTC("Set %s, key:%s, val:%s\n", functionality_attr[index].attrib_name, key_str, value_str);
    err = functionality_vendor_attr[index].setter(key, &(attr->value), functionality_vendor_attr[index].setter_arg);

    SX_LOG_EXIT();
    return err;
}

static sai_status_t get_dispatch_attribs_handler(_In_ uint32_t                            attr_count,
                                                 _Inout_ sai_attribute_t                 *attr_list,
                                                 _In_ const sai_attribute_entry_t        *functionality_attr,
                                                 _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                                 _In_ const sai_object_key_t             *key,
                                                 _In_ const char                         *key_str)
{
    uint32_t       ii, index;
    vendor_cache_t cache;
    sai_status_t   status;
    char           value_str[MAX_VALUE_STR_LEN];

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_attr) {
        SX_LOG_ERR("NULL value functionality attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_vendor_attr) {
        SX_LOG_ERR("NULL value functionality vendor attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(&cache, 0, sizeof(cache));

    for (ii = 0; ii < attr_count; ii++) {
        assert(SAI_STATUS_SUCCESS == find_functionality_attrib_index(attr_list[ii].id, functionality_attr, &index));

        if (!functionality_vendor_attr[index].getter) {
            SX_LOG_ERR("Attribute %s not implemented on get and defined incorrectly\n",
                       functionality_attr[index].attrib_name);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        if (SAI_STATUS_SUCCESS !=
            (status =
                 functionality_vendor_attr[index].getter(key, &(attr_list[ii].value), ii, &cache,
                                                         functionality_vendor_attr[index].getter_arg))) {
            SX_LOG_ERR("Failed getting attrib %s\n", functionality_attr[index].attrib_name);
            return status;
        }
        if (functionality_attr[index].type == SAI_ATTR_VAL_TYPE_QOSMAP) {
            sai_qos_map_to_str_oid(key->object_id, attr_list[ii].value, MAX_VALUE_STR_LEN, value_str);
        } else {
            sai_value_to_str(attr_list[ii].value, functionality_attr[index].type, MAX_VALUE_STR_LEN, value_str);
        }
        SX_LOG_NTC("Got #%u, %s, key:%s, val:%s\n", ii, functionality_attr[index].attrib_name, key_str, value_str);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t find_attrib_in_list(_In_ uint32_t                       attr_count,
                                 _In_ const sai_attribute_t         *attr_list,
                                 _In_ sai_attr_id_t                  attrib_id,
                                 _Out_ const sai_attribute_value_t **attr_value,
                                 _Out_ uint32_t                     *index)
{
    uint32_t ii;

    SX_LOG_ENTER();

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == attr_value) {
        SX_LOG_ERR("NULL value attr value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == index) {
        SX_LOG_ERR("NULL value index\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (attr_list[ii].id == attrib_id) {
            *attr_value = &(attr_list[ii].value);
            *index      = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

sai_status_t sai_set_attribute(_In_ const sai_object_key_t             *key,
                               _In_ const char                         *key_str,
                               _In_ const sai_attribute_entry_t        *functionality_attr,
                               _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                               _In_ const sai_attribute_t              *attr)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(1, attr, functionality_attr, functionality_vendor_attr, SAI_COMMON_API_SET))) {
        SX_LOG_ERR("Failed attribs check, key:%s\n", key_str);
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = set_dispatch_attrib_handler(attr, functionality_attr, functionality_vendor_attr, key, key_str))) {
        SX_LOG_ERR("Failed set attrib dispatch\n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_attributes(_In_ const sai_object_key_t             *key,
                                _In_ const char                         *key_str,
                                _In_ const sai_attribute_entry_t        *functionality_attr,
                                _In_ const sai_vendor_attribute_entry_t *functionality_vendor_attr,
                                _In_ uint32_t                            attr_count,
                                _Inout_ sai_attribute_t                 *attr_list)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, functionality_attr, functionality_vendor_attr,
                                    SAI_COMMON_API_GET))) {
        SX_LOG_ERR("Failed attribs check, key:%s\n", key_str);
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             get_dispatch_attribs_handler(attr_count, attr_list, functionality_attr, functionality_vendor_attr, key,
                                          key_str))) {
        SX_LOG_ERR("Failed attribs dispatch\n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_ipv4_to_str(_In_ sai_ip4_t value,
                                    _In_ uint32_t  max_length,
                                    _Out_ char    *value_str,
                                    _Out_ int     *chars_written)
{
    inet_ntop(AF_INET, &value, value_str, max_length);

    if (NULL != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_ipv6_to_str(_In_ sai_ip6_t value,
                                    _In_ uint32_t  max_length,
                                    _Out_ char    *value_str,
                                    _Out_ int     *chars_written)
{
    inet_ntop(AF_INET6, value, value_str, max_length);

    if (NULL != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
                               _In_ uint32_t         max_length,
                               _Out_ char           *value_str,
                               _Out_ int            *chars_written)
{
    int res;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, chars_written);
    } else {
        res = snprintf(value_str, max_length, "Invalid ipaddr family %d", value.addr_family);
        if (NULL != chars_written) {
            *chars_written = res;
        }
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char *value_str)
{
    int      chars_written;
    uint32_t pos = 0;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv4_to_str(value.mask.ip4, max_length - pos, value_str + pos, &chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv6_to_str(value.mask.ip6, max_length - pos, value_str + pos, &chars_written);
    } else {
        snprintf(value_str, max_length, "Invalid addr family %d", value.addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_ip_address_to_sdk(_In_ const sai_ip_address_t *sai_addr, _Out_ sx_ip_addr_t *sdk_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_addr->addr_family) {
        /* SDK IPv4 is in host order, while SAI is in network order */
        sdk_addr->version          = SX_IP_VERSION_IPV4;
        sdk_addr->addr.ipv4.s_addr = ntohl(sai_addr->addr.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_addr->addr_family) {
        /* SDK IPv6 is 4*uint32. Each uint32 is in host order. Between uint32s there is network byte order */
        sdk_addr->version = SX_IP_VERSION_IPV6;
        from              = (uint32_t*)sai_addr->addr.ip6;
        to                = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = ntohl(from[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sai_addr->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_ip_address_to_sai(_In_ const sx_ip_addr_t *sdk_addr, _Out_ sai_ip_address_t *sai_addr)
{
    int       ii;
    uint32_t *from, *to;

    if (SX_IP_VERSION_IPV4 == sdk_addr->version) {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_addr->addr.ip4    = htonl(sdk_addr->addr.ipv4.s_addr);
    } else if (SX_IP_VERSION_IPV6 == sdk_addr->version) {
        sai_addr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from                  = (uint32_t*)sdk_addr->addr.ipv6.s6_addr32;
        to                    = (uint32_t*)sai_addr->addr.ip6;

        for (ii = 0; ii < 4; ii++) {
            to[ii] = htonl(from[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_addr->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_ip_prefix_to_sdk(_In_ const sai_ip_prefix_t *sai_prefix,
                                                 _Out_ sx_ip_prefix_t       *sdk_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SAI_IP_ADDR_FAMILY_IPV4 == sai_prefix->addr_family) {
        sdk_prefix->version                 = SX_IP_VERSION_IPV4;
        sdk_prefix->prefix.ipv4.addr.s_addr = ntohl(sai_prefix->addr.ip4);
        sdk_prefix->prefix.ipv4.mask.s_addr = ntohl(sai_prefix->mask.ip4);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == sai_prefix->addr_family) {
        sdk_prefix->version = SX_IP_VERSION_IPV6;

        from_addr = (uint32_t*)sai_prefix->addr.ip6;
        to_addr   = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;

        from_mask = (uint32_t*)sai_prefix->mask.ip6;
        to_mask   = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sai_prefix->addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_ip_prefix_to_sai(_In_ const sx_ip_prefix_t *sdk_prefix,
                                                 _Out_ sai_ip_prefix_t     *sai_prefix)
{
    int       ii;
    uint32_t *from_addr, *to_addr, *from_mask, *to_mask;

    if (SX_IP_VERSION_IPV4 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        sai_prefix->addr.ip4    = htonl(sdk_prefix->prefix.ipv4.addr.s_addr);
        sai_prefix->mask.ip4    = htonl(sdk_prefix->prefix.ipv4.mask.s_addr);
    } else if (SX_IP_VERSION_IPV6 == sdk_prefix->version) {
        sai_prefix->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        from_addr               = (uint32_t*)sdk_prefix->prefix.ipv6.addr.s6_addr32;
        to_addr                 = (uint32_t*)sai_prefix->addr.ip6;

        from_mask = (uint32_t*)sdk_prefix->prefix.ipv6.mask.s6_addr32;
        to_mask   = (uint32_t*)sai_prefix->mask.ip6;

        for (ii = 0; ii < 4; ii++) {
            to_addr[ii] = htonl(from_addr[ii]);
            to_mask[ii] = htonl(from_mask[ii]);
        }
    } else {
        SX_LOG_ERR("Invalid addr family %d\n", sdk_prefix->version);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_nexthops_to_str(_In_ uint32_t               next_hop_count,
                                 _In_ const sai_object_id_t* nexthops,
                                 _In_ uint32_t               max_length,
                                 _Out_ char                 *str)
{
    uint32_t     ii;
    uint32_t     pos = 0;
    uint32_t     nexthop_id;
    sai_status_t status;

    pos += snprintf(str, max_length, "%u hops : [", next_hop_count);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }
    for (ii = 0; ii < next_hop_count; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status = mlnx_object_to_type(nexthops[ii], SAI_OBJECT_TYPE_NEXT_HOP, &nexthop_id, NULL))) {
            snprintf(str + pos, max_length - pos, " invalid next hop]");
            return status;
        }

        pos += snprintf(str + pos, max_length - pos, " %u", nexthop_id);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
    }
    snprintf(str + pos, max_length - pos, "]");

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_qos_map_to_str(_In_ const sai_qos_map_list_t *qosmap,
                                _In_ sai_qos_map_type_t        type,
                                _In_ uint32_t                  max_length,
                                _Out_ char                    *value_str)
{
    sai_qos_map_t *list;
    uint32_t       count;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    uint32_t       pos    = 0;
    uint32_t       ii;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *value_str = '\0';

    if (!qosmap) {
        return SAI_STATUS_SUCCESS;
    }

    list  = qosmap->list;
    count = qosmap->count;

    if (!count || !list) {
        return SAI_STATUS_SUCCESS;
    }

    pos += snprintf(value_str + pos, max_length - pos, "%u : [", count);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < count; ii++) {
        switch (type) {
        case SAI_QOS_MAP_DOT1P_TO_TC:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dot1p, list[ii].value.tc);
            break;

        case SAI_QOS_MAP_DOT1P_TO_COLOR:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dot1p, list[ii].value.color);
            break;

        case SAI_QOS_MAP_DSCP_TO_TC:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dscp, list[ii].value.tc);
            break;

        case SAI_QOS_MAP_DSCP_TO_COLOR:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.dscp, list[ii].value.color);
            break;

        case SAI_QOS_MAP_TC_TO_QUEUE:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.tc, list[ii].value.queue_index);
            break;

        case SAI_QOS_MAP_TC_AND_COLOR_TO_DSCP:
            pos += snprintf(value_str + pos, max_length - pos, "(%u,%u)->%u",
                            list[ii].key.tc, list[ii].key.color,
                            list[ii].value.dscp);
            break;

        case SAI_QOS_MAP_TC_AND_COLOR_TO_DOT1P:
            pos += snprintf(value_str + pos, max_length - pos, "(%u,%u)->%u",
                            list[ii].key.tc, list[ii].key.color,
                            list[ii].value.dot1p);
            break;

        case SAI_QOS_MAP_TC_TO_PRIORITY_GROUP:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.tc, list[ii].value.pg);
            break;

        case SAI_QOS_MAP_PFC_PRIORITY_TO_PRIORITY_GROUP:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.pg, list[ii].value.prio);
            break;

        case SAI_QOS_MAP_PFC_PRIORITY_TO_QUEUE:
            pos += snprintf(value_str + pos, max_length - pos, "%u->%u",
                            list[ii].key.prio, list[ii].value.queue_index);
            break;

        default:
            status = SAI_STATUS_NOT_SUPPORTED;
            break;
        }

        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        if (ii < count - 1) {
            pos += snprintf(value_str + pos, max_length - pos, ",");
        }
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
    }

    snprintf(value_str + pos, max_length - pos, "]");
    return status;
}

static sai_status_t sai_qos_map_to_str_oid(_In_ sai_object_id_t       qos_map_id,
                                           _In_ sai_attribute_value_t value,
                                           _In_ uint32_t              max_length,
                                           _Out_ char                *value_str)
{
    mlnx_qos_map_t *qos_map;
    sai_status_t    status;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *value_str = '\0';

    if (!value.qosmap.count || !value.qosmap.list) {
        return SAI_STATUS_SUCCESS;
    }

    sai_db_read_lock();

    status = mlnx_qos_map_get_by_id(qos_map_id, &qos_map);
    if (status != SAI_STATUS_SUCCESS) {
        sai_db_unlock();
        return status;
    }

    sai_db_unlock();

    return sai_qos_map_to_str(&value.qosmap, qos_map->type, max_length, value_str);
}

sai_status_t sai_value_to_str(_In_ sai_attribute_value_t      value,
                              _In_ sai_attribute_value_type_t type,
                              _In_ uint32_t                   max_length,
                              _Out_ char                     *value_str)
{
    uint32_t          ii;
    uint32_t          pos = 0;
    uint32_t          count;
    mlnx_object_id_t *mlnx_object_id;
    int               chars_written;

    if (NULL == value_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *value_str = '\0';

    switch (type) {
    case SAI_ATTR_VAL_TYPE_BOOL:
        snprintf(value_str, max_length, "%u", value.booldata);
        break;

    case SAI_ATTR_VAL_TYPE_CHARDATA:
        snprintf(value_str, max_length, "%s", value.chardata);
        break;

    case SAI_ATTR_VAL_TYPE_U8:
        snprintf(value_str, max_length, "%u", value.u8);
        break;

    case SAI_ATTR_VAL_TYPE_S8:
        snprintf(value_str, max_length, "%d", value.s8);
        break;

    case SAI_ATTR_VAL_TYPE_U16:
        snprintf(value_str, max_length, "%u", value.u16);
        break;

    case SAI_ATTR_VAL_TYPE_S16:
        snprintf(value_str, max_length, "%d", value.s16);
        break;

    case SAI_ATTR_VAL_TYPE_U32:
        snprintf(value_str, max_length, "%u", value.u32);
        break;

    case SAI_ATTR_VAL_TYPE_S32:
        snprintf(value_str, max_length, "%d", value.s32);
        break;

    case SAI_ATTR_VAL_TYPE_U64:
        snprintf(value_str, max_length, "%" PRIu64, value.u64);
        break;

    case SAI_ATTR_VAL_TYPE_S64:
        snprintf(value_str, max_length, "%" PRId64, value.s64);
        break;

    case SAI_ATTR_VAL_TYPE_MAC:
        snprintf(value_str, max_length, "[%02x:%02x:%02x:%02x:%02x:%02x]",
                 value.mac[0],
                 value.mac[1],
                 value.mac[2],
                 value.mac[3],
                 value.mac[4],
                 value.mac[5]);
        break;

    /* IP is in network order */
    case SAI_ATTR_VAL_TYPE_IPV4:
        sai_ipv4_to_str(value.ip4, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_IPV6:
        sai_ipv6_to_str(value.ip6, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_IPADDR:
        sai_ipaddr_to_str(value.ipaddr, max_length, value_str, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_OID:
        mlnx_object_id = (mlnx_object_id_t*)&value.oid;
        snprintf(value_str, max_length, "%s,%x,%02x%02x%02x",
                 SAI_TYPE_STR(sai_object_type_query(value.oid)), mlnx_object_id->data,
                 mlnx_object_id->extended_data[2], mlnx_object_id->extended_data[1], mlnx_object_id->extended_data[0]);
        break;

    case SAI_ATTR_VAL_TYPE_OBJLIST:
    case SAI_ATTR_VAL_TYPE_U8LIST:
    case SAI_ATTR_VAL_TYPE_S8LIST:
    case SAI_ATTR_VAL_TYPE_U16LIST:
    case SAI_ATTR_VAL_TYPE_S16LIST:
    case SAI_ATTR_VAL_TYPE_U32LIST:
    case SAI_ATTR_VAL_TYPE_S32LIST:
    case SAI_ATTR_VAL_TYPE_VLANLIST:
    case SAI_ATTR_VAL_TYPE_VLANPORTLIST:
    case SAI_ATTR_VAL_TYPE_PORTBREAKOUT:
    case SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST:
    case SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST:
    case SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST:
    case SAI_ATTR_VAL_TYPE_TUNNELMAP:
        if (SAI_ATTR_VAL_TYPE_PORTBREAKOUT == type) {
            pos += snprintf(value_str, max_length, "breakout mode %d.", value.portbreakout.breakout_mode);
        }
        if ((SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST == type) ||
            (SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == type)) {
            pos += snprintf(value_str, max_length, "%u", value.aclfield.enable);
        }
        if (SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST == type) {
            pos += snprintf(value_str, max_length, "%u", value.aclaction.enable);
        }
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }

        count = (SAI_ATTR_VAL_TYPE_OBJLIST == type) ? value.objlist.count :
                (SAI_ATTR_VAL_TYPE_U8LIST == type) ? value.u8list.count :
                (SAI_ATTR_VAL_TYPE_S8LIST == type) ? value.s8list.count :
                (SAI_ATTR_VAL_TYPE_U16LIST == type) ? value.u16list.count :
                (SAI_ATTR_VAL_TYPE_S16LIST == type) ? value.s16list.count :
                (SAI_ATTR_VAL_TYPE_U32LIST == type) ? value.u32list.count :
                (SAI_ATTR_VAL_TYPE_S32LIST == type) ? value.s32list.count :
                (SAI_ATTR_VAL_TYPE_VLANLIST == type) ? value.vlanlist.count :
                (SAI_ATTR_VAL_TYPE_VLANPORTLIST == type) ? value.vlanportlist.count :
                (SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST == type) ? value.aclfield.data.objlist.count :
                (SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == type) ? value.aclfield.data.u8list.count :
                (SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST == type) ? value.aclaction.parameter.objlist.count :
                (SAI_ATTR_VAL_TYPE_TUNNELMAP == type) ? value.tunnelmap.count :
                value.portbreakout.port_list.count;
        pos += snprintf(value_str + pos, max_length - pos, "%u : [", count);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }

        for (ii = 0; ii < count; ii++) {
            if (SAI_ATTR_VAL_TYPE_OBJLIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %" PRIx64, value.objlist.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_U8LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u8list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_S8LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s8list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_U16LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u16list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_S16LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s16list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_U32LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.u32list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_S32LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %d", value.s32list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_VLANLIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %u", value.vlanlist.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_VLANPORTLIST == type) {
                pos += snprintf(value_str + pos,
                                max_length - pos,
                                " %" PRIx64 "%s",
                                value.vlanportlist.list[ii].port_id,
                                (SAI_VLAN_PORT_UNTAGGED == value.vlanportlist.list[ii].tagging_mode) ? "U" :
                                (SAI_VLAN_PORT_TAGGED == value.vlanportlist.list[ii].tagging_mode) ? "T" : "PT");
            } else if (SAI_ATTR_VAL_TYPE_ACLFIELD_OBJLIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %" PRIx64, value.aclfield.data.objlist.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_ACLFIELD_U8LIST == type) {
                pos += snprintf(value_str + pos, max_length - pos, " %02x,%02x",
                                value.aclfield.data.u8list.list[ii], value.aclfield.mask.u8list.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_ACLACTION_OBJLIST == type) {
                pos +=
                    snprintf(value_str + pos, max_length - pos, " %" PRIx64,
                             value.aclaction.parameter.objlist.list[ii]);
            } else if (SAI_ATTR_VAL_TYPE_TUNNELMAP == type) {
                pos +=
                    snprintf(value_str + pos, max_length - pos, " %u,%u,%u,%u->%u,%u,%u,%u",
                             value.tunnelmap.list[ii].key.oecn, value.tunnelmap.list[ii].key.uecn,
                             value.tunnelmap.list[ii].key.vlan_id, value.tunnelmap.list[ii].key.vni_id,
                             value.tunnelmap.list[ii].value.oecn, value.tunnelmap.list[ii].value.uecn,
                             value.tunnelmap.list[ii].value.vlan_id, value.tunnelmap.list[ii].value.vni_id);
            } else {
                pos += snprintf(value_str + pos, max_length - pos, " %" PRIx64, value.portbreakout.port_list.list[ii]);
            }
            if (pos > max_length) {
                return SAI_STATUS_SUCCESS;
            }
        }
        snprintf(value_str + pos, max_length - pos, "]");
        break;

    case SAI_ATTR_VAL_TYPE_U32RANGE:
        snprintf(value_str, max_length, "[%u,%u]", value.u32range.min, value.u32range.max);
        break;

    case SAI_ATTR_VAL_TYPE_S32RANGE:
        snprintf(value_str, max_length, "[%d,%d]", value.s32range.min, value.s32range.max);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_BOOLDATA:
        snprintf(value_str,
                 max_length,
                 "%u,%02x",
                 value.aclfield.enable,
                 value.aclfield.data.booldata);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_U8:
        snprintf(value_str,
                 max_length,
                 "%u,%02x,%02x",
                 value.aclfield.enable,
                 value.aclfield.data.u8,
                 value.aclfield.mask.u8);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_U16:
        snprintf(value_str,
                 max_length,
                 "%u,%04x,%04x",
                 value.aclfield.enable,
                 value.aclfield.data.u16,
                 value.aclfield.mask.u16);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_U32:
        snprintf(value_str,
                 max_length,
                 "%u,%08x,%08x",
                 value.aclfield.enable,
                 value.aclfield.data.u32,
                 value.aclfield.mask.u32);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_S8:
        snprintf(value_str,
                 max_length,
                 "%u,%02x,%02x",
                 value.aclfield.enable,
                 value.aclfield.data.s8,
                 value.aclfield.mask.s8);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_S16:
        snprintf(value_str,
                 max_length,
                 "%u,%04x,%04x",
                 value.aclfield.enable,
                 value.aclfield.data.s16,
                 value.aclfield.mask.s16);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_S32:
        snprintf(value_str,
                 max_length,
                 "%u,%08x,%08x",
                 value.aclfield.enable,
                 value.aclfield.data.s32,
                 value.aclfield.mask.s32);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_MAC:
        snprintf(value_str, max_length, "%u,[%02x:%02x:%02x:%02x:%02x:%02x],[%02x:%02x:%02x:%02x:%02x:%02x]",
                 value.aclfield.enable,
                 value.aclfield.data.mac[0],
                 value.aclfield.data.mac[1],
                 value.aclfield.data.mac[2],
                 value.aclfield.data.mac[3],
                 value.aclfield.data.mac[4],
                 value.aclfield.data.mac[5],
                 value.aclfield.mask.mac[0],
                 value.aclfield.mask.mac[1],
                 value.aclfield.mask.mac[2],
                 value.aclfield.mask.mac[3],
                 value.aclfield.mask.mac[4],
                 value.aclfield.mask.mac[5]);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_IPV4:
        pos += snprintf(value_str, max_length, "%u,", value.aclfield.enable);
        sai_ipv4_to_str(value.aclfield.data.ip4, max_length - pos, value_str + pos, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, ",");
        sai_ipv4_to_str(value.aclfield.mask.ip4, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_IPV6:
        pos += snprintf(value_str, max_length, "%u,", value.aclfield.enable);
        sai_ipv6_to_str(value.aclfield.data.ip6, max_length - pos, value_str + pos, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, ",");
        sai_ipv6_to_str(value.aclfield.mask.ip6, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_ACLFIELD_OID:
        mlnx_object_id = (mlnx_object_id_t*)&value.aclfield.data.oid;
        snprintf(value_str, max_length, "%u,%s,%x,%02x%02x%02x",
                 value.aclfield.enable, SAI_TYPE_STR(sai_object_type_query(
                                                         value.aclfield.data.oid)), mlnx_object_id->data,
                 mlnx_object_id->extended_data[2], mlnx_object_id->extended_data[1], mlnx_object_id->extended_data[0]);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_U8:
        snprintf(value_str, max_length, "%u,%u", value.aclaction.enable, value.aclaction.parameter.u8);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_U16:
        snprintf(value_str, max_length, "%u,%u", value.aclaction.enable, value.aclaction.parameter.u16);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_U32:
        snprintf(value_str, max_length, "%u,%u", value.aclaction.enable, value.aclaction.parameter.u32);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_S8:
        snprintf(value_str, max_length, "%u,%d", value.aclaction.enable, value.aclaction.parameter.s8);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_S16:
        snprintf(value_str, max_length, "%u,%d", value.aclaction.enable, value.aclaction.parameter.s16);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_S32:
        snprintf(value_str, max_length, "%u,%d", value.aclaction.enable, value.aclaction.parameter.s32);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_MAC:
        snprintf(value_str, max_length, "%u,[%02x:%02x:%02x:%02x:%02x:%02x]",
                 value.aclaction.enable,
                 value.aclaction.parameter.mac[0],
                 value.aclaction.parameter.mac[1],
                 value.aclaction.parameter.mac[2],
                 value.aclaction.parameter.mac[3],
                 value.aclaction.parameter.mac[4],
                 value.aclaction.parameter.mac[5]);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_IPV4:
        pos += snprintf(value_str, max_length, "%u,", value.aclaction.enable);
        sai_ipv4_to_str(value.aclaction.parameter.ip4, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_IPV6:
        pos += snprintf(value_str, max_length, "%u,", value.aclaction.enable);
        sai_ipv6_to_str(value.aclaction.parameter.ip6, max_length - pos, value_str + pos, NULL);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_OID:
        mlnx_object_id = (mlnx_object_id_t*)&value.aclaction.parameter.oid;
        snprintf(value_str, max_length, "%u,%s,%x,%02x%02x%02x",
                 value.aclaction.enable, SAI_TYPE_STR(sai_object_type_query(
                                                          value.aclaction.parameter.oid)), mlnx_object_id->data,
                 mlnx_object_id->extended_data[2], mlnx_object_id->extended_data[1], mlnx_object_id->extended_data[0]);
        break;

    case SAI_ATTR_VAL_TYPE_ACLACTION_NONE:
        snprintf(value_str, max_length, "%u", value.aclaction.enable);
        break;

    case SAI_ATTR_VAL_TYPE_UNDETERMINED:
    default:
        snprintf(value_str, max_length, "Invalid/Unsupported value type %d", type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_attr_list_to_str(_In_ uint32_t                     attr_count,
                                  _In_ const sai_attribute_t       *attr_list,
                                  _In_ const sai_attribute_entry_t *functionality_attr,
                                  _In_ uint32_t                     max_length,
                                  _Out_ char                       *list_str)
{
    uint32_t ii, index, pos = 0;
    char     value_str[MAX_VALUE_STR_LEN];

    if ((attr_count) && (NULL == attr_list)) {
        SX_LOG_ERR("NULL value attr list\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == functionality_attr) {
        SX_LOG_ERR("NULL value functionality attrib\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == list_str) {
        SX_LOG_ERR("NULL value str");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == attr_count) {
        snprintf(list_str, max_length, "empty list");
        return SAI_STATUS_SUCCESS;
    }

    for (ii = 0; ii < attr_count; ii++) {
        assert(SAI_STATUS_SUCCESS == find_functionality_attrib_index(attr_list[ii].id, functionality_attr, &index));

        sai_value_to_str(attr_list[ii].value, functionality_attr[index].type, MAX_VALUE_STR_LEN, value_str);
        pos += snprintf(list_str + pos,
                        max_length - pos,
                        "#%u %s=%s ",
                        ii,
                        functionality_attr[index].attrib_name,
                        value_str);
        if (pos > max_length) {
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_trap_action_to_sdk(sai_int32_t       action,
                                                   sx_trap_action_t *trap_action,
                                                   uint32_t          param_index)
{
    if (NULL == trap_action) {
        SX_LOG_ERR("NULL trap action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *trap_action = SX_TRAP_ACTION_IGNORE;
        break;

    case SAI_PACKET_ACTION_TRAP:
        *trap_action = SX_TRAP_ACTION_TRAP_2_CPU;
        break;

    case SAI_PACKET_ACTION_LOG:
        *trap_action = SX_TRAP_ACTION_MIRROR_2_CPU;
        break;

    case SAI_PACKET_ACTION_DROP:
        *trap_action = SX_TRAP_ACTION_DISCARD;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sai_router_action_to_sdk(sai_int32_t         action,
                                                     sx_router_action_t *router_action,
                                                     uint32_t            param_index)
{
    if (NULL == router_action) {
        SX_LOG_ERR("NULL router action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (action) {
    case SAI_PACKET_ACTION_FORWARD:
        *router_action = SX_ROUTER_ACTION_FORWARD;
        break;

    case SAI_PACKET_ACTION_TRAP:
        *router_action = SX_ROUTER_ACTION_TRAP;
        break;

    case SAI_PACKET_ACTION_LOG:
        *router_action = SX_ROUTER_ACTION_MIRROR;
        break;

    case SAI_PACKET_ACTION_DROP:
        *router_action = SX_ROUTER_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Invalid packet action %d\n", action);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + param_index;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_translate_sdk_router_action_to_sai(sx_router_action_t router_action, sai_int32_t *sai_action)
{
    if (NULL == sai_action) {
        SX_LOG_ERR("NULL sai action value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (router_action) {
    case SX_ROUTER_ACTION_FORWARD:
        *sai_action = SAI_PACKET_ACTION_FORWARD;
        break;

    case SX_ROUTER_ACTION_TRAP:
        *sai_action = SAI_PACKET_ACTION_TRAP;
        break;

    case SX_ROUTER_ACTION_MIRROR:
        *sai_action = SAI_PACKET_ACTION_LOG;
        break;

    case SX_ROUTER_ACTION_DROP:
        *sai_action = SAI_PACKET_ACTION_DROP;
        break;

    default:
        SX_LOG_ERR("Unexpected router action %d\n", router_action);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_object_to_type(sai_object_id_t   object_id,
                                 sai_object_type_t type,
                                 uint32_t         *data,
                                 uint8_t           extended_data[])
{
    mlnx_object_id_t *mlnx_object_id = (mlnx_object_id_t*)&object_id;

    if (NULL == data) {
        SX_LOG_ERR("NULL data value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (type != mlnx_object_id->object_type) {
        SX_LOG_ERR("Expected object %s got %s\n", SAI_TYPE_STR(type), SAI_TYPE_STR(mlnx_object_id->object_type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *data = mlnx_object_id->data;
    if (extended_data) {
        memcpy(extended_data, mlnx_object_id->extended_data, EXTENDED_DATA_SIZE);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_object(sai_object_type_t type,
                                uint32_t          data,
                                uint8_t           extended_data[],
                                sai_object_id_t  *object_id)
{
    mlnx_object_id_t *mlnx_object_id = (mlnx_object_id_t*)object_id;

    /* guarntee same size for general object id and mellanox prvivate implementation */
    int __attribute__((unused)) dummy[(sizeof(mlnx_object_id_t) == sizeof(sai_object_id_t) ? 1 : -1)];

    UNREFERENCED_PARAMETER(dummy);

    if (NULL == object_id) {
        SX_LOG_ERR("NULL object id value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (type >= SAI_OBJECT_TYPE_MAX) {
        SX_LOG_ERR("Unknown object type %d\n", type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(mlnx_object_id, 0, sizeof(*mlnx_object_id));
    mlnx_object_id->data        = data;
    mlnx_object_id->object_type = type;
    if (extended_data) {
        memcpy(mlnx_object_id->extended_data, extended_data, EXTENDED_DATA_SIZE);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_queue(_In_ sx_port_log_id_t port_id, _In_ uint8_t index, _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_QUEUE, port_id, ext_data, id);
}

sai_status_t mlnx_queue_parse_id(_In_ sai_object_id_t id, _Out_ sx_port_log_id_t *port_id, _Out_ uint8_t *queue_index)
{
    uint8_t      ext_data[EXTENDED_DATA_SIZE];
    sai_status_t status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_QUEUE, port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if (queue_index) {
        *queue_index = ext_data[0];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_create_sched_group(_In_ sx_port_log_id_t  port_id,
                                     _In_ uint8_t           level,
                                     _In_ uint8_t           index,
                                     _Out_ sai_object_id_t *id)
{
    uint8_t ext_data[EXTENDED_DATA_SIZE];

    memset(ext_data, 0, EXTENDED_DATA_SIZE);
    ext_data[0] = level;
    ext_data[1] = index;
    return mlnx_create_object(SAI_OBJECT_TYPE_SCHEDULER_GROUP, port_id, ext_data, id);
}

sai_status_t mlnx_sched_group_parse_id(_In_ sai_object_id_t    id,
                                       _Out_ sx_port_log_id_t *port_id_ptr,
                                       _Out_ uint8_t          *level_ptr,
                                       _Out_ uint8_t          *index_ptr)
{
    uint8_t          ext_data[EXTENDED_DATA_SIZE];
    sx_port_log_id_t port_id;
    sai_status_t     status;

    status = mlnx_object_to_type(id, SAI_OBJECT_TYPE_SCHEDULER_GROUP, &port_id, ext_data);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    if ((ext_data[0] == 0) && (ext_data[1] > 0)) {
        SX_LOG_ERR("Invalid root scheduler group index %u - max allowed value is 0\n", ext_data[1]);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (port_id_ptr) {
        *port_id_ptr = port_id;
    }
    if (level_ptr) {
        *level_ptr = ext_data[0];
    }
    if (index_ptr) {
        *index_ptr = ext_data[1];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_utils_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_fill_genericlist(size_t element_size, void *data, uint32_t count, void *list)
{
    /* all list objects have same field count in the beginning of the object, and then different data,
     * so can be casted to one type */
    sai_object_list_t *objlist = list;

    if (NULL == data) {
        SX_LOG_ERR("NULL data value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == list) {
        SX_LOG_ERR("NULL list value\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (0 == element_size) {
        SX_LOG_ERR("Zero element size\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (count > objlist->count) {
        SX_LOG_ERR("Insufficient list buffer size. Allocated %u needed %u\n",
                   objlist->count, count);
        objlist->count = count;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    objlist->count = count;
    memcpy(objlist->list, data, count * element_size);

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fill_objlist(sai_object_id_t *data, uint32_t count, sai_object_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_object_id_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u8list(uint8_t *data, uint32_t count, sai_u8_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint8_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s8list(int8_t *data, uint32_t count, sai_s8_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int8_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u16list(uint16_t *data, uint32_t count, sai_u16_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint16_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s16list(int16_t *data, uint32_t count, sai_s16_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int16_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_u32list(uint32_t *data, uint32_t count, sai_u32_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(uint32_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_s32list(int32_t *data, uint32_t count, sai_s32_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(int32_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_vlanlist(sai_vlan_id_t *data, uint32_t count, sai_vlan_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_vlan_id_t), (void*)data, count, (void*)list);
}

sai_status_t mlnx_fill_vlanportlist(sai_vlan_port_t *data, uint32_t count, sai_vlan_port_list_t *list)
{
    return mlnx_fill_genericlist(sizeof(sai_vlan_port_t), (void*)data, count, (void*)list);
}

bool mlnx_route_entries_are_equal(_In_ const sai_unicast_route_entry_t *u1, _In_ const sai_unicast_route_entry_t *u2)
{
    if ((NULL == u1) && (NULL == u2)) {
        return true;
    }

    if ((NULL == u1) || (NULL == u2)) {
        return false;
    }

    if (u1->vr_id != u2->vr_id) {
        return false;
    }
    if (u1->destination.addr_family != u2->destination.addr_family) {
        return false;
    }

    if (SAI_IP_ADDR_FAMILY_IPV4 == u1->destination.addr_family) {
        if (u1->destination.addr.ip4 != u2->destination.addr.ip4) {
            return false;
        }
        if (u1->destination.mask.ip4 != u2->destination.mask.ip4) {
            return false;
        }
    } else {
        if (memcmp(u1->destination.addr.ip6, u2->destination.addr.ip6, sizeof(u1->destination.addr.ip6))) {
            return false;
        }
        if (memcmp(u1->destination.addr.ip6, u2->destination.addr.ip6, sizeof(u1->destination.addr.ip6))) {
            return false;
        }
    }

    return true;
}
