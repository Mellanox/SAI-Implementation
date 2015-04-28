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

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

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
        return SAI_STATUS_FAILURE;

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
                                    _In_ sai_operation_t                     oper)
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

    if (SAI_OPERATION_MAX <= oper) {
        SX_LOG_ERR("Invalid operation %d\n", oper);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_OPERATION_REMOVE == oper) {
        /* No attributes expected for remove at this point */
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (SAI_OPERATION_SET == oper) {
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

        if ((SAI_OPERATION_CREATE == oper) &&
            (!(functionality_attr[index].valid_for_create))) {
            SX_LOG_ERR("Invalid attribute %s for create\n", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if ((SAI_OPERATION_SET == oper) &&
            (!(functionality_attr[index].valid_for_set))) {
            SX_LOG_ERR("Invalid attribute %s for set\n", functionality_attr[index].attrib_name);
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

        attr_present[index] = true;
    }

    if (SAI_OPERATION_CREATE == oper) {
        for (ii = 0; ii < functionality_attr_count; ii++) {
            if ((functionality_attr[ii].mandatory_on_create) &&
                (!attr_present[ii])) {
                SX_LOG_ERR("Missing mandatory attribute %s on create\n", functionality_attr[ii].attrib_name);
                free(attr_present);
                return SAI_MANDATORY_ATTRIBUTE_MISSING;
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

    sai_value_to_str(attr->value, functionality_attr[index].type, MAX_VALUE_STR_LEN, value_str);
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
        sai_value_to_str(attr_list[ii].value, functionality_attr[index].type, MAX_VALUE_STR_LEN, value_str);
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
            *index = ii;
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
        (status = check_attribs_metadata(1, attr, functionality_attr, functionality_vendor_attr, SAI_OPERATION_SET))) {
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
                                    SAI_OPERATION_GET))) {
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
    inet_ntop(AF_INET6, &value, value_str, max_length);

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

sai_status_t sai_nexthops_to_str(_In_ uint32_t                 next_hop_count,
                                 _In_ const sai_next_hop_id_t* nexthops,
                                 _In_ uint32_t                 max_length,
                                 _Out_ char                   *str)
{
    uint32_t ii;
    uint32_t pos = 0;

    pos += snprintf(str, max_length, "%u hops : [", next_hop_count);
    if (pos > max_length) {
        return SAI_STATUS_SUCCESS;
    }
    for (ii = 0; ii < next_hop_count; ii++) {
        pos += snprintf(str + pos, max_length - pos, " %u", nexthops[ii]);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
    }
    snprintf(str + pos, max_length - pos, "]");

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_value_to_str(_In_ sai_attribute_value_t      value,
                              _In_ sai_attribute_value_type_t type,
                              _In_ uint32_t                   max_length,
                              _Out_ char                     *value_str)
{
    uint32_t ii;
    uint32_t pos = 0;

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

    case SAI_ATTR_VAL_TYPE_NHLIST:
        pos += snprintf(value_str, max_length, "%u hops : [", value.nhlist.next_hop_count);
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        for (ii = 0; ii < value.nhlist.next_hop_count; ii++) {
            pos += snprintf(value_str + pos, max_length - pos, " %u", value.nhlist.next_hop_list[ii]);
            if (pos > max_length) {
                return SAI_STATUS_SUCCESS;
            }
        }
        snprintf(value_str + pos, max_length - pos, "]");
        break;

    case SAI_ATTR_VAL_TYPE_PORTLIST:
    case SAI_ATTR_VAL_TYPE_ACLFIELD:
    case SAI_ATTR_VAL_TYPE_ACLDATA:
        /* TODO : implement if in case it is used */
        snprintf(value_str, max_length, "Not implemented value type %d", type);
        return SAI_STATUS_NOT_IMPLEMENTED;

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
                        "#%u %s val:%s ",
                        ii,
                        functionality_attr[index].attrib_name,
                        value_str);
        if (pos > max_length) {
            break;
        }
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
