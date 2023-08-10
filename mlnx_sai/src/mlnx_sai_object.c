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
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 */

#include "sai_windows.h"

#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"
#include <errno.h>
#include <saimetadata.h>

#undef  __MODULE__
#define __MODULE__ SAI_OBJECT

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_utils_attrs_is_resource_check(_In_ sai_object_type_t      object_type,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list);
extern const mlnx_availability_get_fn        mlnx_availability_get_fns[SAI_OBJECT_TYPE_MAX];
extern const mlnx_bulk_object_get_stats_fn   mlnx_bulk_object_get_stats_fns[SAI_OBJECT_TYPE_MAX];
extern const mlnx_bulk_object_clear_stats_fn mlnx_bulk_object_clear_stats_fns[SAI_OBJECT_TYPE_MAX];

/**
 * @brief Get maximum number of attributes for an object type
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[inout] count Maximum number of attribute for an object type
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t sai_get_maximum_attribute_count(_In_ sai_object_id_t   switch_id,
                                             _In_ sai_object_type_t object_type,
                                             _Inout_ uint32_t      *count)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get the number of objects present in SAI
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[inout] count Number of objects in SAI
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t sai_get_object_count(_In_ sai_object_id_t   switch_id,
                                  _In_ sai_object_type_t object_type,
                                  _Inout_ uint32_t      *count)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get the list of object keys present in SAI
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[inout] object_count Number of objects in SAI
 * @param[inout] object_list List of SAI objects or keys
 *
 * @return #SAI_STATUS_SUCCESS on success, #SAI_STATUS_BUFFER_OVERFLOW if list size insufficient, failure status code on error
 */
sai_status_t sai_get_object_key(_In_ sai_object_id_t      switch_id,
                                _In_ sai_object_type_t    object_type,
                                _Inout_ uint32_t         *object_count,
                                _Inout_ sai_object_key_t *object_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get the bulk list of valid attributes for a given list of
 * object keys.Only valid attributes for an objects are returned.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] object_count Number of objects
 * @param[in] object_key List of object keys
 * @param[inout] attr_count List of attr_count. Caller passes the number
 *         of attribute allocated in. Callee returns with the actual
 *         number of attributes filled in. If the count is less than
 *         needed, callee fills with the needed count and do not fill
 *         the attributes. Callee also set the corresponding status to
 *         #SAI_STATUS_BUFFER_OVERFLOW.
 *
 * @param[inout] attrs Nist of attributes for every object. Caller is
 *         responsible for allocating and freeing buffer for the attributes.
 *         For list based attribute, e.g., s32list, oidlist, callee should
 *         assume the caller has not allocate the memory for the list and
 *         should only to fill the count but not list. Then, caller
 *         can use corresponding get_attribute to get the list.
 *
 * @param[inout] object_statuses Status for each object. If the object does
 *         not exist, callee sets the corresponding status to #SAI_STATUS_INVALID_OBJECT_ID.
 *         If the allocated attribute count is not large enough,
 *         set the status to #SAI_STATUS_BUFFER_OVERFLOW.
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t sai_bulk_get_attribute(_In_ sai_object_id_t         switch_id,
                                    _In_ sai_object_type_t       object_type,
                                    _In_ uint32_t                object_count,
                                    _In_ const sai_object_key_t *object_key,
                                    _Inout_ uint32_t            *attr_count,
                                    _Inout_ sai_attribute_t    **attrs,
                                    _Inout_ sai_status_t        *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Query attribute capability
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] attr_id SAI attribute ID
 * @param[out] attr_capability Capability per operation
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_query_attribute_capability(_In_ sai_object_id_t         switch_id,
                                            _In_ sai_object_type_t       object_type,
                                            _In_ sai_attr_id_t           attr_id,
                                            _Out_ sai_attr_capability_t *attr_capability)
{
    return mlnx_sai_query_attribute_capability_impl(switch_id, object_type, attr_id, attr_capability);
}

/**
 * @brief Query an enum attribute (enum or enum list) list of implemented enum values
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] attr_id SAI attribute ID
 * @param[inout] enum_values_capability List of implemented enum values
 *
 * @return #SAI_STATUS_SUCCESS on success, #SAI_STATUS_BUFFER_OVERFLOW if list size insufficient, failure status code on error
 */
sai_status_t sai_query_attribute_enum_values_capability(_In_ sai_object_id_t    switch_id,
                                                        _In_ sai_object_type_t  object_type,
                                                        _In_ sai_attr_id_t      attr_id,
                                                        _Inout_ sai_s32_list_t *enum_values_capability)
{
    return mlnx_sai_query_attribute_enum_values_capability_impl(switch_id, object_type, attr_id,
                                                                enum_values_capability);
}

/**
 * @brief Query statistics capability for statistics bound at object level
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[inout] stats_capability List of implemented enum values, and the statistics modes (bit mask) supported per value
 *
 * @return #SAI_STATUS_SUCCESS on success, #SAI_STATUS_BUFFER_OVERFLOW if lists size insufficient, failure status code on error
 */
sai_status_t sai_query_stats_capability(_In_ sai_object_id_t                switch_id,
                                        _In_ sai_object_type_t              object_type,
                                        _Inout_ sai_stat_capability_list_t *stats_capability)
{
    return mlnx_sai_query_stats_capability_impl(switch_id, object_type, stats_capability);
}


/**
 * @brief Get SAI object type resource availability.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list List of attributes that to distinguish resource
 * @param[out] count Available objects left
 *
 * @return #SAI_STATUS_NOT_SUPPORTED if the given object type does not support resource accounting.
 * Otherwise, return #SAI_STATUS_SUCCESS.
 */
sai_status_t sai_object_type_get_availability(_In_ sai_object_id_t        switch_id,
                                              _In_ sai_object_type_t      object_type,
                                              _In_ uint32_t               attr_count,
                                              _In_ const sai_attribute_t *attr_list,
                                              _Out_ uint64_t             *count)
{
    sai_status_t                  status;
    const sai_object_type_info_t *obj_type_info;
    char                          list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    if (!gh_sdk) {
        MLNX_SAI_LOG_ERR("Can't get object type availability before creating a switch\n");
        return SAI_STATUS_FAILURE;
    }

    if (NULL == count) {
        SX_LOG_ERR("NULL count param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (attr_count && !attr_list) {
        SX_LOG_ERR("attr_count > 0 but attr_list is NULL\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    obj_type_info = sai_metadata_get_object_type_info(object_type);
    if (!obj_type_info) {
        SX_LOG_ERR("Invalid object type - %d\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_attr_list_to_str(attr_count, attr_list, object_type, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Querying %s availability, %s\n", obj_type_info->objecttypename, list_str);

    status = mlnx_utils_attrs_is_resource_check(object_type, attr_count, attr_list);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    if (!mlnx_availability_get_fns[object_type]) {
        SX_LOG_ERR("Resource availability for object type %d is not implemented\n", object_type);
        SX_LOG_EXIT();
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    sai_db_read_lock();

    status = mlnx_availability_get_fns[object_type](switch_id, attr_count, attr_list, count);
    if (SAI_ERR(status)) {
        goto out;
    }

    SX_LOG_NTC("Got %s availability, %s: %lu\n", obj_type_info->objecttypename, list_str, *count);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_object_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}
