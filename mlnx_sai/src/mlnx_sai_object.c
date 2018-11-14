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
 * @param[in] object_count Number of objects in SAI
 * @param[in] object_list List of SAI objects or keys
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t sai_get_object_key(_In_ sai_object_id_t      switch_id,
                                _In_ sai_object_type_t    object_type,
                                _In_ uint32_t             object_count,
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
 *         not exist, callee sets the correpsonding status to #SAI_STATUS_INVALID_OBJECT_ID.
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
    return mlnx_sai_query_attribute_enum_values_capability_impl(switch_id, object_type, attr_id, enum_values_capability);
}
