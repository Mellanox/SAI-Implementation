/**
 * Copyright (c) 2014 Microsoft Open Technologies, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 *    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 *    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 *    See the Apache Version 2.0 License for specific language governing
 *    permissions and limitations under the License.
 *
 *    Microsoft would like to thank the following companies for their review and
 *    assistance with these files: Intel Corporation, Mellanox Technologies Ltd,
 *    Dell Products, L.P., Facebook, Inc., Marvell International Ltd.
 *
 * @file    saiobject.h
 *
 * @brief   This module defines SAI APIs for bulk retrieval for each object-type
 */

#if !defined (__SAIOBJECT_H_)
#define __SAIOBJECT_H_

#include <saitypes.h>
#include <saifdb.h>
#include <saimcastfdb.h>
#include <sail2mc.h>
#include <saiipmc.h>
#include <saineighbor.h>
#include <sairoute.h>
#include <saimpls.h>
#include <sainat.h>

/**
 * @defgroup SAIOBJECT SAI - Object API definitions.
 *
 * @{
 */

/**
 * @extraparam sai_object_type_t object_type
 */
typedef union _sai_object_key_entry_t
{
    /**
     * @brief Key is object ID.
     *
     * @validonly sai_metadata_is_object_type_oid(object_type) == true
     */
    sai_object_id_t           object_id;

    /** @validonly object_type == SAI_OBJECT_TYPE_FDB_ENTRY */
    sai_fdb_entry_t           fdb_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_NEIGHBOR_ENTRY */
    sai_neighbor_entry_t      neighbor_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_ROUTE_ENTRY */
    sai_route_entry_t         route_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_MCAST_FDB_ENTRY */
    sai_mcast_fdb_entry_t     mcast_fdb_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_L2MC_ENTRY */
    sai_l2mc_entry_t          l2mc_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_IPMC_ENTRY */
    sai_ipmc_entry_t          ipmc_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_INSEG_ENTRY */
    sai_inseg_entry_t         inseg_entry;

    /** @validonly object_type == SAI_OBJECT_TYPE_NAT_ENTRY */
    sai_nat_entry_t           nat_entry;

} sai_object_key_entry_t;

/**
 * @brief Structure for bulk retrieval of object ids, attribute and values for
 * each object-type. Key will be used in case of object-types not having
 * object-ids.
 *
 * @extraparam sai_object_type_t object_type
 */
typedef struct _sai_object_key_t
{
    /** @passparam object_type */
    sai_object_key_entry_t key;

} sai_object_key_t;

/**
 * @brief Structure for attribute capabilities per operation
 */
typedef struct _sai_attr_capability_t
{
    /**
     * @brief Create is implemented
     */
    bool create_implemented;

    /**
     * @brief Set is implemented
     */
    bool set_implemented;

    /**
     * @brief Get is implemented
     */
    bool get_implemented;
} sai_attr_capability_t;

/**
 * @brief Get maximum number of attributes for an object type
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[out] count Maximum number of attribute for an object type
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_get_maximum_attribute_count(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _Out_ uint32_t *count);

/**
 * @brief Get the number of objects present in SAI. Deprecated for backward compatibility.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[out] count Number of objects in SAI
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_get_object_count(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _Out_ uint32_t *count);

/**
 * @brief Get the number of and list of object keys present in SAI if enough large
 * list provided, otherwise get the number of object keys only.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[inout] object_count Number of objects in SAI
 * @param[inout] object_list List of SAI objects or keys
 *
 * @return #SAI_STATUS_SUCCESS on success, #SAI_STATUS_BUFFER_OVERFLOW if list size insufficient, failure status code on error
 */
sai_status_t sai_get_object_key(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _Inout_ uint32_t *object_count,
        _Inout_ sai_object_key_t *object_list);

/**
 * @brief Get the bulk list of valid attributes for a given list of
 * object keys.
 *
 * Only valid attributes for an object are returned.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] object_count Number of objects
 * @param[in] object_key List of object keys
 * @param[inout] attr_count List of attr_count. Caller passes the number
 *    of attribute allocated in. Callee returns with the actual
 *    number of attributes filled in. If the count is less than
 *    needed, callee fills with the needed count and do not fill
 *    the attributes. Callee also set the corresponding status to
 *    #SAI_STATUS_BUFFER_OVERFLOW.
 *
 * @param[inout] attr_list List of attributes for every object. Caller is
 *    responsible for allocating and freeing buffer for the attributes.
 *    For list based attribute, e.g., s32list, objlist, callee should
 *    assume the caller has not allocated the memory for the list and
 *    should only to fill the count but not list. Then, caller
 *    can use corresponding get_attribute to get the list.
 *
 * @param[inout] object_statuses Status for each object. If the object does
 *    not exist, callee sets the corresponding status to #SAI_STATUS_INVALID_OBJECT_ID.
 *    If the allocated attribute count is not large enough,
 *    set the status to #SAI_STATUS_BUFFER_OVERFLOW.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_bulk_get_attribute(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _In_ uint32_t object_count,
        _In_ const sai_object_key_t *object_key,
        _Inout_ uint32_t *attr_count,
        _Inout_ sai_attribute_t **attr_list,
        _Inout_ sai_status_t *object_statuses);

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
sai_status_t sai_query_attribute_capability(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _In_ sai_attr_id_t attr_id,
        _Out_ sai_attr_capability_t *attr_capability);

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
sai_status_t sai_query_attribute_enum_values_capability(
        _In_ sai_object_id_t switch_id,
        _In_ sai_object_type_t object_type,
        _In_ sai_attr_id_t attr_id,
        _Inout_ sai_s32_list_t *enum_values_capability);

/**
 * @}
 */
#endif /** __SAIOBJECT_H_ */
