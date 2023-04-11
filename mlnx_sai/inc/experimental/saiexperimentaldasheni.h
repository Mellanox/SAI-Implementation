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
 * @file    saiexperimentaldasheni.h
 *
 * @brief   This module defines SAI P4 extension  interface
 */

#if !defined (__SAIEXPERIMENTALDASHENI_H_)
#define __SAIEXPERIMENTALDASHENI_H_

#include <saitypes.h>

/**
 * @defgroup SAIEXPERIMENTALDASH_ENI SAI - Extension specific API definitions
 *
 * @{
 */

/**
 * @brief Entry for eni_ether_address_map_entry
 */
typedef struct _sai_eni_ether_address_map_entry_t
{
    /**
     * @brief Switch ID
     *
     * @objects SAI_OBJECT_TYPE_SWITCH
     */
    sai_object_id_t switch_id;

    /**
     * @brief Exact matched key address
     */
    sai_mac_t address;

} sai_eni_ether_address_map_entry_t;

/**
 * @brief Attribute ID for dash_eni_eni_ether_address_map_entry
 */
typedef enum _sai_eni_ether_address_map_entry_attr_t
{
    /**
     * @brief Start of attributes
     */
    SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_START,

    /**
     * @brief Action set_eni parameter ENI_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_ENI
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_ENI_ID = SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_START,

    /**
     * @brief End of attributes
     */
    SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_END,

    /** Custom range base value */
    SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_CUSTOM_RANGE_START = 0x10000000,

    /** End of custom range base */
    SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_CUSTOM_RANGE_END,

} sai_eni_ether_address_map_entry_attr_t;

/**
 * @brief Attribute ID for dash_eni_eni
 */
typedef enum _sai_eni_attr_t
{
    /**
     * @brief Start of attributes
     */
    SAI_ENI_ATTR_START,

    /**
     * @brief Action set_eni_attrs parameter CPS
     *
     * @type sai_uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_ENI_ATTR_CPS = SAI_ENI_ATTR_START,

    /**
     * @brief Action set_eni_attrs parameter PPS
     *
     * @type sai_uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_ENI_ATTR_PPS,

    /**
     * @brief Action set_eni_attrs parameter FLOWS
     *
     * @type sai_uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_ENI_ATTR_FLOWS,

    /**
     * @brief Action set_eni_attrs parameter ADMIN_STATE
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_ENI_ATTR_ADMIN_STATE,

    /**
     * @brief Action set_eni_attrs parameter VM_UNDERLAY_DIP
     *
     * @type sai_ip_address_t
     * @flags CREATE_AND_SET
     * @default 0.0.0.0
     */
    SAI_ENI_ATTR_VM_UNDERLAY_DIP,

    /**
     * @brief Action set_eni_attrs parameter VM_VNI
     *
     * @type sai_uint32_t
     * @flags CREATE_AND_SET
     * @default 0
     */
    SAI_ENI_ATTR_VM_VNI,

    /**
     * @brief Action set_eni_attrs parameter VNET_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_VNET
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_VNET_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V4_STAGE1_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V4_STAGE1_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V4_STAGE2_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V4_STAGE2_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V4_STAGE3_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V4_STAGE3_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V4_STAGE4_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V4_STAGE4_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V4_STAGE5_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V4_STAGE5_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V6_STAGE1_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V6_STAGE1_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V6_STAGE2_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V6_STAGE2_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V6_STAGE3_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V6_STAGE3_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V6_STAGE4_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V6_STAGE4_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter INBOUND_V6_STAGE5_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_INBOUND_V6_STAGE5_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V4_STAGE1_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V4_STAGE1_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V4_STAGE2_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V4_STAGE2_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V4_STAGE3_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V4_STAGE3_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V4_STAGE4_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V4_STAGE4_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V4_STAGE5_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V4_STAGE5_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V6_STAGE1_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V6_STAGE1_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V6_STAGE2_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V6_STAGE2_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V6_STAGE3_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V6_STAGE3_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V6_STAGE4_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V6_STAGE4_DASH_ACL_GROUP_ID,

    /**
     * @brief Action set_eni_attrs parameter OUTBOUND_V6_STAGE5_DASH_ACL_GROUP_ID
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_DASH_ACL_GROUP
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_ENI_ATTR_OUTBOUND_V6_STAGE5_DASH_ACL_GROUP_ID,

    /**
     * @brief End of attributes
     */
    SAI_ENI_ATTR_END,

    /** Custom range base value */
    SAI_ENI_ATTR_CUSTOM_RANGE_START = 0x10000000,

    /** End of custom range base */
    SAI_ENI_ATTR_CUSTOM_RANGE_END,

} sai_eni_attr_t;

/**
 * @brief Create dash_eni_eni_ether_address_map_entry
 *
 * @param[in] eni_ether_address_map_entry Entry
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_create_eni_ether_address_map_entry_fn)(
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

/**
 * @brief Remove dash_eni_eni_ether_address_map_entry
 *
 * @param[in] eni_ether_address_map_entry Entry
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_remove_eni_ether_address_map_entry_fn)(
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry);

/**
 * @brief Set attribute for dash_eni_eni_ether_address_map_entry
 *
 * @param[in] eni_ether_address_map_entry Entry
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_set_eni_ether_address_map_entry_attribute_fn)(
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry,
        _In_ const sai_attribute_t *attr);

/**
 * @brief Get attribute for dash_eni_eni_ether_address_map_entry
 *
 * @param[in] eni_ether_address_map_entry Entry
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_get_eni_ether_address_map_entry_attribute_fn)(
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

/**
 * @brief Bulk create dash_eni_eni_ether_address_map_entry
 *
 * @param[in] object_count Number of objects to create
 * @param[in] eni_ether_address_map_entry List of object to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *    of attribute for each object to create.
 * @param[in] attr_list List of attributes for every object.
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or
 * #SAI_STATUS_FAILURE when any of the objects fails to create. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
typedef sai_status_t (*sai_bulk_create_eni_ether_address_map_entry_fn)(
        _In_ uint32_t object_count,
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry,
        _In_ const uint32_t *attr_count,
        _In_ const sai_attribute_t **attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

/**
 * @brief Bulk remove dash_eni_eni_ether_address_map_entry
 *
 * @param[in] object_count Number of objects to remove
 * @param[in] eni_ether_address_map_entry List of objects to remove
 * @param[in] mode Bulk operation error handling mode.
 * @param[out] object_statuses List of status for every object. Caller needs to
 * allocate the buffer
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or
 * #SAI_STATUS_FAILURE when any of the objects fails to remove. When there is
 * failure, Caller is expected to go through the list of returned statuses to
 * find out which fails and which succeeds.
 */
typedef sai_status_t (*sai_bulk_remove_eni_ether_address_map_entry_fn)(
        _In_ uint32_t object_count,
        _In_ const sai_eni_ether_address_map_entry_t *eni_ether_address_map_entry,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

/**
 * @brief Create dash_eni_eni
 *
 * @param[out] eni_id Entry id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_create_eni_fn)(
        _Out_ sai_object_id_t *eni_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

/**
 * @brief Remove dash_eni_eni
 *
 * @param[in] eni_id Entry id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_remove_eni_fn)(
        _In_ sai_object_id_t eni_id);

/**
 * @brief Set attribute for dash_eni_eni
 *
 * @param[in] eni_id Entry id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_set_eni_attribute_fn)(
        _In_ sai_object_id_t eni_id,
        _In_ const sai_attribute_t *attr);

/**
 * @brief Get attribute for dash_eni_eni
 *
 * @param[in] eni_id Entry id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_get_eni_attribute_fn)(
        _In_ sai_object_id_t eni_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

typedef struct _sai_dash_eni_api_t
{
    sai_create_eni_ether_address_map_entry_fn           create_eni_ether_address_map_entry;
    sai_remove_eni_ether_address_map_entry_fn           remove_eni_ether_address_map_entry;
    sai_set_eni_ether_address_map_entry_attribute_fn    set_eni_ether_address_map_entry_attribute;
    sai_get_eni_ether_address_map_entry_attribute_fn    get_eni_ether_address_map_entry_attribute;
    sai_bulk_create_eni_ether_address_map_entry_fn      create_eni_ether_address_map_entries;
    sai_bulk_remove_eni_ether_address_map_entry_fn      remove_eni_ether_address_map_entries;

    sai_create_eni_fn                                   create_eni;
    sai_remove_eni_fn                                   remove_eni;
    sai_set_eni_attribute_fn                            set_eni_attribute;
    sai_get_eni_attribute_fn                            get_eni_attribute;
    sai_bulk_object_create_fn                           create_enis;
    sai_bulk_object_remove_fn                           remove_enis;

} sai_dash_eni_api_t;

/**
 * @}
 */
#endif /** __SAIEXPERIMENTALDASHENI_H_ */
