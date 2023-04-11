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

    if (!get_sdk_handle()) {
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

/**
 * @brief Bulk objects get statistics.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type Object type
 * @param[in] object_count Number of objects to get the stats
 * @param[in] object_key List of object keys
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[inout] object_statuses Array of status for each object. Length of the array should be object_count. Should be looked only if API return is not SAI_STATUS_SUCCESS.
 * @param[out] counters Array of resulting counter values.
 *    Length of counters array should be object_count*number_of_counters.
 *    Counter value of I object and J counter_id = counter[I*number_of_counters + J]
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_bulk_object_get_stats(_In_ sai_object_id_t         switch_id,
                                       _In_ sai_object_type_t       object_type,
                                       _In_ uint32_t                object_count,
                                       _In_ const sai_object_key_t *object_key,
                                       _In_ uint32_t                number_of_counters,
                                       _In_ const sai_stat_id_t    *counter_ids,
                                       _In_ sai_stats_mode_t        mode,
                                       _Inout_ sai_status_t        *object_statuses,
                                       _Out_ uint64_t              *counters)
{
    sai_status_t    status;
    sx_access_cmd_t cmd;

    SX_LOG_ENTER();

    if (!get_sdk_handle()) {
        MLNX_SAI_LOG_ERR("Can't get object stats before creating a switch\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (NULL == object_key) {
        SX_LOG_ERR("NULL object_key param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (0 == object_count) {
        SX_LOG_ERR("object_count is 0\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter_ids param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (0 == number_of_counters) {
        SX_LOG_ERR("number_of_counters is 0\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == object_statuses) {
        SX_LOG_ERR("NULL object_statuses param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    switch (mode) {
    case SAI_STATS_MODE_BULK_READ_AND_CLEAR:
    case SAI_STATS_MODE_BULK_READ:
        break;

    default:
        SX_LOG_ERR("Invalid stats mode %d for bulk get", mode);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if ((uint32_t)object_type >= SAI_OBJECT_TYPE_MAX) {
        SX_LOG_ERR("Unsupported object type: %d\n", object_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (!mlnx_bulk_object_get_stats_fns[object_type]) {
        SX_LOG_NTC("Bulk stats get for object type %d is not implemented\n", object_type);
        status = SAI_STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_stats_mode_to_sdk(mode, &cmd))) {
        goto out;
    }

    status = mlnx_bulk_object_get_stats_fns[object_type](switch_id,
                                                         object_count,
                                                         object_key,
                                                         number_of_counters,
                                                         counter_ids,
                                                         cmd,
                                                         object_statuses,
                                                         counters);

out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Bulk objects clear statistics.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type Object type
 * @param[in] object_count Number of objects to get the stats
 * @param[in] object_key List of object keys
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[inout] object_statuses Array of status for each object. Length of the array should be object_count. Should be looked only if API return is not SAI_STATUS_SUCCESS.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_bulk_object_clear_stats(_In_ sai_object_id_t         switch_id,
                                         _In_ sai_object_type_t       object_type,
                                         _In_ uint32_t                object_count,
                                         _In_ const sai_object_key_t *object_key,
                                         _In_ uint32_t                number_of_counters,
                                         _In_ const sai_stat_id_t    *counter_ids,
                                         _In_ sai_stats_mode_t        mode,
                                         _Inout_ sai_status_t        *object_statuses)
{
    sai_status_t    status;
    sx_access_cmd_t cmd;

    SX_LOG_ENTER();

    if (!get_sdk_handle()) {
        MLNX_SAI_LOG_ERR("Can't clear object stats before creating a switch\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    if (NULL == object_key) {
        SX_LOG_ERR("NULL object_key param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (0 == object_count) {
        SX_LOG_ERR("object_count is 0\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter_ids param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (0 == number_of_counters) {
        SX_LOG_ERR("number_of_counters is 0\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (NULL == object_statuses) {
        SX_LOG_ERR("NULL object_statuses param\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if ((uint32_t)object_type >= SAI_OBJECT_TYPE_MAX) {
        SX_LOG_ERR("Unsupported object type: %d\n", object_type);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (!mlnx_bulk_object_clear_stats_fns[object_type]) {
        SX_LOG_NTC("Bulk stats clear for object type %d is not implemented\n", object_type);
        status = SAI_STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    switch (mode) {
    case SAI_STATS_MODE_BULK_CLEAR:
        break;

    default:
        SX_LOG_ERR("Invalid stats mode %d for bulk clear", mode);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_translate_sai_stats_mode_to_sdk(mode, &cmd))) {
        goto out;
    }

    status = mlnx_bulk_object_clear_stats_fns[object_type](switch_id,
                                                           object_count,
                                                           object_key,
                                                           number_of_counters,
                                                           counter_ids,
                                                           cmd,
                                                           object_statuses);

out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_bulk_counter_event_init(_Out_ sai_bulk_counter_event_t *event)
{
    assert(event);

    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    pthread_condattr_t  cond_attr;
    pthread_mutexattr_t mutex_attr;

    if (0 != pthread_condattr_init(&cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable attribute for bulk counter event\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    if (0 != pthread_mutexattr_init(&mutex_attr)) {
        SX_LOG_ERR("Failed to init mutex attribute for bulk counter event\n");
        status = SAI_STATUS_NO_MEMORY;
        goto destroy_cond_attr;
    }

    if (0 != pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set condition variable attribute for bulk counter event - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto destroy_mutex_attr;
    }

    if (0 != pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)) {
        SX_LOG_ERR("Failed to set mutex attribute for bulk counter event - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto destroy_mutex_attr;
    }

    if (0 != pthread_cond_init(&event->cond, &cond_attr)) {
        SX_LOG_ERR("Failed to init condition variable for bulk counter event - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto destroy_mutex_attr;
    }

    if (0 != pthread_mutex_init(&event->mutex, &mutex_attr)) {
        SX_LOG_ERR("Failed to init mutex for bulk counter event - %s\n", strerror(errno));
        status = SAI_STATUS_FAILURE;
        goto destroy_mutex_attr;
    }

    event->read_done = -1;
    event->in_use = false;
    event->message_id = 0;
    status = SAI_STATUS_SUCCESS;

destroy_mutex_attr:
    if (0 != pthread_mutexattr_destroy(&mutex_attr)) {
        SX_LOG_ERR("Failed to destroy mutex attribute for bulk counter event\n");
        status = SAI_STATUS_FAILURE;
    }

destroy_cond_attr:
    if (0 != pthread_condattr_destroy(&cond_attr)) {
        SX_LOG_ERR("Failed to destroy condition variable attribute for bulk counter event\n");
        status = SAI_STATUS_FAILURE;
    }

out:
#endif /* ifndef _WIN32 */
    return status;
}

sai_status_t mlnx_bulk_counter_event_deinit(_In_ sai_bulk_counter_event_t *event)
{
    assert(event);

#ifndef _WIN32
    if (0 != pthread_mutex_destroy(&event->mutex)) {
        SX_LOG_ERR("Failed to destroy mutex for bulk counter event\n");
    }

    if (0 != pthread_cond_destroy(&event->cond)) {
        SX_LOG_ERR("Failed to destroy cond for bulk counter event\n");
    }
#endif

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_bulk_counter_init()
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    bool         sem_inited = false;
    bool         event_lock_inited = false;
    int          per_bulk_lock_init_count = 0;
    int          event_inited_count = 0;

#ifndef _WIN32
    if (0 != sem_init(&g_sai_db_ptr->bulk_counter_transaction_sem, 1, MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS)) {
        SX_LOG_ERR("Error creating bulk counter transaction semaphore\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    sem_inited = true;

    for (int i = 0; i < MLNX_BULK_TYPE_MAX_BULK_COUNTER_TYPE; i++) {
        if (0 != cl_plock_init_pshared(&g_sai_db_ptr->bulk_counter_info.per_type_locks[i])) {
            SX_LOG_ERR("Failed to init per bulk type lock for bulk counter\n");
            status = SAI_STATUS_NO_MEMORY;
            goto out;
        }
        ++per_bulk_lock_init_count;
    }

    if (0 != cl_plock_init_pshared(&g_sai_db_ptr->bulk_counter_info.event_lock)) {
        SX_LOG_ERR("Failed to init event lock for bulk counter\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    event_lock_inited = true;

    cl_plock_excl_acquire(&g_sai_db_ptr->bulk_counter_info.event_lock);
    g_sai_db_ptr->bulk_counter_info.last_message_id = 0;
    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        if (SAI_STATUS_SUCCESS != mlnx_bulk_counter_event_init(&g_sai_db_ptr->bulk_counter_info.events[i])) {
            cl_plock_release(&g_sai_db_ptr->bulk_counter_info.event_lock);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        ++event_inited_count;
    }
    cl_plock_release(&g_sai_db_ptr->bulk_counter_info.event_lock);

out:
    if (status != SAI_STATUS_SUCCESS) {
        /* do clean up */
        if (sem_inited) {
            if (0 != sem_destroy(&g_sai_db_ptr->bulk_counter_transaction_sem)) {
                SX_LOG_ERR("Error destroying bulk counter transaction semaphore\n");
            }
        }

        for (int i = 0; i < per_bulk_lock_init_count; i++) {
            cl_plock_destroy(&g_sai_db_ptr->bulk_counter_info.per_type_locks[i]);
        }

        if (event_lock_inited) {
            cl_plock_destroy(&g_sai_db_ptr->bulk_counter_info.event_lock);
        }

        for (int i = 0; i < event_inited_count; i++) {
            mlnx_bulk_counter_event_deinit(&g_sai_db_ptr->bulk_counter_info.events[i]);
        }
    }

#endif /* ifndef _WIN32 */
    return status;
}

sai_status_t mlnx_bulk_counter_deinit(void)
{
#ifndef _WIN32
    if (0 != sem_destroy(&g_sai_db_ptr->bulk_counter_transaction_sem)) {
        SX_LOG_ERR("Error destroying bulk counter transaction semaphore\n");
    }

    for (int i = 0; i < MLNX_BULK_TYPE_MAX_BULK_COUNTER_TYPE; i++) {
        cl_plock_destroy(&g_sai_db_ptr->bulk_counter_info.per_type_locks[i]);
    }

    cl_plock_destroy(&g_sai_db_ptr->bulk_counter_info.event_lock);
    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        mlnx_bulk_counter_event_deinit(&g_sai_db_ptr->bulk_counter_info.events[i]);
    }
#endif

    return SAI_STATUS_SUCCESS;
}

sai_bulk_counter_event_t* mlnx_get_bulk_counter_event()
{
    sai_bulk_counter_event_t *event = NULL;

    cl_plock_excl_acquire(&g_sai_db_ptr->bulk_counter_info.event_lock);
    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        if (!g_sai_db_ptr->bulk_counter_info.events[i].in_use) {
            event = &g_sai_db_ptr->bulk_counter_info.events[i];
            event->read_done = -1;
            event->message_id = g_sai_db_ptr->bulk_counter_info.last_message_id++;
            event->in_use = true;
            break;
        }
    }

    cl_plock_release(&g_sai_db_ptr->bulk_counter_info.event_lock);
    return event;
}

sai_status_t mlnx_notify_bulk_counter_readable(_In_ uint32_t cookie, _In_ int32_t read_status)
{
    sai_bulk_counter_event_t *event = NULL;
    sai_status_t              status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    cl_plock_excl_acquire(&g_sai_db_ptr->bulk_counter_info.event_lock);
    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        if (g_sai_db_ptr->bulk_counter_info.events[i].message_id == cookie) {
            event = &g_sai_db_ptr->bulk_counter_info.events[i];
            break;
        }
    }

    if (event) {
        mutex_lock(event->mutex);
        event->read_done = read_status;
        if (0 != pthread_cond_signal(&event->cond)) {
            SX_LOG_ERR("Failed to signal condition variable to wake up bulk counter thread\n");
            status = SAI_STATUS_FAILURE;
        } else {
            status = SAI_STATUS_SUCCESS;
        }

        mutex_unlock(event->mutex);
    } else {
        /* Timeout transaction, just ignore it. */
        status = SAI_STATUS_SUCCESS;
    }

    cl_plock_release(&g_sai_db_ptr->bulk_counter_info.event_lock);
#endif
    return status;
}

sai_status_t mlnx_allocate_sx_bulk_buffer(_In_ sx_bulk_cntr_buffer_key_t *bulk_read_key,
                                          _Out_ sx_bulk_cntr_buffer_t    *bulk_read_buff)
{
    assert(bulk_read_key);
    assert(bulk_read_buff);

    sx_status_t sx_status;

    sx_status = sx_api_bulk_counter_buffer_set(get_sdk_handle(),
                                               SX_ACCESS_CMD_CREATE,
                                               bulk_read_key,
                                               bulk_read_buff);

    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to create buffer: %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_deallocate_sx_bulk_buffer(_In_ sx_bulk_cntr_buffer_t *bulk_read_buff)
{
    assert(bulk_read_buff);

    sx_status_t sx_status;

    sx_status = sx_api_bulk_counter_buffer_set(get_sdk_handle(),
                                               SX_ACCESS_CMD_DESTROY,
                                               NULL,
                                               bulk_read_buff);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to destroy buffer: %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_set_async_bulk_read(_In_ sx_access_cmd_t cmd, _In_ sx_bulk_cntr_buffer_t *bulk_read_buff)
{
    assert(bulk_read_buff);

    sx_status_t sx_status;

    sx_status = sx_api_bulk_counter_transaction_set(get_sdk_handle(),
                                                    cmd,
                                                    bulk_read_buff);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to start bulk read operation: %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_wait_for_bulk_read_event(_In_ sai_bulk_counter_event_t *event)
{
    assert(event);

    sai_status_t    status = SAI_STATUS_SUCCESS;
    int             retval = 0;
    struct timespec time = {0};

#ifndef _WIN32
    mutex_lock(event->mutex);
    clock_gettime(CLOCK_REALTIME, &time);
#ifdef IS_PLD
    time.tv_sec += 2000;
#else
    time.tv_sec += 1;
#endif
    while (-1 == event->read_done) {
        retval = pthread_cond_timedwait(&event->cond, &event->mutex, &time);
        if (retval != 0) {
            SX_LOG_ERR("Failed to wait for an event: %s.\n", strerror(retval));
            status = SAI_STATUS_FAILURE;
            goto out;
        }
    }
    if (event->read_done != SX_BULK_CNTR_DONE_STATUS_OK) {
        SX_LOG_ERR("Bulk read event status is not OK [%d].\n", event->read_done);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    mutex_unlock(event->mutex);
#endif
    return status;
}

sai_status_t mlnx_prepare_bulk_counter_read(_In_ sai_bulk_counter_type      bulk_type,
                                            _In_ sx_access_cmd_t            cmd,
                                            _In_ sx_bulk_cntr_buffer_key_t *bulk_read_key,
                                            _Out_ sx_bulk_cntr_buffer_t    *bulk_read_buff)
{
    assert(bulk_read_key);
    assert(bulk_read_buff);

    sai_status_t status = SAI_STATUS_SUCCESS;

#ifndef _WIN32
    sai_bulk_counter_event_t *event;
    bool                      need_free_buffer = false;

    cl_plock_excl_acquire(&g_sai_db_ptr->bulk_counter_info.per_type_locks[bulk_type]);
    sai_db_read_lock();
    sem_wait(&g_sai_db_ptr->bulk_counter_transaction_sem);
    if (g_sai_db_ptr->issu_start_called) {
        sai_db_unlock();
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }
    sai_db_unlock();

    event = mlnx_get_bulk_counter_event();
    if (event == NULL) {
        SX_LOG_ERR("Failed to get bulk counter event.\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    bulk_read_buff->cookie = event->message_id;
    status = mlnx_allocate_sx_bulk_buffer(bulk_read_key, bulk_read_buff);
    if (SX_ERR(status)) {
        goto release_event;
    }

    status = mlnx_set_async_bulk_read(cmd, bulk_read_buff);
    if (SX_ERR(status)) {
        need_free_buffer = true;
        goto free_buffer;
    }

    status = mlnx_wait_for_bulk_read_event(event);
    if (SX_ERR(status)) {
        need_free_buffer = true;
        goto free_buffer;
    }

    status = SAI_STATUS_SUCCESS;

free_buffer:
    if (need_free_buffer) {
        mlnx_deallocate_sx_bulk_buffer(bulk_read_buff);
    }

release_event:
    cl_plock_excl_acquire(&g_sai_db_ptr->bulk_counter_info.event_lock);
    event->read_done = -1;
    event->in_use = false;
    cl_plock_release(&g_sai_db_ptr->bulk_counter_info.event_lock);
out:
    sem_post(&g_sai_db_ptr->bulk_counter_transaction_sem);
    cl_plock_release(&g_sai_db_ptr->bulk_counter_info.per_type_locks[bulk_type]);
#endif /* ifndef _WIN32 */
    return status;
}

sai_status_t mlnx_exhaust_bulk_counter_trasaction_sem()
{
#ifndef _WIN32
    struct timespec ts;
    int             status;

    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5; /* Max wait time 5 second for each transaction */
        while ((status = sem_timedwait(&g_sai_db_ptr->bulk_counter_transaction_sem, &ts)) == -1 && errno == EINTR) {
            continue;       /* Restart if interrupted by handler. */
        }
        if (status == -1) {
            if (errno == ETIMEDOUT) {
                SX_LOG_ERR("Wait bulk transaction semaphore timeout");
            } else {
                SX_LOG_ERR("Wait bulk transaction semaphore error - %s", strerror(errno));
            }
        }
    }
#endif

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_fillup_bulk_counter_trasaction_sem()
{
#ifndef _WIN32
    for (int i = 0; i < MLNX_SAI_MAX_BULK_COUNTER_TRANSACTIONS; i++) {
        sem_post(&g_sai_db_ptr->bulk_counter_transaction_sem);
    }
#endif

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Retrieve a SAI API version this implementation is aligned to
 *
 * @param[out] version Version number
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_query_api_version(_Out_ sai_api_version_t *version)
{
    SX_LOG_ENTER();

    if (NULL == version) {
        SX_LOG_ERR("NULL version param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    *version = SAI_API_VERSION;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Query the HW stage of an attribute for the specified object type
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_type SAI object type
 * @param[in] attr_count Count of attributes
 * @param[in] attr_list List of attributes
 * @param[out] stage HW stage of the attributes. Length of the array should be attr_count. Caller must allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t sai_query_object_stage(_In_ sai_object_id_t        switch_id,
                                    _In_ sai_object_type_t      object_type,
                                    _In_ uint32_t               attr_count,
                                    _In_ const sai_attribute_t *attr_list,
                                    _Out_ sai_object_stage_t   *stage)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t mlnx_object_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}
