/*
 *  Copyright (C) 2019. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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

#include "sai.h"
#include "sai_windows.h"
#include "mlnx_sai.h"
#include "assert.h"

#undef __MODULE__
#define __MODULE__ SAI_ISOLATION_GROUP

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

sai_status_t mlnx_isolation_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_isolation_group_db_alloc(_Out_ mlnx_isolation_group_t **isolation_group, uint32_t *db_idx)
{
    uint32_t                ii;
    mlnx_isolation_group_t *group_db = g_sai_db_ptr->isolation_groups;

    SX_LOG_ENTER();
    assert(isolation_group);
    assert(db_idx);

    for (ii = 0; ii < MAX_ISOLATION_GROUPS; ii++) {
        if (!group_db[ii].is_used) {
            memset(&group_db[ii], 0, sizeof(mlnx_isolation_group_t));
            group_db[ii].is_used = true;

            *isolation_group = &group_db[ii];
            *db_idx = ii;

            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Failed to allocate isolation group entry - DB is full\n");
    return SAI_STATUS_INSUFFICIENT_RESOURCES;
}

/* needs sai_db write lock */
static sai_status_t mlnx_isolation_group_db_nfree(_In_ mlnx_isolation_group_t **isolation_group)
{
    mlnx_isolation_group_t *group_db = g_sai_db_ptr->isolation_groups;
    sai_status_t            status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();
    assert(isolation_group);
    assert(*isolation_group);

    if (((*isolation_group) >= group_db) && (((*isolation_group) - group_db) < MAX_ISOLATION_GROUPS)) {
        if (!(*isolation_group)->is_used) {
            SX_LOG_ERR("Failed to free isolation group db: entry is not used\n");
            status = SAI_STATUS_INVALID_PARAMETER;
            goto out;
        }

        memset((*isolation_group), 0, sizeof(mlnx_isolation_group_t));
        *isolation_group = NULL;
    } else {
        SX_LOG_ERR("Invalid isolation group db entry pointer\n");
        status = SAI_STATUS_INVALID_PARAMETER;
    }

out:
    return status;
}

/* needs sai_db read lock */
static sai_status_t mlnx_isolation_group_db_get_by_idx(_In_ uint32_t                  isolation_group_idx,
                                                       _Out_ mlnx_isolation_group_t **isolation_group_db_entry)
{
    SX_LOG_ENTER();
    assert(isolation_group_db_entry);

    if (isolation_group_idx >= MAX_ISOLATION_GROUPS) {
        SX_LOG_ERR("Invalid isolation group db index\n");
        return SAI_STATUS_FAILURE;
    }

    *isolation_group_db_entry = &(g_sai_db_ptr->isolation_groups[isolation_group_idx]);
    if (!(*isolation_group_db_entry)->is_used) {
        SX_LOG_ERR("Isolation group db entry at idx - %u is not initialized\n", isolation_group_idx);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db read lock */
static sai_status_t mlnx_isolation_group_db_get_by_id(_In_ sai_object_id_t           isolation_group_id,
                                                      _Out_ mlnx_isolation_group_t **isolation_group_db_entry)
{
    mlnx_object_id_t mlnx_oid;
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai oid to mlnx oid\n");
        return status;
    }

    return mlnx_isolation_group_db_get_by_idx(mlnx_oid.id.isolation_group_db_idx, isolation_group_db_entry);
}

static void isolation_group_key_to_str(_In_ sai_object_id_t isolation_group_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_oid;
    sai_status_t     status;
    const char      *group_name = NULL;

    memset(&mlnx_oid, 0, sizeof(mlnx_oid));

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group_id, &mlnx_oid);
    if (!SAI_ERR(status)) {
        switch (mlnx_oid.field.sub_type) {
        case SAI_ISOLATION_GROUP_TYPE_PORT:
            group_name = "port";
            break;

        case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
            group_name = "bridge port";
            break;

        default:
            status = SAI_STATUS_FAILURE;
        }
    }

    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid isolation group");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Isolation group id %u, type ='%s'", mlnx_oid.id.isolation_group_db_idx,
                 group_name);
    }
}

/* needs sai_db read lock */
static int32_t mlnx_find_acl_entry_isolation_group_db(sai_object_id_t          acl_entry,
                                                      mlnx_isolation_group_t **isolation_group_entry)
{
    uint32_t                ii, jj;
    mlnx_isolation_group_t *isolation_group_db = g_sai_db_ptr->isolation_groups;

    SX_LOG_ENTER();

    assert(isolation_group_entry);

    for (ii = 0; ii < MAX_ISOLATION_GROUPS; ii++) {
        if (!isolation_group_db[ii].is_used) {
            continue;
        }

        for (jj = 0; jj < isolation_group_db[ii].subscribed_acl_count; jj++) {
            if (acl_entry == isolation_group_db[ii].subscribed_acl[jj]) {
                *isolation_group_entry = &isolation_group_db[ii];
                return (int32_t)ii;
            }
        }
    }

    *isolation_group_entry = NULL;

    return -1;
}

/* needs sai_db read lock */
static int32_t mlnx_isolation_group_find_member_port_pos(mlnx_isolation_group_t *isolation_group,
                                                         sx_port_log_id_t        log_port)
{
    uint32_t ii;

    SX_LOG_ENTER();

    assert(isolation_group);

    for (ii = 0; ii < isolation_group->members_count; ii++) {
        if (isolation_group->members[ii] == log_port) {
            return (int32_t)ii;
        }
    }

    return -1;
}

static sai_status_t mlnx_isolation_group_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg);
static sai_status_t mlnx_isolation_group_member_list_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static const sai_vendor_attribute_entry_t isolation_group_vendor_attribs[] = {
    { SAI_ISOLATION_GROUP_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_isolation_group_type_get, NULL,
      NULL, NULL },
    { SAI_ISOLATION_GROUP_ATTR_ISOLATION_MEMBER_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_isolation_group_member_list_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static mlnx_attr_enum_info_t              isolation_group_enum_info[] = {
    [SAI_ISOLATION_GROUP_ATTR_TYPE] = ATTR_ENUM_VALUES_ALL()
};
const mlnx_obj_type_attrs_info_t          mlnx_isolation_group_obj_type_info =
{ isolation_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(isolation_group_enum_info), OBJ_STAT_CAP_INFO_EMPTY()};

static sai_status_t mlnx_isolation_group_type_get(_In_ const sai_object_key_t   *key,
                                                  _Inout_ sai_attribute_value_t *value,
                                                  _In_ uint32_t                  attr_index,
                                                  _Inout_ vendor_cache_t        *cache,
                                                  void                          *arg)
{
    sai_status_t            status;
    mlnx_isolation_group_t *isolation_group_entry;

    SX_LOG_ENTER();

    sai_db_read_lock();
    status = mlnx_isolation_group_db_get_by_id(key->key.object_id, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        goto out;
    }

    value->s32 = isolation_group_entry->type;

out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_isolation_group_member_list_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    mlnx_isolation_group_t *isolation_group_entry;
    sai_status_t            status;
    sai_object_id_t         member_list[MAX_ISOLATION_GROUP_MEMBERS];
    uint32_t                ii;

    SX_LOG_ENTER();

    sai_db_read_lock();
    status = mlnx_isolation_group_db_get_by_id(key->key.object_id, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        goto out;
    }

    for (ii = 0; ii < isolation_group_entry->members_count; ii++) {
        status = mlnx_create_isolation_group_member_oid(&member_list[ii], key->key.object_id,
                                                        isolation_group_entry->members[ii]);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create isolation group member oid\n");
            goto out;
        }
    }

    status = mlnx_fill_objlist(member_list, isolation_group_entry->members_count, &value->objlist);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to fill object list\n");
        goto out;
    }

out:
    sai_db_unlock();

    return status;
}

sai_status_t mlnx_create_isolation_group_oid(uint32_t                   isolation_group_idx,
                                             sai_isolation_group_type_t type,
                                             sai_object_id_t           *object_id)
{
    mlnx_object_id_t mlnx_oid;

    SX_LOG_ENTER();

    assert(object_id);

    memset(&mlnx_oid, 0, sizeof(mlnx_oid));
    mlnx_oid.id.isolation_group_db_idx = isolation_group_idx;
    mlnx_oid.field.sub_type = type;

    return mlnx_object_id_to_sai(SAI_OBJECT_TYPE_ISOLATION_GROUP, &mlnx_oid, object_id);
}

static sai_status_t mlnx_create_isolation_group(_Out_ sai_object_id_t      *isolation_group_id,
                                                _In_ sai_object_id_t        switch_id,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    const sai_attribute_value_t *attr;
    uint32_t                     attr_idx;
    mlnx_isolation_group_t      *isolation_group_entry = NULL;
    uint32_t                     isolation_group_db_idx;

    SX_LOG_ENTER();

    if (NULL == isolation_group_id) {
        SX_LOG_ERR("NULL isolation group id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ISOLATION_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create isolation group, %s\n", list_str);

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ISOLATION_GROUP,
                                    isolation_group_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_db_write_lock();
    status = mlnx_validate_port_isolation_api(PORT_ISOLATION_API_ISOLATION_GROUP);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Egress block port in use\n");
        goto out;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_ISOLATION_GROUP_ATTR_TYPE, &attr, &attr_idx);
    assert(status == SAI_STATUS_SUCCESS);
    status = mlnx_isolation_group_db_alloc(&isolation_group_entry, &isolation_group_db_idx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to alloc isolation group db entry\n");
        goto out;
    }

    isolation_group_entry->type = attr->s32;

    status = mlnx_create_isolation_group_oid(isolation_group_db_idx, isolation_group_entry->type, isolation_group_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create isolation group oid\n");
        goto out;
    }

    isolation_group_key_to_str(*isolation_group_id, key_str);
    SX_LOG_NTC("Created isolation group: id - %s\n", key_str);
out:
    /*rollback*/
    if (SAI_ERR(status)) {
        if (isolation_group_entry != NULL) {
            mlnx_isolation_group_db_nfree(&isolation_group_entry);
        }
    }

    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_remove_isolation_group(_In_ sai_object_id_t isolation_group_id)
{
    mlnx_isolation_group_t *isolation_group_entry = NULL;
    char                    key_str[MAX_KEY_STR_LEN];
    sai_status_t            status;

    SX_LOG_ENTER();

    isolation_group_key_to_str(isolation_group_id, key_str);
    SX_LOG_NTC("Remove isolation group: id - %s\n", key_str);

    sai_db_write_lock();
    status = mlnx_isolation_group_db_get_by_id(isolation_group_id, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        goto out;
    }

    if ((isolation_group_entry->members_count != 0) || (isolation_group_entry->subscribed_acl_count != 0) ||
        (isolation_group_entry->subscribed_ports_count != 0)) {
        SX_LOG_ERR("Failed to remove isolation group: isolation group in use. Id - %s\n", key_str);
        SX_LOG_ERR("Isolation group: "
                   "members count - %u, subscribed acl entry count - %u, subscribed ports count - %u\n",
                   isolation_group_entry->members_count, isolation_group_entry->subscribed_acl_count,
                   isolation_group_entry->subscribed_ports_count);

        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    status = mlnx_isolation_group_db_nfree(&isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to remove isolation group db entry\n");
        goto out;
    }
out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_set_isolation_group_attribute(_In_ sai_object_id_t        isolation_group_id,
                                                       _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = isolation_group_id};
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    isolation_group_key_to_str(isolation_group_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group_vendor_attribs, attr);
}

static sai_status_t mlnx_get_isolation_group_attribute(_In_ sai_object_id_t     isolation_group_id,
                                                       _In_ uint32_t            attr_count,
                                                       _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = isolation_group_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    isolation_group_key_to_str(isolation_group_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group_vendor_attribs,
                              attr_count, attr_list);
}

static sai_status_t mlnx_isolation_group_member_isolation_object_get(_In_ const sai_object_key_t   *key,
                                                                     _Inout_ sai_attribute_value_t *value,
                                                                     _In_ uint32_t                  attr_index,
                                                                     _Inout_ vendor_cache_t        *cache,
                                                                     void                          *arg);
static sai_status_t mlnx_isolation_group_member_isolation_group_id_get(_In_ const sai_object_key_t   *key,
                                                                       _Inout_ sai_attribute_value_t *value,
                                                                       _In_ uint32_t                  attr_index,
                                                                       _Inout_ vendor_cache_t        *cache,
                                                                       void                          *arg);
static const sai_vendor_attribute_entry_t isolation_group_member_vendor_attribs[] = {
    { SAI_ISOLATION_GROUP_MEMBER_ATTR_ISOLATION_GROUP_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_isolation_group_member_isolation_group_id_get, NULL,
      NULL, NULL },
    { SAI_ISOLATION_GROUP_MEMBER_ATTR_ISOLATION_OBJECT,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_isolation_group_member_isolation_object_get, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};

static sai_status_t mlnx_isolation_group_update_subscribed_acl(mlnx_isolation_group_t *isolation_group);

static sai_status_t mlnx_isolation_group_member_isolation_object_get(_In_ const sai_object_key_t   *key,
                                                                     _Inout_ sai_attribute_value_t *value,
                                                                     _In_ uint32_t                  attr_index,
                                                                     _Inout_ vendor_cache_t        *cache,
                                                                     void                          *arg)
{
    sai_status_t            status;
    mlnx_object_id_t        mlnx_oid;
    mlnx_isolation_group_t *isolation_group;
    int32_t                 port_position;
    sx_port_log_id_t        log_port;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, key->key.object_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai object id to mlnx object id\n");
        return status;
    }
    log_port = mlnx_oid.id.log_port_id;

    sai_db_read_lock();
    status = mlnx_isolation_group_db_get_by_idx(mlnx_oid.ext.isolation_group_member.isolation_group_db_idx,
                                                &isolation_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db\n");
        goto out;
    }

    port_position = mlnx_isolation_group_find_member_port_pos(isolation_group, log_port);
    if (port_position < 0) {
        SX_LOG_ERR("Invalid isolation group member id - port is not a group member\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    switch (isolation_group->type) {
    case SAI_ISOLATION_GROUP_TYPE_PORT:
        status = mlnx_log_port_to_object(log_port, &value->oid);
        break;

    case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
        status = mlnx_log_port_to_sai_bridge_port(log_port, &value->oid);
        break;

    default:
        SX_LOG_ERR("Invalid isolation group type\n");
        status = SAI_STATUS_INVALID_PARAMETER;
    }
out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_isolation_group_member_isolation_group_id_get(_In_ const sai_object_key_t   *key,
                                                                       _Inout_ sai_attribute_value_t *value,
                                                                       _In_ uint32_t                  attr_index,
                                                                       _Inout_ vendor_cache_t        *cache,
                                                                       void                          *arg)
{
    sai_status_t            status;
    mlnx_object_id_t        mlnx_oid;
    mlnx_isolation_group_t *isolation_group;
    uint32_t                isolation_group_db_idx;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, key->key.object_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai object id to mlnx object id\n");
        return status;
    }
    isolation_group_db_idx = mlnx_oid.ext.isolation_group_member.isolation_group_db_idx;

    sai_db_read_lock();
    status = mlnx_isolation_group_db_get_by_idx(isolation_group_db_idx, &isolation_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db\n");
        goto out;
    }

    status = mlnx_create_isolation_group_oid(isolation_group_db_idx, isolation_group->type, &value->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create isolation group oid\n");
        goto out;
    }

out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_get_isolation_group_objtype(sai_object_id_t isolation_group, sai_object_type_t *objtype)
{
    mlnx_object_id_t mlnx_oid;
    sai_status_t     status;

    SX_LOG_ENTER();

    memset(&mlnx_oid, 0, sizeof(mlnx_oid));
    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai object id to mlnx object id\n");
        return status;
    }

    switch (mlnx_oid.field.sub_type) {
    case SAI_ISOLATION_GROUP_TYPE_PORT:
        *objtype = SAI_OBJECT_TYPE_PORT;
        break;

    case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
        *objtype = SAI_OBJECT_TYPE_BRIDGE_PORT;
        break;

    default:
        SX_LOG_ERR("Invalid isolation group type\n");
        status = SAI_STATUS_FAILURE;
        break;
    }

    return status;
}

/* needs sai_db read lock */
static sai_status_t mlnx_isolation_group_validate_port(sai_object_id_t isolation_group, sai_object_id_t port_oid)
{
    sai_status_t        status;
    sai_object_type_t   member_obj_type = sai_object_type_query(port_oid);
    sai_object_type_t   group_obj_type;
    sx_port_log_id_t    log_port;
    mlnx_bridge_port_t *bridge_port;

    SX_LOG_ENTER();

    status = mlnx_get_isolation_group_objtype(isolation_group, &group_obj_type);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group objects type\n");
        return status;
    }

    if (member_obj_type != group_obj_type) {
        SX_LOG_ERR("Failed to add %s to isolation group. Allowed obj type - %s\n", SAI_TYPE_STR(member_obj_type),
                   SAI_TYPE_STR(group_obj_type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (member_obj_type) {
    case SAI_OBJECT_TYPE_PORT:
        status = mlnx_object_to_log_port(port_oid, &log_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to convert object id to log port\n");
            return status;
        }
        break;

    case SAI_OBJECT_TYPE_BRIDGE_PORT:
        status = mlnx_bridge_port_by_oid(port_oid, &bridge_port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get bridge port db entry by isolation member oid\n");
            return status;
        }

        if (bridge_port->port_type != SAI_BRIDGE_PORT_TYPE_PORT) {
            SX_LOG_ERR("Only SAI_BRIDGE_PORT_TYPE_PORT is available for isolation group\n");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        break;

    default:
        SX_LOG_ERR("Invalid isolation group member object type - %s\n", SAI_TYPE_STR(member_obj_type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db read lock */
static sai_status_t mlnx_port_or_bridge_port_to_log_port(sai_object_id_t port_object_id, sx_port_log_id_t *log_port)
{
    sai_object_type_t port_type = sai_object_type_query(port_object_id);

    SX_LOG_ENTER();

    if (port_type == SAI_OBJECT_TYPE_PORT) {
        return mlnx_object_to_log_port(port_object_id, log_port);
    }

    if (port_type == SAI_OBJECT_TYPE_BRIDGE_PORT) {
        return mlnx_bridge_port_sai_to_log_port_not_locked(port_object_id, log_port);
    }

    SX_LOG_ERR("Invalid object type - %s\n", SAI_TYPE_STR(port_type));

    return SAI_STATUS_INVALID_PARAMETER;
}

/* needs sai_db read lock */
static sai_status_t mlnx_isolation_group_validate_add_member(sai_object_id_t         isolation_group_oid,
                                                             mlnx_isolation_group_t *isolation_group_db,
                                                             mlnx_port_config_t     *port)
{
    sx_port_log_id_t log_port = port->logical;
    int32_t          port_position;

    SX_LOG_ENTER();

    assert(port);
    assert(isolation_group_db);

    if (port->isolation_group == isolation_group_oid) {
        SX_LOG_ERR("Port is already bound to the group\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (isolation_group_db->members_count == MAX_ISOLATION_GROUP_MEMBERS) {
        SX_LOG_ERR("Isolation group members storage full\n");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    port_position = mlnx_isolation_group_find_member_port_pos(isolation_group_db, log_port);
    if (port_position >= 0) {
        SX_LOG_ERR("Port is already a member of the isolation group\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_isolation_group_add_member(sai_object_id_t isolation_group, sai_object_id_t member_object)
{
    mlnx_isolation_group_t *isolation_group_entry;
    sx_port_log_id_t        log_port;
    sai_status_t            status;
    sx_status_t             sx_status;
    mlnx_port_config_t     *port;

    SX_LOG_ENTER();

    status = mlnx_isolation_group_validate_port(isolation_group, member_object);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid isolation group member object\n");
        return status;
    }

    status = mlnx_port_or_bridge_port_to_log_port(member_object, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group member object log port\n");
        return status;
    }

    status = mlnx_port_by_log_id(log_port, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port db by log port id\n");
        return status;
    }

    status = mlnx_isolation_group_db_get_by_id(isolation_group, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        return status;
    }

    status = mlnx_isolation_group_validate_add_member(isolation_group, isolation_group_entry, port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to validate adding member to isolation group\n");
        return status;
    }

    if (isolation_group_entry->subscribed_ports_count > 0) {
        sx_status = sx_api_port_isolate_set(gh_sdk, SX_ACCESS_CMD_ADD, log_port,
                                            isolation_group_entry->subscribed_ports,
                                            isolation_group_entry->subscribed_ports_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to add port isolation ports to port %#0x - %s\n", log_port, SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    isolation_group_entry->members[isolation_group_entry->members_count++] = log_port;

    status = mlnx_isolation_group_update_subscribed_acl(isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update ACL entry\n");
        return status;
    }


    switch (isolation_group_entry->type) {
    case SAI_ISOLATION_GROUP_TYPE_PORT:
        port->isolation_group_port_refcount++;
        break;

    case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
        port->isolation_group_bridge_port_refcount++;
        break;

    default:
        SX_LOG_ERR("Invalid isolation group type\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return status;
}

sai_status_t mlnx_create_isolation_group_member_oid(sai_object_id_t *object_id,
                                                    sai_object_id_t  isolation_group,
                                                    sx_port_log_id_t log_port)
{
    mlnx_object_id_t member_mlnx_oid, group_mlnx_oid;
    sai_status_t     status;

    SX_LOG_ENTER();

    memset(&member_mlnx_oid, 0, sizeof(member_mlnx_oid));
    memset(&group_mlnx_oid, 0, sizeof(group_mlnx_oid));

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP, isolation_group, &group_mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai object id to mlnx object id\n");
        return status;
    }

    member_mlnx_oid.id.log_port_id = log_port;
    member_mlnx_oid.ext.isolation_group_member.isolation_group_db_idx =
        (uint16_t)group_mlnx_oid.id.isolation_group_db_idx;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, &member_mlnx_oid, object_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert mlnx object id to sai object id\n");
        return status;
    }

    return status;
}

static void isolation_group_member_key_to_str(_In_ sai_object_id_t isolation_group_member_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_oid;
    sai_status_t     status;

    memset(&mlnx_oid, 0, sizeof(mlnx_oid));

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, isolation_group_member_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid isolation group member");
    } else {
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "Isolation group member id: isolation group idx - %u, logical port id- %#0x",
                 mlnx_oid.ext.isolation_group_member.isolation_group_db_idx,
                 mlnx_oid.id.log_port_id);
    }
}

static sai_status_t mlnx_create_isolation_group_member(_Out_ sai_object_id_t      *isolation_group_member_id,
                                                       _In_ sai_object_id_t        switch_id,
                                                       _In_ uint32_t               attr_count,
                                                       _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    const sai_attribute_value_t *group_attr, *member_object_attr;
    uint32_t                     group_attr_idx, member_object_attr_idx;
    sx_port_log_id_t             log_port;

    SX_LOG_ENTER();

    if (NULL == isolation_group_member_id) {
        SX_LOG_ERR("NULL isolation group member id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, MAX_LIST_VALUE_STR_LEN,
                         list_str);
    SX_LOG_NTC("Create isolation group member, %s\n", list_str);
    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER,
                                    isolation_group_member_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_ISOLATION_GROUP_MEMBER_ATTR_ISOLATION_GROUP_ID,
                                 &group_attr,
                                 &group_attr_idx);
    assert(status == SAI_STATUS_SUCCESS);

    status = find_attrib_in_list(attr_count, attr_list, SAI_ISOLATION_GROUP_MEMBER_ATTR_ISOLATION_OBJECT,
                                 &member_object_attr, &member_object_attr_idx);
    assert(status == SAI_STATUS_SUCCESS);

    sai_db_write_lock();

    status = mlnx_isolation_group_add_member(group_attr->oid, member_object_attr->oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to add isolation group member\n");
        goto out;
    }

    status = mlnx_port_or_bridge_port_to_log_port(member_object_attr->oid, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port object log port\n");
        return status;
    }

    status = mlnx_create_isolation_group_member_oid(isolation_group_member_id, group_attr->oid, log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create isolation group member oid\n");
        goto out;
    }

    isolation_group_member_key_to_str(*isolation_group_member_id, key_str);
    SX_LOG_NTC("Created isolation group member: id - %s\n", key_str);

out:

    sai_db_unlock();

    return status;
}

/*needs sai_db read lock*/
static sai_status_t mlnx_isolation_group_member_get_lag_applied_count(const sx_port_log_id_t member_log_port,
                                                                      const sx_port_log_id_t lag_log_port,
                                                                      uint32_t              *count)
{
    mlnx_isolation_group_t *isolation_group_db = g_sai_db_ptr->isolation_groups;
    uint32_t                ii, jj;
    bool                    is_member_present, is_lag_present;
    uint32_t                applied_count = 0;

    SX_LOG_ENTER();

    assert(count);

    for (ii = 0; ii < MAX_ISOLATION_GROUPS; ii++) {
        if (!isolation_group_db[ii].is_used) {
            continue;
        }

        is_member_present = false;
        for (jj = 0; jj < isolation_group_db[ii].members_count; jj++) {
            if (isolation_group_db[ii].members[jj] == member_log_port) {
                is_member_present = true;
                break;
            }
        }
        if (!is_member_present) {
            continue;
        }

        is_lag_present = false;
        for (jj = 0; jj < isolation_group_db[ii].subscribed_ports_count; jj++) {
            if (isolation_group_db[ii].subscribed_ports[jj] == lag_log_port) {
                is_lag_present = true;
                break;
            }
        }

        if (is_member_present && is_lag_present) {
            applied_count++;
        }
    }

    *count = applied_count;

    return SAI_STATUS_SUCCESS;
}

/*needs sai_db write lock*/
static sai_status_t mlnx_update_subscribed_ports_remove_group_member(mlnx_isolation_group_t *isolation_group,
                                                                     sx_port_log_id_t        log_port)
{
    sx_port_log_id_t ports_to_update[MAX_SUBSCRIBED_PORTS_ISOLATION_GROUP];
    uint32_t         ports_to_update_count = 0;
    uint32_t         ii;
    uint32_t         lag_applied_count;
    sai_status_t     status;
    sx_status_t      sx_status;

    SX_LOG_ENTER();

    assert(isolation_group);

    for (ii = 0; ii < isolation_group->subscribed_ports_count; ii++) {
        if (SX_PORT_TYPE_LAG & SX_PORT_TYPE_ID_GET(isolation_group->subscribed_ports[ii])) {
            status = mlnx_isolation_group_member_get_lag_applied_count(log_port, isolation_group->subscribed_ports[ii],
                                                                       &lag_applied_count);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed to get isolation group lag refcount\n");
                return status;
            }

            if (lag_applied_count != 1) {
                continue;
            }
        }

        ports_to_update[ports_to_update_count++] = isolation_group->subscribed_ports[ii];
    }

    if (ports_to_update_count > 0) {
        sx_status = sx_api_port_isolate_set(gh_sdk,
                                            SX_ACCESS_CMD_DELETE,
                                            log_port,
                                            ports_to_update,
                                            ports_to_update_count);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to delete port isolation ports from port %#0x - %s\n", log_port,
                       SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_isolation_group_member(_In_ sai_object_id_t isolation_group_member_id)
{
    sai_status_t            status;
    mlnx_object_id_t        mlnx_oid;
    mlnx_isolation_group_t *isolation_group_entry;
    mlnx_port_config_t     *port;
    sx_port_log_id_t        log_port;
    char                    key_str[MAX_KEY_STR_LEN];
    int32_t                 port_position;

    SX_LOG_ENTER();

    isolation_group_member_key_to_str(isolation_group_member_id, key_str);
    SX_LOG_NTC("Remove isolation group member: id - %s\n", key_str);

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER, isolation_group_member_id, &mlnx_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert sai object id to mlnx object id\n");
        return status;
    }

    log_port = mlnx_oid.id.log_port_id;
    status = mlnx_port_by_log_id(log_port, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port by log id\n");
        goto out;
    }

    sai_db_write_lock();
    status = mlnx_isolation_group_db_get_by_idx(mlnx_oid.ext.isolation_group_member.isolation_group_db_idx,
                                                &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db\n");
        goto out;
    }

    port_position = mlnx_isolation_group_find_member_port_pos(isolation_group_entry, log_port);
    if (port_position < 0) {
        SX_LOG_ERR("Invalid isolation group member id - port is not a group member\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = mlnx_update_subscribed_ports_remove_group_member(isolation_group_entry, log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update ports subscribers\n");
        goto out;
    }

    isolation_group_entry->members[port_position] =
        isolation_group_entry->members[isolation_group_entry->members_count - 1];
    isolation_group_entry->members_count--;

    status = mlnx_isolation_group_update_subscribed_acl(isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update ACL entry\n");
        goto out;
    }


    switch (isolation_group_entry->type) {
    case SAI_ISOLATION_GROUP_TYPE_PORT:
        port->isolation_group_port_refcount--;
        break;

    case SAI_ISOLATION_GROUP_TYPE_BRIDGE_PORT:
        port->isolation_group_bridge_port_refcount--;
        break;

    default:
        SX_LOG_ERR("Invalid isolation group type\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

out:
    sai_db_unlock();

    return status;
}

static sai_status_t mlnx_set_isolation_group_member_attribute(_In_ sai_object_id_t        isolation_group_member_id,
                                                              _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = isolation_group_member_id};
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    isolation_group_member_key_to_str(isolation_group_member_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER,
                             isolation_group_member_vendor_attribs, attr);
}

sai_status_t mlnx_get_isolation_group_member_attribute(_In_ sai_object_id_t     isolation_group_member_id,
                                                       _In_ uint32_t            attr_count,
                                                       _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = isolation_group_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    isolation_group_member_key_to_str(isolation_group_member_id, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_ISOLATION_GROUP_MEMBER,
                              isolation_group_member_vendor_attribs, attr_count, attr_list);
}

/* needs sai_db write lock
 * This function finds isolation group members that are not applied on
 * any other port in the same lag
 */
static sai_status_t mlnx_get_group_members_to_delete_lag_from(mlnx_isolation_group_t *isolation_group_entry,
                                                              sx_port_log_id_t        lag_id,
                                                              sx_port_log_id_t       *members,
                                                              uint32_t               *member_count)
{
    uint32_t                ii, jj, kk;
    uint32_t                member_count_tmp;
    mlnx_isolation_group_t *isolation_group_db;
    bool                    lag_is_present;

    SX_LOG_ENTER();

    memcpy(members, isolation_group_entry->members,
           sizeof(*members) * isolation_group_entry->members_count);
    member_count_tmp = isolation_group_entry->members_count;

    /*iterate over isolation groups */
    isolation_group_db = g_sai_db_ptr->isolation_groups;
    for (ii = 0; (ii < MAX_ISOLATION_GROUPS) && (member_count_tmp > 0); ii++) {
        if ((!isolation_group_db[ii].is_used) || (&isolation_group_db[ii] == isolation_group_entry)) {
            continue;
        }

        /*find if port lag is subscribed to isolation group */
        lag_is_present = false;
        for (jj = 0; jj < isolation_group_db[ii].subscribed_ports_count; jj++) {
            if (isolation_group_db[ii].subscribed_ports[jj] == lag_id) {
                lag_is_present = true;
                break;
            }
        }

        if (!lag_is_present) {
            continue;
        }

        /*remove member from members if the member port is present in a different isolation group */
        for (jj = 0; (jj < isolation_group_db[ii].members_count) && (member_count_tmp > 0); jj++) {
            for (kk = 0; kk < member_count_tmp; kk++) {
                if (isolation_group_db[ii].members[jj] == members[kk]) {
                    members[kk] = members[member_count_tmp - 1];
                    member_count_tmp--;
                    break;
                }
            }
        }
    }

    *member_count = member_count_tmp;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_update_lag_isolation_group_remove_lag_member(mlnx_isolation_group_t *isolation_group_entry,
                                                                      sx_port_log_id_t        log_port)
{
    sx_status_t      sx_status;
    sai_status_t     status;
    int32_t          port_idx = -1;
    sx_port_log_id_t ports_to_delete_lag_from[MAX_ISOLATION_GROUP_MEMBERS];
    uint32_t         ports_count = MAX_ISOLATION_GROUP_MEMBERS;
    uint32_t         ii;
    uint32_t         lag_members_count = 0;

    for (ii = 0; ii < isolation_group_entry->subscribed_ports_count; ii++) {
        if (isolation_group_entry->subscribed_ports[ii] == log_port) {
            port_idx = ii;
            lag_members_count++;
        }
    }

    if (!lag_members_count) {
        SX_LOG_ERR("Port LAG is not group member\n");
        return SAI_STATUS_FAILURE;
    }

    /*update sx port isolation when last LAG member is going to be deleted*/
    if (lag_members_count == 1) {
        /*Find unique members that are only applied on current isolation group*/
        status = mlnx_get_group_members_to_delete_lag_from(isolation_group_entry, log_port, ports_to_delete_lag_from,
                                                           &ports_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get isolation group members for lag deletion\n");
            return status;
        }

        for (ii = 0; ii < ports_count; ii++) {
            sx_status = sx_api_port_isolate_set(gh_sdk, SX_ACCESS_CMD_DELETE, ports_to_delete_lag_from[ii],
                                                &log_port, 1);
            if (SX_ERR(sx_status)) {
                SX_LOG_ERR("Failed to set sx port isolation group - %s\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }
    }

    isolation_group_entry->subscribed_ports[port_idx] =
        isolation_group_entry->subscribed_ports[isolation_group_entry->subscribed_ports_count - 1];
    isolation_group_entry->subscribed_ports_count--;

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_unsubscribe_port_in_lag_from_isolation_group(mlnx_isolation_group_t *isolation_group_entry,
                                                                      mlnx_port_config_t     *port)
{
    sai_status_t     status;
    sx_port_log_id_t lag_log_port;

    SX_LOG_ENTER();

    lag_log_port = mlnx_port_get_lag_id(port);
    if (lag_log_port == 0) {
        SX_LOG_ERR("Failed to get LAG log port\n");
        return SAI_STATUS_FAILURE;
    }

    status = mlnx_update_lag_isolation_group_remove_lag_member(isolation_group_entry, lag_log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update LAG isolation group\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_unsubscribe_port_from_isolation_group_impl(mlnx_isolation_group_t *isolation_group_entry,
                                                                    sx_port_log_id_t        log_port)
{
    sx_status_t sx_status;
    uint32_t    ii;
    int32_t     port_idx = -1;

    SX_LOG_ENTER();

    for (ii = 0; ii < isolation_group_entry->subscribed_ports_count; ii++) {
        if (isolation_group_entry->subscribed_ports[ii] == log_port) {
            port_idx = ii;
            break;
        }
    }

    if (port_idx == -1) {
        SX_LOG_ERR("Port is not group member\n");
        return SAI_STATUS_FAILURE;
    }

    for (ii = 0; ii < isolation_group_entry->members_count; ii++) {
        sx_status = sx_api_port_isolate_set(gh_sdk, SX_ACCESS_CMD_DELETE, isolation_group_entry->members[ii],
                                            &log_port, 1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set sx port isolation group - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    isolation_group_entry->subscribed_ports[port_idx] =
        isolation_group_entry->subscribed_ports[isolation_group_entry->subscribed_ports_count - 1];
    isolation_group_entry->subscribed_ports_count--;

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_unsubscribe_port_from_isolation_group(sai_object_id_t     isolation_group,
                                                               mlnx_port_config_t *port)
{
    sai_status_t            status;
    mlnx_isolation_group_t *isolation_group_entry;

    SX_LOG_ENTER();

    status = mlnx_isolation_group_db_get_by_id(isolation_group, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get isolation group db\n");
        return status;
    }

    if ((isolation_group_entry->type == SAI_ISOLATION_GROUP_TYPE_PORT) && mlnx_port_is_lag_member(port)) {
        status = mlnx_unsubscribe_port_in_lag_from_isolation_group(isolation_group_entry, port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unsubscribe lag member port from isolation group\n");
            return status;
        }
    } else {
        status = mlnx_unsubscribe_port_from_isolation_group_impl(isolation_group_entry, port->logical);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unsubscribe port from isolation group\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_subscribe_port_to_isolation_group_impl(mlnx_isolation_group_t *isolation_group_entry,
                                                                sx_port_log_id_t        log_port)
{
    uint32_t    ii;
    sx_status_t sx_status;

    SX_LOG_ENTER();

    if (mlnx_isolation_group_find_member_port_pos(isolation_group_entry, log_port) != -1) {
        SX_LOG_ERR("Port is already a member of the isolation group\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (isolation_group_entry->subscribed_ports_count == MAX_SUBSCRIBED_PORTS_ISOLATION_GROUP) {
        SX_LOG_ERR("Failed to subscribe port: maximum subscriber ports reached\n");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    for (ii = 0; ii < isolation_group_entry->members_count; ii++) {
        sx_status = sx_api_port_isolate_set(gh_sdk, SX_ACCESS_CMD_ADD, isolation_group_entry->members[ii], &log_port,
                                            1);
        if (SX_ERR(sx_status)) {
            SX_LOG_ERR("Failed to set sx port isolation group - %s\n", SX_STATUS_MSG(sx_status));
            return sdk_to_sai(sx_status);
        }
    }

    isolation_group_entry->subscribed_ports[isolation_group_entry->subscribed_ports_count++] = log_port;

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_subscribe_port_to_isolation_group(sai_object_id_t     isolation_group,
                                                           sai_object_id_t     port_oid,
                                                           mlnx_port_config_t *port)
{
    mlnx_isolation_group_t *isolation_group_entry;
    sai_status_t            status;
    sx_port_log_id_t        log_port;

    SX_LOG_ENTER();

    status = mlnx_isolation_group_validate_port(isolation_group, port_oid);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Invalid port to apply isolation group on\n");
        return status;
    }

    status = mlnx_isolation_group_db_get_by_id(isolation_group, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed get isolation group db\n");
        return status;
    }

    if ((isolation_group_entry->type == SAI_ISOLATION_GROUP_TYPE_PORT) && mlnx_port_is_lag_member(port)) {
        log_port = mlnx_port_get_lag_id(port);
        if (log_port == 0) {
            SX_LOG_ERR("Failed to get LAG log port\n");
            return status;
        }
    } else {
        log_port = port->logical;
    }

    status = mlnx_subscribe_port_to_isolation_group_impl(isolation_group_entry, log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to subscribe to isolation group\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_validate_set_port_isolation_group(sai_object_id_t     port_oid,
                                                           mlnx_port_config_t *port,
                                                           sai_object_id_t     isolation_group)
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sai_object_type_t cur_group_objtype;
    sai_object_type_t port_objtype = sai_object_type_query(port_oid);

    SX_LOG_ENTER();

    if (port->isolation_group != SAI_NULL_OBJECT_ID) {
        status = mlnx_get_isolation_group_objtype(port->isolation_group, &cur_group_objtype);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get current isolation group object type\n");
            return status;
        }

        if (port_objtype != cur_group_objtype) {
            SX_LOG_ERR("Isolation group is already set on %s, trying to for set different type\n",
                       SAI_TYPE_STR(cur_group_objtype));
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (isolation_group != SAI_NULL_OBJECT_ID) {
        status = mlnx_isolation_group_validate_port(isolation_group, port_oid);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Invalid port for isolation group\n");
            return status;
        }
    }

    return status;
}

/* needs sai_db write lock */
sai_status_t mlnx_set_port_isolation_group_impl(sai_object_id_t port_oid, sai_object_id_t isolation_group)
{
    sai_status_t        status;
    mlnx_port_config_t *port;
    sx_port_log_id_t    log_port;

    SX_LOG_ENTER();

    status = mlnx_port_or_bridge_port_to_log_port(port_oid, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port object log port\n");
        return status;
    }

    status = mlnx_port_by_log_id(log_port, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port db\n");
        return status;
    }

    status = mlnx_validate_set_port_isolation_group(port_oid, port, isolation_group);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to validate isolation group set\n");
        return status;
    }

    if (port->isolation_group == isolation_group) {
        if (isolation_group != SAI_NULL_OBJECT_ID) {
            SX_LOG_INF("The group is already set to port\n");
        }

        return SAI_STATUS_SUCCESS;
    }

    if (port->isolation_group != SAI_NULL_OBJECT_ID) {
        status = mlnx_unsubscribe_port_from_isolation_group(port->isolation_group, port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to unsubscribe port from isolation group\n");
            return status;
        }
    }

    if (isolation_group != SAI_NULL_OBJECT_ID) {
        status = mlnx_subscribe_port_to_isolation_group(isolation_group, port_oid, port);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to subscribe port to isolation group\n");
            return status;
        }
    }

    port->isolation_group = isolation_group;

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db read lock */
sai_status_t mlnx_get_port_isolation_group_impl(sai_object_id_t port_oid, sai_object_id_t *isolation_group)
{
    sai_status_t        status;
    mlnx_port_config_t *port;
    sx_port_log_id_t    log_port;
    sai_object_type_t   group_objtype;
    sai_object_type_t   port_objtype = sai_object_type_query(port_oid);

    SX_LOG_ENTER();

    assert(isolation_group);

    status = mlnx_port_or_bridge_port_to_log_port(port_oid, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port object log port\n");
        return status;
    }

    status = mlnx_port_by_log_id(log_port, &port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port db\n");
        return status;
    }

    if (port->isolation_group == SAI_NULL_OBJECT_ID) {
        *isolation_group = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_get_isolation_group_objtype(port->isolation_group, &group_objtype);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get current isolation group object type\n");
        return status;
    }

    if (port_objtype == group_objtype) {
        *isolation_group = port->isolation_group;
    } else {
        *isolation_group = SAI_NULL_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db read lock*/
sai_status_t mlnx_get_acl_entry_isolation_group_impl(sai_object_id_t acl_entry, sai_object_id_t *isolation_group)
{
    int32_t                 isolation_group_db_idx;
    mlnx_isolation_group_t *isolation_group_entry = NULL;
    sai_status_t            status;

    SX_LOG_ENTER();

    assert(isolation_group);

    isolation_group_db_idx = mlnx_find_acl_entry_isolation_group_db(acl_entry, &isolation_group_entry);
    if (isolation_group_entry) {
        status = mlnx_create_isolation_group_oid(isolation_group_db_idx, isolation_group_entry->type, isolation_group);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to create isolation group object id\n");
            return status;
        }
    } else {
        *isolation_group = SAI_NULL_OBJECT_ID;
    }

    return SAI_STATUS_SUCCESS;
}

/*needs write lock for sai_sb and acl table*/
sai_status_t mlnx_set_acl_entry_isolation_group_impl(sai_object_id_t acl_entry, sai_object_id_t new_isolation_group)
{
    sai_status_t            status;
    mlnx_isolation_group_t *cur_isolation_group_entry, *new_isolation_group_entry = NULL;
    sx_port_log_id_t       *log_port_list = NULL;
    uint32_t                ii, log_port_count = 0;

    SX_LOG_ENTER();

    mlnx_find_acl_entry_isolation_group_db(acl_entry, &cur_isolation_group_entry);

    if (new_isolation_group != SAI_NULL_OBJECT_ID) {
        status = mlnx_isolation_group_db_get_by_id(new_isolation_group, &new_isolation_group_entry);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to get isolation group db entry\n");
            return status;
        }
    }

    if (cur_isolation_group_entry == new_isolation_group_entry) {
        return SAI_STATUS_SUCCESS;
    }

    if (new_isolation_group_entry &&
        (new_isolation_group_entry->subscribed_acl_count == MAX_SUBSCRIBED_ACL_ISOLATION_GROUP)) {
        SX_LOG_ERR("Maximum number of subscribed ACL entries reached\n");
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (new_isolation_group_entry && (new_isolation_group_entry->members_count > 0)) {
        log_port_list = new_isolation_group_entry->members;
        log_port_count = new_isolation_group_entry->members_count;
    }

    status = mlnx_acl_isolation_group_update_not_locked(acl_entry, log_port_list, log_port_count);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update acl entry port isolation\n");
        return status;
    }

    if (cur_isolation_group_entry) {
        for (ii = 0; ii < cur_isolation_group_entry->subscribed_acl_count; ii++) {
            if (cur_isolation_group_entry->subscribed_acl[ii] == acl_entry) {
                cur_isolation_group_entry->subscribed_acl[ii] =
                    cur_isolation_group_entry->subscribed_acl[cur_isolation_group_entry->subscribed_acl_count - 1];

                cur_isolation_group_entry->subscribed_acl_count--;
            }
        }
    }

    if (new_isolation_group_entry) {
        new_isolation_group_entry->subscribed_acl[new_isolation_group_entry->subscribed_acl_count] = acl_entry;
        new_isolation_group_entry->subscribed_acl_count++;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
static sai_status_t mlnx_isolation_group_update_subscribed_acl(mlnx_isolation_group_t *isolation_group)
{
    sai_status_t status;
    uint32_t     ii;

    SX_LOG_ENTER();

    for (ii = 0; ii < isolation_group->subscribed_acl_count; ii++) {
        status = mlnx_acl_isolation_group_update(isolation_group->subscribed_acl[ii],
                                                 isolation_group->members, isolation_group->members_count);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to update ACL entry\n");
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
sai_status_t mlnx_port_move_isolation_group_to_lag(mlnx_port_config_t *port, mlnx_port_config_t *lag)
{
    sai_status_t            status;
    mlnx_isolation_group_t *isolation_group_entry;

    assert(port);
    assert(lag);

    SX_LOG_ENTER();

    if (port->isolation_group == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_isolation_group_db_get_by_id(port->isolation_group, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        return status;
    }

    if (isolation_group_entry->type != SAI_ISOLATION_GROUP_TYPE_PORT) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_unsubscribe_port_from_isolation_group_impl(isolation_group_entry, port->logical);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unset port isolation group\n");
        return status;
    }

    status = mlnx_subscribe_port_to_isolation_group_impl(isolation_group_entry, lag->logical);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to subscribe lag to isolation group\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

/* needs sai_db write lock */
sai_status_t mlnx_port_move_isolation_group_from_lag(mlnx_port_config_t *lag, mlnx_port_config_t *port)
{
    sai_status_t            status;
    mlnx_isolation_group_t *isolation_group_entry;

    assert(port);
    assert(lag);

    SX_LOG_ENTER();

    if (port->isolation_group == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_isolation_group_db_get_by_id(port->isolation_group, &isolation_group_entry);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get isolation group db entry\n");
        return status;
    }

    if (isolation_group_entry->type != SAI_ISOLATION_GROUP_TYPE_PORT) {
        return SAI_STATUS_SUCCESS;
    }

    status = mlnx_update_lag_isolation_group_remove_lag_member(isolation_group_entry, lag->logical);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unsubscribe lag member port from isolation group\n");
        return status;
    }

    status = mlnx_subscribe_port_to_isolation_group_impl(isolation_group_entry, port->logical);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to subscribe lag to isolation group\n");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_isolation_group_update_mc_containers(sx_access_cmd_t cmd, sx_port_log_id_t log_port)
{
    uint32_t                ii, jj;
    mlnx_isolation_group_t *isolation_group_db = g_sai_db_ptr->isolation_groups;
    sai_status_t            status;

    for (ii = 0; ii < MAX_ISOLATION_GROUPS; ii++) {
        if (isolation_group_db[ii].members_count && isolation_group_db[ii].subscribed_acl_count) {
            for (jj = 0; jj < isolation_group_db[ii].subscribed_acl_count; jj++) {
                status = mlnx_acl_entry_update_port_filter(isolation_group_db[ii].subscribed_acl[jj], cmd, log_port);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed to update acl entry mc_container\n");
                    return status;
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

const sai_isolation_group_api_t mlnx_isolation_group_api = {
    mlnx_create_isolation_group,
    mlnx_remove_isolation_group,
    mlnx_set_isolation_group_attribute,
    mlnx_get_isolation_group_attribute,
    mlnx_create_isolation_group_member,
    mlnx_remove_isolation_group_member,
    mlnx_set_isolation_group_member_attribute,
    mlnx_get_isolation_group_member_attribute,
};
