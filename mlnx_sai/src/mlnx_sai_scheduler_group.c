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

typedef enum mlnx_list_cmd {
    LIST_CMD_ADD,
    LIST_CMD_DEL,
} mlnx_list_cmd_t;

#undef  __MODULE__
#define __MODULE__ SAI_SCHEDULER_GROUPS

#define level_max_groups(level) (uint32_t)MAX_SCHED_CHILD_GROUPS

#define level_max_childs(level) \
    (((level) == MAX_SCHED_LEVELS - 1) ? MAX_QUEUES : MAX_SCHED_CHILD_GROUPS)

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_sched_group_child_count_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_sched_group_child_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_sched_group_port_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t mlnx_sched_group_level_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_sched_group_max_childs_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t mlnx_sched_group_profile_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_sched_group_profile_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t sched_group_add_or_del_child_list(sai_object_id_t       scheduler_group_id,
                                                      const sai_object_id_t child_id,
                                                      mlnx_list_cmd_t       cmd);
static sai_status_t sai_obj_to_sched_obj(mlnx_port_config_t *port, mlnx_sched_obj_t   *sch_obj,
                                         sai_object_id_t sai_obj);
static const sai_vendor_attribute_entry_t sched_group_vendor_attribs[] = {
    /* READ-ONLY */
    { SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_sched_group_child_count_get, NULL,
      NULL, NULL },
    { SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_sched_group_child_list_get, NULL,
      NULL, NULL },
    /* CREATE-ONLY */
    { SAI_SCHEDULER_GROUP_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_sched_group_port_get, NULL,
      NULL, NULL },
    { SAI_SCHEDULER_GROUP_ATTR_LEVEL,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_sched_group_level_get, NULL,
      NULL, NULL },
    { SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_sched_group_max_childs_get, NULL,
      NULL, NULL },
    /* READ, WRITE, CREATE */
    { SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_group_profile_get, NULL,
      mlnx_sched_group_profile_set, NULL},
    { SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_sched_group_parent_get, NULL,
      mlnx_sched_group_parent_set, NULL},
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
const mlnx_obj_type_attrs_info_t mlnx_sched_group_obj_type_info =
    { sched_group_vendor_attribs, OBJ_ATTRS_ENUMS_INFO_EMPTY()};
static mlnx_sched_obj_t * group_get(mlnx_port_config_t *port, uint8_t level, uint8_t index)
{
    return &port->sched_hierarchy.groups[level][index];
}

static sx_cos_ets_element_config_t * sched_obj_to_ets(mlnx_sched_obj_t *obj, sx_cos_ets_element_config_t *ets)
{
    assert(obj != NULL);
    assert(ets != NULL);

    ets->element_index      = obj->index;
    ets->element_hierarchy  = obj->ets_type;
    ets->next_element_index = (obj->next_index == INVALID_INDEX) ? 0 : obj->next_index;

    return ets;
}

static sai_status_t ets_lookup(sx_cos_ets_element_config_t  *ets_list,
                               mlnx_sched_obj_t             *sch_obj,
                               sx_cos_ets_element_config_t **ets)
{
    uint32_t ii;

    for (ii = 0; ii < MAX_ETS_ELEMENTS; ii++) {
        if ((ets_list[ii].element_hierarchy == sch_obj->ets_type) &&
            (ets_list[ii].element_index == sch_obj->index)) {
            *ets = &ets_list[ii];
            return SAI_STATUS_SUCCESS;
        }
    }

    SX_LOG_ERR("Failed lookup ETS element by level %u and index %u\n",
               sch_obj->level, sch_obj->index);

    return SAI_STATUS_ITEM_NOT_FOUND;
}

static void queue_to_sched_obj(mlnx_port_config_t      *port,
                               mlnx_qos_queue_config_t *queue,
                               uint32_t                 index,
                               mlnx_sched_obj_t        *obj)
{
    assert(obj != NULL);
    assert(queue != NULL);

    memcpy(obj, &queue->sched_obj, sizeof(*obj));
}

sai_status_t mlnx_sched_hierarchy_foreach(mlnx_port_config_t    *port,
                                          mlnx_sched_obj_iter_t  iter,
                                          mlnx_sched_iter_ctx_t *ctx)
{
    mlnx_qos_queue_config_t *queue;
    mlnx_iter_ret_t          ret;
    uint32_t                 ii, lvl;

    assert(iter != NULL);

    for (lvl = 0; lvl < MAX_SCHED_LEVELS; lvl++) {
        for (ii = 0; ii < level_max_groups(lvl); ii++) {
            ret = iter(port, group_get(port, lvl, ii), ctx);
            if (ret == ITER_STOP) {
                goto out;
            }
        }
    }

    port_queues_foreach(port, queue, ii) {
        ret = iter(port, &queue->sched_obj, ctx);
        if (ret == ITER_STOP) {
            goto out;
        }
    }

out:
    if (ctx) {
        return ctx->sai_status;
    }

    return SAI_STATUS_SUCCESS;
}

static mlnx_iter_ret_t groups_child_iter(mlnx_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_obj_t      *parent;
    mlnx_sched_iter_ctx_t *ctx = arg;

    assert(ctx != NULL);
    assert(obj != NULL);

    parent = (mlnx_sched_obj_t*)ctx->arg;

    if ((obj->level != parent->level + 1) || (obj->next_index != parent->index)) {
        return ITER_NEXT;
    }

    return ctx->iter(port, obj, ctx->iter_ctx);
}

static sai_status_t groups_child_foreach(mlnx_port_config_t    *port,
                                         uint8_t                lvl,
                                         uint8_t                idx,
                                         mlnx_sched_obj_iter_t  iter,
                                         mlnx_sched_iter_ctx_t *ctx)
{
    mlnx_sched_obj_t      parent    = {.level = lvl, .index = idx };
    mlnx_sched_iter_ctx_t child_ctx = { .arg = &parent, .iter = iter, .iter_ctx = ctx };

    parent.level = lvl;
    parent.index = idx;

    child_ctx.arg      = &parent;
    child_ctx.iter     = iter;
    child_ctx.iter_ctx = ctx;

    mlnx_sched_hierarchy_foreach(port, groups_child_iter, &child_ctx);
    return ctx->sai_status;
}

static sai_status_t ets_list_load(sx_port_log_id_t port_id, sx_cos_ets_element_config_t **ets)
{
    uint32_t     max_ets_count = MAX_ETS_ELEMENTS;
    sai_status_t status;

    assert(ets != NULL);

    *ets = (sx_cos_ets_element_config_t*)malloc(sizeof(**ets) * max_ets_count);
    if (!*ets) {
        SX_LOG_ERR("Failed allocate memory for ETS list\n");
        return SAI_STATUS_NO_MEMORY;
    }

    status = sx_api_cos_port_ets_element_get(gh_sdk, port_id, *ets, &max_ets_count);
    if (status != SX_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed get ETS list - %s\n", SX_STATUS_MSG(status));
    }

    status = sdk_to_sai(status);
    if (status != SAI_STATUS_SUCCESS) {
        free(*ets);
        *ets = NULL;
    }

    return status;
}

static void mlnx_sched_group_key_to_str(_In_ sai_object_id_t group_id, _Out_ char *key_str)
{
    sx_port_log_id_t port_id;
    sai_status_t     status;
    uint8_t          index,   level;

    status = mlnx_sched_group_parse_id(group_id, &port_id, &level, &index);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid scheduler group id");
        return;
    }

    snprintf(key_str, MAX_KEY_STR_LEN, "scheduler group id %x:%u:%u", port_id, level, index);
}

static mlnx_iter_ret_t groups_child_counter(mlnx_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;

    assert(arg != NULL);

    if (obj->is_used) {
        (*(uint32_t*)ctx->arg)++;
    }

    ctx->sai_status = SAI_STATUS_SUCCESS;
    return ITER_NEXT;
}

static mlnx_iter_ret_t groups_child_to_objlist(mlnx_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;
    sai_object_list_t     *obj_list;
    uint32_t               ii;

    assert(ctx != NULL);

    if (!obj->is_used) {
        return ITER_NEXT;
    }

    obj_list = (sai_object_list_t*)ctx->arg;
    ii       = obj_list->count++;

    if (obj->type == MLNX_SCHED_OBJ_QUEUE) {
        ctx->sai_status = mlnx_create_queue_object(port->logical, obj->index, &obj_list->list[ii]);
    } else if (obj->type == MLNX_SCHED_OBJ_GROUP) {
        ctx->sai_status = mlnx_create_sched_group(port->logical, obj->level, obj->index,
                                                  &obj_list->list[ii]);
    } else {
        assert(false);
    }

    if (SAI_ERR(ctx->sai_status)) {
        return ITER_STOP;
    }

    return ITER_NEXT;
}

/** Number of queues/groups childs added to
 * scheduler group [uint32_t] */
static sai_status_t mlnx_sched_group_child_count_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    mlnx_port_config_t   *port;
    sx_port_log_id_t      port_id;
    mlnx_sched_iter_ctx_t ctx;
    sai_status_t          status;
    uint32_t              count = 0;
    uint8_t               idx;
    uint8_t               lvl;

    status = mlnx_sched_group_parse_id(key->key.object_id, &port_id, &lvl, &idx);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed parse scheduler group id\n");
        return status;
    }

    sai_qos_db_read_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    ctx.sai_status = SAI_STATUS_SUCCESS;
    ctx.arg        = &count;

    status = groups_child_foreach(port, lvl, idx, groups_child_counter, &ctx);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->u32 = count;

out:
    sai_qos_db_unlock();
    return status;
}

/** Scheduler Group child obejct id List [sai_object_list_t] */
static sai_status_t mlnx_sched_group_child_list_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    mlnx_port_config_t   *port;
    sai_object_list_t     child_list = {0};
    sx_port_log_id_t      port_id;
    mlnx_sched_iter_ctx_t ctx;
    sai_status_t          status;
    uint32_t              count = 0;
    uint8_t               idx;
    uint8_t               lvl;

    status = mlnx_sched_group_parse_id(key->key.object_id, &port_id, &lvl, &idx);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("Failed parse scheduler group id\n");
        return status;
    }

    sai_qos_db_read_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    ctx.sai_status = SAI_STATUS_SUCCESS;
    ctx.arg        = &count;

    status = groups_child_foreach(port, lvl, idx, groups_child_counter, &ctx);
    if (SAI_ERR(status)) {
        goto out;
    }

    child_list.list = malloc(count * sizeof(sai_object_id_t));
    if (!child_list.list) {
        SX_LOG_ERR("Failed allocate memory for child list\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    child_list.count = 0; /* will be filled by child iterator */

    ctx.sai_status = SAI_STATUS_SUCCESS;
    ctx.arg        = &child_list;

    status = groups_child_foreach(port, lvl, idx, groups_child_to_objlist, &ctx);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_fill_objlist(child_list.list, child_list.count, &value->objlist);

out:
    if (child_list.list) {
        free(child_list.list);
    }
    sai_qos_db_unlock();
    return status;
}

/** Scheduler group on port [sai_object_id_t]
 *  MANDATORY_ON_CREATE,  CREATE_ONLY */
static sai_status_t mlnx_sched_group_port_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sx_port_log_id_t port_log_id;
    sai_status_t     status;

    SX_LOG_ENTER();

    status = mlnx_sched_group_parse_id(key->key.object_id, &port_log_id, NULL, NULL);
    if (status != SAI_STATUS_SUCCESS) {
        return status;
    }

    status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, port_log_id, NULL, &value->oid);

    SX_LOG_EXIT();
    return status;
}

/** Scheduler group level [sai_uint8_t]
*  MANDATORY_ON_CREATE,  CREATE_ONLY */
static sai_status_t mlnx_sched_group_level_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    status = mlnx_sched_group_parse_id(key->key.object_id, NULL, &value->u8, NULL);

    SX_LOG_EXIT();
    return status;
}

/** Maximum Number of childs on group [uint8_t]
 * MANDATORY_ON_CREATE,  CREATE_ONLY */
static sai_status_t mlnx_sched_group_max_childs_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    mlnx_port_config_t *port;
    sx_port_log_id_t    port_id;
    sai_status_t        status;
    uint8_t             level;
    uint8_t             index;

    SX_LOG_ENTER();

    status = mlnx_sched_group_parse_id(key->key.object_id, &port_id, &level, &index);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_EXIT();
        return status;
    }

    sai_qos_db_read_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->u8 = group_get(port, level, index)->max_child_count;

out:
    sai_qos_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/** Scheduler ID [sai_object_id_t] */
static sai_status_t mlnx_sched_group_profile_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    mlnx_port_config_t *port;
    sx_port_log_id_t    port_id;
    sai_status_t        status;
    uint8_t             level;
    uint8_t             index;

    SX_LOG_ENTER();

    status = mlnx_sched_group_parse_id(key->key.object_id, &port_id, &level, &index);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_EXIT();
        return status;
    }

    sai_qos_db_read_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->oid = group_get(port, level, index)->scheduler_id;

    SX_LOG_DBG("Get scheduler profile id %" PRIx64 " for group at port %x level %u index %u\n",
               value->oid, port_id, level, index);

out:
    sai_qos_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/** Scheduler ID [sai_object_id_t] */
static sai_status_t mlnx_sched_group_profile_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    sai_qos_db_write_lock();

    status = mlnx_scheduler_to_group_apply(value->oid, key->key.object_id);

    sai_qos_db_sync();
    sai_qos_db_unlock();

    SX_LOG_EXIT();
    return status;
}

/* It is used also by mlnx_sai_queue.c */
sai_status_t mlnx_sched_group_parent_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    uint8_t             ext_data[EXTENDED_DATA_SIZE] = {0};
    sx_port_log_id_t    port_id;
    sai_status_t        status;
    uint8_t             index;
    uint8_t             level;
    mlnx_sched_obj_t    group;
    mlnx_port_config_t *port;

    SX_LOG_ENTER();

    if (sai_object_type_query(key->key.object_id) == SAI_OBJECT_TYPE_QUEUE) {
        status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_QUEUE, &port_id, ext_data);
    } else if (sai_object_type_query(key->key.object_id) == SAI_OBJECT_TYPE_SCHEDULER_GROUP) {
        status = mlnx_sched_group_parse_id(key->key.object_id, &port_id, &level, &index);
    } else {
        status = SAI_STATUS_INVALID_OBJECT_TYPE;
        SX_LOG_ERR("Expected queue or scheduler group object type\n");
    }

    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_qos_db_read_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = sai_obj_to_sched_obj(port, &group, key->key.object_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->oid = group.parent_id;

out:
    sai_qos_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/* It is used also by mlnx_sai_queue.c */
sai_status_t mlnx_sched_group_parent_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    sai_status_t    status;
    mlnx_list_cmd_t cmd;

    SX_LOG_ENTER();

    sai_qos_db_write_lock();

    cmd = value->oid == SAI_NULL_OBJECT_ID ? LIST_CMD_DEL : LIST_CMD_ADD;

    status = sched_group_add_or_del_child_list(value->oid, key->key.object_id, cmd);
    sai_qos_db_unlock();

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_sched_objlist_to_ets_update(sx_port_log_id_t  port_id,
                                                     mlnx_sched_obj_t *sch_objlist,
                                                     uint32_t          count)
{
    sx_cos_ets_element_config_t *ets_list = NULL;
    sx_status_t                  sx_status;
    sai_status_t                 status;
    uint32_t                     ii;

    assert(sch_objlist != NULL);

    status = ets_list_load(port_id, &ets_list);
    if (SAI_ERR(status)) {
        goto out;
    }

    for (ii = 0; ii < count; ii++) {
        sx_cos_ets_element_config_t *ets;

        status = ets_lookup(ets_list, &sch_objlist[ii], &ets);
        if (SAI_ERR(status)) {
            goto out;
        }

        sched_obj_to_ets(&sch_objlist[ii], ets);

        SX_LOG_DBG("Changed ETS element (type %u index %u) next index %u -> %u\n",
                   ets->element_hierarchy,
                   sch_objlist[ii].next_index,
                   ets->next_element_index,
                   ets->element_index);
    }

    sx_status = sx_api_cos_port_ets_element_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                                port_id, ets_list, MAX_ETS_ELEMENTS);

    status = sdk_to_sai(sx_status);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update ETS elements on log port id 0x%x - %s\n",
                   port_id, SX_STATUS_MSG(sx_status));
    }

out:
    if (ets_list) {
        free(ets_list);
    }
    return status;
}

static mlnx_iter_ret_t sched_obj_reset(mlnx_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;
    sai_object_id_t        group_id;

    assert(ctx != NULL);

    obj->next_index = INVALID_INDEX;

    if (obj->type != MLNX_SCHED_OBJ_GROUP) {
        return ITER_NEXT;
    }

    ctx->sai_status = mlnx_create_sched_group(port->logical, obj->level, obj->index, &group_id);
    if (SAI_ERR(ctx->sai_status)) {
        return ITER_STOP;
    }

    ctx->sai_status = mlnx_scheduler_to_group_apply(SAI_NULL_OBJECT_ID, group_id);
    if (SAI_ERR(ctx->sai_status)) {
        SX_LOG_ERR("Failed to reset scheduler profile on group at port %x level %u index %u\n",
                   port->logical, obj->level, obj->index);
        return ITER_STOP;
    }

    obj->is_used   = false;
    obj->parent_id = SAI_NULL_OBJECT_ID;
    port->sched_hierarchy.groups_count[obj->level]--;

    ctx->sai_status = mlnx_sched_objlist_to_ets_update(port->logical, obj, 1);
    if (SAI_ERR(ctx->sai_status)) {
        return ITER_STOP;
    }

    return ITER_NEXT;
}

static sai_status_t sched_hierarchy_reset(mlnx_port_config_t *port)
{
    mlnx_sched_iter_ctx_t ctx = { .sai_status = SAI_STATUS_SUCCESS };

    SX_LOG_NTC("Drop default hierarchy on log port id %x\n", port->logical);

    mlnx_sched_hierarchy_foreach(port, sched_obj_reset, &ctx);
    if (SAI_ERR(ctx.sai_status)) {
        SX_LOG_ERR("Failed drop default hierarchy on log port id %x\n", port->logical);
        return ctx.sai_status;
    }
    port->sched_hierarchy.is_default = false;

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sched_hierarchy_reset(mlnx_port_config_t *port)
{
    if (port->sched_hierarchy.is_default) {
        return sched_hierarchy_reset(port);
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief  Create Scheduler group
 *
 * @param[out] scheduler_group_id Scheudler group id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_create_scheduler_group(_Out_ sai_object_id_t      *scheduler_group_id,
                                                _In_ sai_object_id_t        switch_id,
                                                _In_ uint32_t               attr_count,
                                                _In_ const sai_attribute_t *attr_list)
{
    uint32_t                     ii;
    const sai_attribute_value_t *attr;
    uint32_t                     index;
    sai_status_t                 status;
    mlnx_port_config_t          *port;
    sx_port_log_id_t             port_id;
    uint8_t                      level;
    uint8_t                      max_child_count;
    sai_object_id_t              parent_group_id = SAI_NULL_OBJECT_ID;
    sai_object_id_t              scheduler_id    = SAI_NULL_OBJECT_ID;
    mlnx_sched_obj_t            *sched_obj       = NULL;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];

    SX_LOG_ENTER();

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_SCHEDULER_GROUP,
                                    sched_group_vendor_attribs,
                                    SAI_COMMON_API_CREATE);

    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_SCHEDULER_GROUP, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create scheduler group, %s\n", list_str);

    /* Handle SAI_SCHEDULER_GROUP_ATTR_PORT_ID */
    status = find_attrib_in_list(attr_count, attr_list, SAI_SCHEDULER_GROUP_ATTR_PORT_ID,
                                 &attr, &index);

    assert(!SAI_ERR(status));

    status = mlnx_object_to_type(attr->oid, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
    if (SAI_ERR(status)) {
        return status;
    }

    parent_group_id = attr->oid;

    /* Handle SAI_SCHEDULER_GROUP_ATTR_LEVEL */
    status = find_attrib_in_list(attr_count, attr_list, SAI_SCHEDULER_GROUP_ATTR_LEVEL,
                                 &attr, &index);

    assert(!SAI_ERR(status));

    level = attr->u8;
    if (level >= MAX_SCHED_LEVELS) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SX_LOG_ERR("Invalid scheduler group level %u, (min, max) allowed are (%u, %u)\n",
                   level, 0, MAX_SCHED_LEVELS - 1);
        goto out;
    }

    if (level > 0) {
        /* Handle SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE */
        status = find_attrib_in_list(attr_count, attr_list, SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE,
                                     &attr, &index);

        if (SAI_ERR(status)) {
            SX_LOG_ERR("Missing SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE attribute for level > 0\n");
            status = SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            goto out;
        }

        parent_group_id = attr->oid;
    }

    sai_qos_db_write_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_sched_hierarchy_reset(port);
    if (SAI_ERR(status)) {
        goto out;
    }

    /* Find free sched group object */
    for (ii = 0; ii < level_max_groups(level); ii++) {
        if (!group_get(port, level, ii)->is_used) {
            sched_obj = group_get(port, level, ii);
            break;
        }
    }

    if (!sched_obj) {
        SX_LOG_ERR("No free scheduler groups on level %u\n", level);
        status = SAI_STATUS_TABLE_FULL;
        goto out;
    }

    /* Handle SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID */
    status = find_attrib_in_list(attr_count, attr_list, SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID,
                                 &attr, &index);
    if (!SAI_ERR(status)) {
        scheduler_id = attr->oid;
    }

    /* Handle SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS */
    status = find_attrib_in_list(attr_count, attr_list, SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS,
                                 &attr, &index);

    assert(!SAI_ERR(status));

    max_child_count = attr->u8;
    if (max_child_count > level_max_childs(level)) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SX_LOG_ERR("Invalid scheduler group max childs %u, maximum allowed is %u\n",
                   max_child_count, level_max_childs(level));
        goto out;
    }

    status = mlnx_create_sched_group(port_id, level, ii, scheduler_group_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (parent_group_id != SAI_NULL_OBJECT_ID) {
        status = sched_group_add_or_del_child_list(parent_group_id, *scheduler_group_id, LIST_CMD_ADD);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to set parent group oid %" PRIx64 "\n", parent_group_id);
            goto out;
        }
    }

    status = mlnx_scheduler_to_group_apply(scheduler_id, *scheduler_group_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to apply scheduler profile on created group\n");
        goto out;
    }

    sched_obj->is_used         = true;
    sched_obj->max_child_count = max_child_count;
    sched_obj->scheduler_id    = scheduler_id;

    port->sched_hierarchy.groups_count[level]++;

    SX_LOG_NTC("Created scheduler group %" PRIx64 " at port %x level %u index %u\n",
               *scheduler_group_id, port_id, sched_obj->level, sched_obj->index);
out:
    sai_qos_db_sync();
    sai_qos_db_unlock();
    SX_LOG_EXIT();
    return status;
}

static mlnx_iter_ret_t groups_child_exist(mlnx_port_config_t *port, mlnx_sched_obj_t *obj, void *arg)
{
    mlnx_sched_iter_ctx_t *ctx = arg;

    assert(arg != NULL);

    ctx->sai_status = SAI_STATUS_OBJECT_IN_USE;
    return ITER_STOP;
}

/**
 * @brief  Remove Scheduler group
 *
 * @param[in] scheduler_group_id Scheudler group id
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_remove_scheduler_group(_In_ sai_object_id_t scheduler_group_id)
{
    mlnx_port_config_t   *port;
    uint8_t               level;
    uint8_t               index;
    sx_port_log_id_t      port_id;
    sai_status_t          status;
    mlnx_sched_iter_ctx_t ctx;
    mlnx_sched_obj_t     *group;

    SX_LOG_ENTER();

    status = mlnx_sched_group_parse_id(scheduler_group_id, &port_id, &level, &index);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    sai_qos_db_write_lock();

    status = mlnx_port_by_log_id(port_id, &port);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (!group_get(port, level, index)->is_used) {
        SX_LOG_ERR("Failed remove non existing group\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    ctx.sai_status = SAI_STATUS_SUCCESS;

    status = groups_child_foreach(port, level, index, groups_child_exist, &ctx);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed remove scheduler group %" PRIx64 ": there are bound child list\n",
                   scheduler_group_id);
        goto out;
    }

    status = mlnx_scheduler_to_group_apply(SAI_NULL_OBJECT_ID, scheduler_group_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to reset scheduler profile for group at log port %x level %u index %u\n",
                   port_id, level, index);
        goto out;
    }

    /* Invalidate scheduler group object */
    group               = group_get(port, level, index);
    group->is_used      = false;
    group->next_index   = INVALID_INDEX;
    group->scheduler_id = SAI_NULL_OBJECT_ID;
    group->parent_id    = SAI_NULL_OBJECT_ID;

    port->sched_hierarchy.groups_count[level]--;

    SX_LOG_NTC("Removed scheduler group on log port id %x level %u index %u\n",
               port_id, level, index);
out:
    sai_qos_db_sync();
    sai_qos_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief  Set Scheduler group Attribute
 *
 * @param[in] scheduler_group_id Scheudler group id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
static sai_status_t mlnx_set_scheduler_group_attribute(_In_ sai_object_id_t        scheduler_group_id,
                                                       _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = scheduler_group_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    mlnx_sched_group_key_to_str(scheduler_group_id, key_str);
    status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_SCHEDULER_GROUP,
                               sched_group_vendor_attribs, attr);
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief  Get Scheduler Group attribute
 *
 * @param[in] scheduler_group_id - scheduler group id
 * @param[in] attr_count - number of attributes
 * @param[inout] attr_list - array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */

static sai_status_t mlnx_get_scheduler_group_attribute(_In_ sai_object_id_t     scheduler_group_id,
                                                       _In_ uint32_t            attr_count,
                                                       _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = scheduler_group_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    mlnx_sched_group_key_to_str(scheduler_group_id, key_str);
    status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_SCHEDULER_GROUP,
                                sched_group_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return status;
}

/* DB read lock is needed */
static sai_status_t sai_obj_to_sched_obj(mlnx_port_config_t *port, mlnx_sched_obj_t   *sch_obj,
                                         sai_object_id_t sai_obj)
{
    mlnx_qos_queue_config_t *queue;
    sx_port_log_id_t         port_id;
    sai_status_t             status;
    uint8_t                  level;
    uint8_t                  index;

    assert(port != NULL);
    assert(sch_obj != NULL);

    if (sai_object_type_query(sai_obj) == SAI_OBJECT_TYPE_QUEUE) {
        status = mlnx_queue_parse_id(sai_obj, &port_id, &index);
        if (SAI_ERR(status)) {
            return status;
        }

        if (port->logical != port_id) {
            SX_LOG_ERR("Invalid queue logical port id %x\n", port_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        status = mlnx_queue_cfg_lookup(port_id, index, &queue);
        if (SAI_ERR(status)) {
            return status;
        }

        queue_to_sched_obj(port, queue, index, sch_obj);
    } else if (sai_object_type_query(sai_obj) == SAI_OBJECT_TYPE_SCHEDULER_GROUP) {
        status = mlnx_sched_group_parse_id(sai_obj, &port_id, &level, &index);
        if (SAI_ERR(status)) {
            return status;
        }

        if (port->logical != port_id) {
            SX_LOG_ERR("Invalid scheduler group logical port id %x\n", port_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        memcpy(sch_obj, group_get(port, level, index), sizeof(*sch_obj));
    } else {
        /* We should not get here */
        assert(false);
    }

    return status;
}

static sai_status_t mlnx_sched_objlist_to_hierarchy_update(mlnx_port_config_t *port,
                                                           mlnx_sched_obj_t   *sch_objlist,
                                                           uint32_t            count)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    assert(count > 0);
    assert(port != NULL);
    assert(sch_objlist != NULL);

    for (ii = 0; ii < count; ii++) {
        mlnx_sched_obj_t *obj = &sch_objlist[ii];

        if (obj->type == MLNX_SCHED_OBJ_GROUP) {
            memcpy(group_get(port, obj->level, obj->index), obj, sizeof(*obj));
        } else if (obj->type == MLNX_SCHED_OBJ_QUEUE) {
            mlnx_qos_queue_config_t *queue;

            status = mlnx_queue_cfg_lookup(port->logical, obj->index, &queue);
            if (SAI_ERR(status)) {
                return status;
            }

            queue->sched_obj.parent_id  = obj->parent_id;
            queue->sched_obj.next_index = obj->next_index;
            queue->sched_obj.level      = obj->level;
            queue->sched_obj.ets_type   = obj->ets_type;
        } else {
            /* We should not reach here */
            assert(false);
        }
    }

    return status;
}

static sai_status_t sched_group_add_or_del_child_list(sai_object_id_t       parent_id,
                                                      const sai_object_id_t child_id,
                                                      mlnx_list_cmd_t       cmd)
{
    uint8_t           parent_level = 0;
    uint8_t           parent_index = 0;
    mlnx_sched_obj_t  sch_child;
    mlnx_sched_obj_t *parent_sch_obj;
    mlnx_sched_obj_t  parent_port =
    { .index = 0, .type = MLNX_SCHED_OBJ_PORT, .max_child_count = MAX_SCHED_CHILD_GROUPS };
    sx_port_log_id_t    port_id;
    sai_status_t        status;
    mlnx_port_config_t *port;

    if (cmd == LIST_CMD_ADD) {
        sai_object_type_t parent_type = sai_object_type_query(parent_id);

        if (parent_type == SAI_OBJECT_TYPE_SCHEDULER_GROUP) {
            uint32_t              count = 0;
            mlnx_sched_iter_ctx_t ctx;

            status = mlnx_sched_group_parse_id(parent_id, &port_id, &parent_level, &parent_index);
            if (SAI_ERR(status)) {
                return status;
            }

            status = mlnx_port_by_log_id(port_id, &port);
            if (SAI_ERR(status)) {
                goto out;
            }

            parent_sch_obj = group_get(port, parent_level, parent_index);

            ctx.sai_status = SAI_STATUS_SUCCESS;
            ctx.arg        = &count;

            status = groups_child_foreach(port, parent_level, parent_index, groups_child_counter, &ctx);
            if (SAI_ERR(status)) {
                goto out;
            }

            if (count >= parent_sch_obj->max_child_count) {
                SX_LOG_ERR("Child groups count %u exceeds max value %u\n",
                           count, parent_sch_obj->max_child_count);

                status = SAI_STATUS_TABLE_FULL;
                goto out;
            }
        } else if (parent_type == SAI_OBJECT_TYPE_PORT) {
            status = mlnx_object_to_type(parent_id, SAI_OBJECT_TYPE_PORT, &port_id, NULL);
            if (SAI_ERR(status)) {
                return status;
            }

            status = mlnx_port_by_log_id(port_id, &port);
            if (SAI_ERR(status)) {
                goto out;
            }

            parent_sch_obj = &parent_port;
        } else {
            status = SAI_STATUS_INVALID_OBJECT_TYPE;
            SX_LOG_ERR("Invalid object type %u - can be port or scheduler group\n", parent_type);
            goto out;
        }

        status = sai_obj_to_sched_obj(port, &sch_child, child_id);
        if (SAI_ERR(status)) {
            goto out;
        }

        if (parent_sch_obj->type != MLNX_SCHED_OBJ_PORT) {
            if ((sch_child.type == MLNX_SCHED_OBJ_GROUP) && (sch_child.level != parent_level + 1)) {
                SX_LOG_ERR("Child level %u must equal to group level %u + 1\n", sch_child.level, parent_level);
                status = SAI_STATUS_INVALID_PARAMETER;
                goto out;
            }
        }
    } else { /* DEL */
        status = mlnx_sched_group_parse_id(child_id, &port_id, &parent_level, &parent_index);
        if (SAI_ERR(status)) {
            return status;
        }

        status = mlnx_port_by_log_id(port_id, &port);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = sai_obj_to_sched_obj(port, &sch_child, child_id);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    SX_LOG_NTC("%s child group %" PRIx64 " to group %" PRIx64 "\n",
               cmd == LIST_CMD_ADD ? "Adding" : "Deleting", child_id, parent_id);

    sch_child.next_index = (cmd == LIST_CMD_ADD) ? parent_index : INVALID_INDEX;

    if (sch_child.type == MLNX_SCHED_OBJ_QUEUE) {
        /* If created levels count < MAX_SCHED_LEVELS then we need re-apply scheduler parameters
         * for queue to the lower level (sub-group) */

        /* 1. Un-bind scheduler parameters from current ETS hierarchy level */
        SX_LOG_DBG("Un-bind scheulder parameters for queue index %u on ETS hierarchy %u\n",
                   sch_child.index, sch_child.ets_type);

        status = __mlnx_scheduler_to_queue_apply(SAI_NULL_OBJECT_ID, port_id, &sch_child);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to un-bind scheduler parameters for queue index %u\n", sch_child.index);
            goto out;
        }

        /* 2. Apply new ETS hierarchy level */
        if (port->sched_hierarchy.groups_count[MAX_SCHED_LEVELS - 1] == 0) {
            sch_child.ets_type = SX_COS_ETS_HIERARCHY_SUB_GROUP_E;
        } else {
            sch_child.ets_type = SX_COS_ETS_HIERARCHY_TC_E;
        }
        if (cmd == LIST_CMD_ADD) {
            sch_child.level = parent_level + 1;
        } else {
            sch_child.level    = MAX_SCHED_LEVELS;
            sch_child.ets_type = SX_COS_ETS_HIERARCHY_TC_E;
        }

        /* 3. Apply scheduler parameters to new ETS hierarchy level */
        SX_LOG_DBG("Re-bind scheulder parameters for queue index %u on ETS hierarchy %u\n",
                   sch_child.index, sch_child.ets_type);

        status = __mlnx_scheduler_to_queue_apply(sch_child.scheduler_id, port_id, &sch_child);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed to re-bind scheduler parameters for queue index %u\n", sch_child.index);
            goto out;
        }
    }

    sch_child.parent_id = parent_id;

    status = mlnx_sched_objlist_to_ets_update(port_id, &sch_child, 1);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_sched_objlist_to_hierarchy_update(port, &sch_child, 1);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to update sched group hierarchy on log port id 0x%x\n",
                   port->logical);
        goto out;
    }

out:
    return status;
}

sai_status_t mlnx_scheduler_group_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_cos_log_verbosity_level_set(gh_sdk,
                                                             SX_LOG_VERBOSITY_BOTH, level, level));
    }

    return SAI_STATUS_SUCCESS;
}

/* DB read lock is needed */
sai_status_t mlnx_sched_group_port_init(mlnx_port_config_t *port)
{
    sx_cos_ets_element_config_t *ets_list = NULL, *ets;
    uint32_t                     level, ii;
    mlnx_qos_queue_config_t     *queue;
    sai_status_t                 status;

    status = ets_list_load(port->logical, &ets_list);
    if (SAI_ERR(status)) {
        return status;
    }

    for (level = 0; level < MAX_SCHED_LEVELS; level++) {
        for (ii = 0; ii < level_max_groups(level); ii++) {
            mlnx_sched_obj_t *obj = group_get(port, level, ii);

            obj->index           = ii;
            obj->level           = level;
            obj->is_used         = true;
            obj->next_index      = 0;
            obj->type            = MLNX_SCHED_OBJ_GROUP;
            obj->max_child_count = level_max_childs(level);
            obj->ets_type        = level + 1;

            if (level > 0) {
                status = mlnx_create_sched_group(port->logical, level - 1, obj->next_index, &obj->parent_id);
                if (SAI_ERR(status)) {
                    SX_LOG_ERR("Failed create of parent oid\n");
                    return status;
                }
            } else {
                obj->parent_id = port->saiport;
            }

            status = ets_lookup(ets_list, obj, &ets);
            if (SAI_ERR(status)) {
                goto out;
            }

            status = sx_api_cos_port_ets_element_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                                     port->logical,
                                                     sched_obj_to_ets(obj, ets),
                                                     1);

            status = sdk_to_sai(status);
            if (SAI_ERR(status)) {
                goto out;
            }

            port->sched_hierarchy.groups_count[level]++;
        }
    }

    port_queues_foreach(port, queue, ii) {
        queue->sched_obj.next_index = ii % MAX_SCHED_CHILD_GROUPS;
        queue->sched_obj.type       = MLNX_SCHED_OBJ_QUEUE;
        queue->sched_obj.index      = ii;
        queue->sched_obj.ets_type   = SX_COS_ETS_HIERARCHY_TC_E;
        queue->sched_obj.is_used    = true;
        queue->sched_obj.level      = MAX_SCHED_LEVELS;

        status = mlnx_create_sched_group(port->logical,
                                         queue->sched_obj.level - 1,
                                         queue->sched_obj.next_index,
                                         &queue->sched_obj.parent_id);
        if (SAI_ERR(status)) {
            SX_LOG_ERR("Failed create parent oid for queue\n");
            return status;
        }

        status = ets_lookup(ets_list, &queue->sched_obj, &ets);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = sx_api_cos_port_ets_element_set(gh_sdk, SX_ACCESS_CMD_EDIT,
                                                 port->logical,
                                                 sched_obj_to_ets(&queue->sched_obj, ets),
                                                 1);

        status = sdk_to_sai(status);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

out:
    if (ets_list) {
        free(ets_list);
    }
    port->sched_hierarchy.is_default = true;
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief  Scheduler methods table retrieved with sai_api_query()
 */
const sai_scheduler_group_api_t mlnx_scheduler_group_api = {
    mlnx_create_scheduler_group,
    mlnx_remove_scheduler_group,
    mlnx_set_scheduler_group_attribute,
    mlnx_get_scheduler_group_attribute,
};
