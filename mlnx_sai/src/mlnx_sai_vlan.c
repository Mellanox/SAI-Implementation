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

#undef  __MODULE__
#define __MODULE__ SAI_VLAN

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
static sai_status_t check_attrs_port_type(_In_ const sai_object_key_t *key,
                                          _In_ uint32_t                count,
                                          _In_ const sai_attribute_t  *attrs)
{
    uint32_t ii;

    sai_db_read_lock();
    for (ii = 0; ii < count; ii++) {
        const sai_attribute_t *attr  = &attrs[ii];
        attr_port_type_check_t check = ATTR_PORT_IS_LAG_ENABLED;

        if (attr->id == SAI_VLAN_MEMBER_ATTR_PORT_ID) {
            sai_status_t status;

            status = check_port_type_attr(&attr->value.oid, 1, check, attr->id, ii);

            sai_db_unlock();
            return status;
        }
    }
    sai_db_unlock();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_learn_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_vlan_learn_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t mlnx_vlan_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_vlan_member_tagging_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t mlnx_vlan_member_tagging_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static const sai_attribute_entry_t        vlan_attribs[] = {
    { SAI_VLAN_ATTR_MEMBER_LIST, false, false, false, true,
      "Vlan member list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES, false, false, true, true,
      "Vlan Maximum number of learned MAC addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_VLAN_ATTR_STP_INSTANCE, false, false, true, true,
      "Vlan associated STP instance", SAI_ATTR_VAL_TYPE_U64 },
    { SAI_VLAN_ATTR_LEARN_DISABLE, false, false, true, true,
      "Vlan learn disable", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_VLAN_ATTR_META_DATA, false, false, true, true,
      "Vlan meta data", SAI_ATTR_VAL_TYPE_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t vlan_vendor_attribs[] = {
    { SAI_VLAN_ATTR_MEMBER_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_vlan_member_list_get, NULL,
      NULL, NULL },
    { SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_VLAN_ATTR_STP_INSTANCE,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_VLAN_ATTR_LEARN_DISABLE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_vlan_learn_get, NULL,
      mlnx_vlan_learn_set, NULL },
    { SAI_VLAN_ATTR_META_DATA,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
};
static const sai_attribute_entry_t        vlan_member_attribs[] = {
    { SAI_VLAN_MEMBER_ATTR_VLAN_ID, true, true, false, true,
      "Vlan member VID", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_VLAN_MEMBER_ATTR_PORT_ID, true, true, false, true,
      "Vlan member port", SAI_ATTR_VAL_TYPE_OID },
    { SAI_VLAN_MEMBER_ATTR_TAGGING_MODE, false, true, true, true,
      "Vlan member tagging mode", SAI_ATTR_VAL_TYPE_S32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t vlan_member_vendor_attribs[] = {
    { SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_PORT_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_TAGGING_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_member_tagging_get, NULL,
      mlnx_vlan_member_tagging_set, NULL },
};
static void vlan_key_to_str(_In_ sai_vlan_id_t vlan_id, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "vlan %u", vlan_id);
}

static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sx_status_t         status;
    sx_vlan_ports_t    *sx_vlan_port_list  = NULL;
    sai_object_id_t    *sai_vlan_port_list = NULL;
    const sai_vlan_id_t vlan_id            = key->vlan_id;
    uint32_t            port_cnt           = g_resource_limits.port_ext_num_max;
    uint32_t            ii;
    uint8_t             extended_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    sx_vlan_port_list  = (sx_vlan_ports_t*)malloc(sizeof(sx_vlan_ports_t) * port_cnt);
    sai_vlan_port_list = (sai_object_id_t*)malloc(sizeof(sai_object_id_t) * port_cnt);
    if ((NULL == sx_vlan_port_list) || (NULL == sai_vlan_port_list)) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_vlan_ports_get(gh_sdk, DEFAULT_ETH_SWID, vlan_id, sx_vlan_port_list, &port_cnt))) {
        SX_LOG_ERR("Failed to get vlan ports %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    memset(extended_data, 0, sizeof(extended_data));
    extended_data[0] = vlan_id & 0xff;
    extended_data[1] = vlan_id >> 8;

    for (ii = 0; ii < port_cnt; ii++) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 mlnx_create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, sx_vlan_port_list[ii].log_port, extended_data,
                                    &sai_vlan_port_list[ii]))) {
            goto out;
        }
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_fill_objlist(sai_vlan_port_list, port_cnt, &value->objlist))) {
        goto out;
    }

out:
    if (sx_vlan_port_list) {
        free(sx_vlan_port_list);
    }
    if (sai_vlan_port_list) {
        free(sai_vlan_port_list);
    }
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_learn_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sx_status_t         status;
    const sai_vlan_id_t vlan_id = key->vlan_id;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_fid_learn_mode_get(gh_sdk, DEFAULT_ETH_SWID, vlan_id, &mode))) {
        SX_LOG_ERR("Failed to get learn mode %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (SX_FDB_LEARN_MODE_DONT_LEARN == mode) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

out:
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_learn_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sx_status_t         status;
    const sai_vlan_id_t vlan_id = key->vlan_id;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    if (value->booldata) {
        mode = SX_FDB_LEARN_MODE_DONT_LEARN;
    } else {
        mode = SX_FDB_LEARN_MODE_AUTO_LEARN;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_fid_learn_mode_set(gh_sdk, DEFAULT_ETH_SWID, vlan_id, mode))) {
        SX_LOG_ERR("Failed to set learn mode %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

out:
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_vlan_attribute(_In_ sai_vlan_id_t vlan_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .vlan_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_key_to_str(vlan_id, key_str);
    return sai_set_attribute(&key, key_str, vlan_attribs, vlan_vendor_attribs, attr);
}


/*
 * Routine Description:
 *    Get VLAN attribute Value
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_vlan_attribute(_In_ sai_vlan_id_t       vlan_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .vlan_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_key_to_str(vlan_id, key_str);
    return sai_get_attributes(&key, key_str, vlan_attribs, vlan_vendor_attribs, attr_count, attr_list);
}


/*
 * Routine Description:
 *    Create a VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_vlan(_In_ sai_vlan_id_t vlan_id)
{
    char key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_key_to_str(vlan_id, key_str);
    SX_LOG_NTC("Create vlan %s\n", key_str);

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/*
 * Routine Description:
 *    Remove a VLAN
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_vlan(_In_ sai_vlan_id_t vlan_id)
{
    char key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_key_to_str(vlan_id, key_str);
    SX_LOG_NTC("Remove vlan %s\n", key_str);

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Get vlan statistics counters.
 *
 * Arguments:
 *    [in] vlan_id - VLAN id
 *    [in] counter_ids - specifies the array of counter ids
 *    [in] number_of_counters - number of counters in the array
 *    [out] counters - array of resulting counter values.
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_vlan_stats(_In_ sai_vlan_id_t                  vlan_id,
                                        _In_ const sai_vlan_stat_counter_t *counter_ids,
                                        _In_ uint32_t                       number_of_counters,
                                        _Out_ uint64_t                    * counters)
{
    UNREFERENCED_PARAMETER(vlan_id);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == counters) {
        SX_LOG_ERR("NULL counters array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * Routine Description:
 *   @brief Clear vlan statistics counters.
 *
 * Arguments:
 *    @param[in] vlan_id - vlan id
 *    @param[in] counter_ids - specifies the array of counter ids
 *    @param[in] number_of_counters - number of counters in the array
 *
 * Return Values:
 *    @return SAI_STATUS_SUCCESS on success
 *            Failure status code on error
 */
static sai_status_t mlnx_clear_vlan_stats(_In_ sai_vlan_id_t                  vlan_id,
                                          _In_ const sai_vlan_stat_counter_t *counter_ids,
                                          _In_ uint32_t                       number_of_counters)
{
    UNREFERENCED_PARAMETER(vlan_id);
    UNREFERENCED_PARAMETER(number_of_counters);

    SX_LOG_ENTER();

    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter ids array param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* TODO : implement */

    SX_LOG_EXIT();
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static void vlan_member_key_to_str(_In_ sai_object_id_t vlan_member_id, _Out_ char *key_str)
{
    uint32_t port;
    uint8_t  extended_data[EXTENDED_DATA_SIZE];
    uint16_t vlan;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(vlan_member_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port, extended_data)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid vlan member");
    } else {
        vlan = ((uint16_t)extended_data[1]) << 8 | extended_data[0];
        snprintf(key_str, MAX_KEY_STR_LEN, "Vlan member port %x vlan %u", port, vlan);
    }
}

/*
 *  \brief Create VLAN Member
 *  \param[out] vlan_member_id VLAN member ID
 *  \param[in] attr_count number of attributes
 *  \param[in] attr_list array of attributes
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_create_vlan_member(_Out_ sai_object_id_t     * vlan_member_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    sai_status_t                 status;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    const sai_attribute_value_t *vid, *port, *tagging;
    uint32_t                     vid_index, port_index, tagging_index, port_data;
    sx_vlan_ports_t              sx_vlan_port_list;
    mlnx_port_config_t          *port_cfg;

    SX_LOG_ENTER();

    memset(extended_data, 0, sizeof(extended_data));
    memset(&sx_vlan_port_list, 0, sizeof(sx_vlan_port_list));

    if (NULL == vlan_member_id) {
        SX_LOG_ERR("NULL vlan member ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, vlan_member_attribs, vlan_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    status = check_attrs_port_type(NULL, attr_count, attr_list);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, vlan_member_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create vlan member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_VLAN_ID, &vid, &vid_index);
    assert(SAI_STATUS_SUCCESS == status);
    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_PORT_ID, &port, &port_index);
    assert(SAI_STATUS_SUCCESS == status);

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_log_port(port->oid, &port_data))) {
        return status;
    }

    sx_vlan_port_list.log_port = port_data;

    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_TAGGING_MODE,
                                      &tagging, &tagging_index))) {
        switch (tagging->s32) {
        case SAI_VLAN_PORT_UNTAGGED:
            sx_vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
            break;

        case SAI_VLAN_PORT_TAGGED:
            sx_vlan_port_list.is_untagged = SX_TAGGED_MEMBER;
            break;

        case SAI_VLAN_PORT_PRIORITY_TAGGED:
            SX_LOG_ERR("Vlan port priority tagged not supported\n");
            return SAI_STATUS_NOT_SUPPORTED;

        default:
            SX_LOG_ERR("Invalid tagging mode %d\n", tagging->s32);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    } else {
        sx_vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
    }

    /* skip CPU port, which doesn't need to be added/removed to vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("add port to vlan %u - Skip CPU port\n", vid->u16);
    } else {
        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vid->u16, &sx_vlan_port_list,
                                       1))) {
            SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    extended_data[0] = vid->u16 & 0xff;
    extended_data[1] = vid->u16 >> 8;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, port_data, extended_data, vlan_member_id))) {
        return status;
    }
    vlan_member_key_to_str(*vlan_member_id, key_str);
    SX_LOG_NTC("Created vlan member %s\n", key_str);

    if (CPU_PORT != port_data) {
        sai_db_write_lock();
        status = mlnx_port_by_obj_id(port->oid, &port_cfg);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            return status;
        }
        port_cfg->vlans++;
        sai_db_unlock();
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  \brief Remove VLAN Member
 *  \param[in] vlan_member_id VLAN member ID
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_remove_vlan_member(_In_ sai_object_id_t vlan_member_id)
{
    char                key_str[MAX_KEY_STR_LEN];
    uint32_t            port_data;
    uint8_t             extended_data[EXTENDED_DATA_SIZE];
    sai_status_t        status;
    sx_vlan_ports_t     sx_vlan_port_list;
    uint16_t            vlan;
    mlnx_port_config_t *port_cfg;

    SX_LOG_ENTER();

    memset(&sx_vlan_port_list, 0, sizeof(sx_vlan_port_list));

    vlan_member_key_to_str(vlan_member_id, key_str);
    SX_LOG_NTC("Remove vlan member interface %s\n", key_str);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(vlan_member_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }

    sx_vlan_port_list.log_port = port_data;
    vlan                       = ((uint16_t)extended_data[1]) << 8 | extended_data[0];

    /* skip CPU port, which doesn't need to be added/removed to vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("remove port from vlan %u - Skip CPU port\n", vlan);
    } else {
        if (SX_STATUS_SUCCESS !=
            (status =
                 sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, vlan, &sx_vlan_port_list, 1))) {
            SX_LOG_ERR("Failed to delete vlan ports %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    if (CPU_PORT != port_data) {
        sai_db_write_lock();
        status = mlnx_port_by_log_id(port_data, &port_cfg);
        if (SAI_ERR(status)) {
            sai_db_unlock();
            return status;
        }
        port_cfg->vlans--;
        sai_db_unlock();
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  \brief Set VLAN Member Attribute
 *  \param[in] vlan_member_id VLAN member ID
 *  \param[in] attr attribute structure containing ID and value
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_set_vlan_member_attribute(_In_ sai_object_id_t        vlan_member_id,
                                                   _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    status = check_attrs_port_type(&key, 1, attr);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_set_attribute(&key, key_str, vlan_member_attribs, vlan_member_vendor_attribs, attr);
}

/*
 *  \brief Get VLAN Member Attribute
 *  \param[in] vlan_member_id VLAN member ID
 *  \param[in] attr_count number of attributes
 *  \param[in,out] attr_list list of attribute structures containing ID and value
 *  \return Success: SAI_STATUS_SUCCESS
 *  Failure: failure status code on error
 */
static sai_status_t mlnx_get_vlan_member_attribute(_In_ sai_object_id_t     vlan_member_id,
                                                   _In_ const uint32_t      attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_get_attributes(&key, key_str, vlan_member_attribs, vlan_member_vendor_attribs, attr_count, attr_list);
}

/* VLAN ID [sai_vlan_t] */
/* logical port ID [sai_object_id_t] */
/* VLAN tagging mode [sai_vlan_tagging_mode_t] */
static sai_status_t mlnx_vlan_member_attrib_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sx_status_t status;
    uint32_t    port_data;
    uint8_t     extended_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    assert((SAI_VLAN_MEMBER_ATTR_VLAN_ID == (long)arg) ||
           (SAI_VLAN_MEMBER_ATTR_PORT_ID == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }

    switch ((long)arg) {
    case SAI_VLAN_MEMBER_ATTR_VLAN_ID:
        value->u16 = ((uint16_t)extended_data[1]) << 8 | extended_data[0];
        break;

    case SAI_VLAN_MEMBER_ATTR_PORT_ID:
        if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT,
                                                               port_data, NULL, &value->oid))) {
            return status;
        }
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* VLAN tagging mode [sai_vlan_tagging_mode_t] */
static sai_status_t mlnx_vlan_member_tagging_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    uint32_t        port_data;
    uint8_t         extended_data[EXTENDED_DATA_SIZE];
    sai_status_t    status;
    sx_vlan_ports_t sx_vlan_port_list;
    uint16_t        vlan;

    SX_LOG_ENTER();

    memset(&sx_vlan_port_list, 0, sizeof(sx_vlan_port_list));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }

    sx_vlan_port_list.log_port = port_data;
    vlan                       = ((uint16_t)extended_data[1]) << 8 | extended_data[0];

    /* skip CPU port, which doesn't need to be added/removed to vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("set tagging vlan %u - Skip CPU port\n", vlan);
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    if (SX_STATUS_SUCCESS !=
        (status =
             sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, vlan, &sx_vlan_port_list, 1))) {
        SX_LOG_ERR("Failed to delete vlan ports %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    switch (value->s32) {
    case SAI_VLAN_PORT_UNTAGGED:
        sx_vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
        break;

    case SAI_VLAN_PORT_TAGGED:
        sx_vlan_port_list.is_untagged = SX_TAGGED_MEMBER;
        break;

    case SAI_VLAN_PORT_PRIORITY_TAGGED:
        SX_LOG_ERR("Vlan port priority tagged not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;

    default:
        SX_LOG_ERR("Invalid tagging mode %d\n", value->s32);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vlan, &sx_vlan_port_list, 1))) {
        SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_vlan_member_tagging_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sx_status_t      status;
    sx_vlan_ports_t *sx_vlan_port_list = NULL;
    uint32_t         port_cnt          = g_resource_limits.port_ext_num_max;
    uint32_t         ii;
    uint32_t         port_data;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    uint16_t         vlan;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }
    vlan = ((uint16_t)extended_data[1]) << 8 | extended_data[0];

    /* skip CPU port, which isn't actual member of vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("get tagging vlan %u - Skip CPU port\n", vlan);
        value->s32 = SAI_VLAN_PORT_UNTAGGED;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    sx_vlan_port_list = (sx_vlan_ports_t*)malloc(sizeof(sx_vlan_ports_t) * port_cnt);
    if (NULL == sx_vlan_port_list) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_vlan_ports_get(gh_sdk, DEFAULT_ETH_SWID, vlan, sx_vlan_port_list, &port_cnt))) {
        SX_LOG_ERR("Failed to get vlan ports %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    for (ii = 0; ii < port_cnt; ii++) {
        if (sx_vlan_port_list[ii].log_port == port_data) {
            if (sx_vlan_port_list[ii].is_untagged) {
                value->s32 = SAI_VLAN_PORT_UNTAGGED;
            } else {
                value->s32 = SAI_VLAN_PORT_TAGGED;
            }
            break;
        }
    }
    if (ii == port_cnt) {
        SX_LOG_ERR("Failed to find port %x in vlan %u, %u members\n", port_data, vlan, port_cnt);
        status = SAI_STATUS_FAILURE;
    }

out:
    if (sx_vlan_port_list) {
        free(sx_vlan_port_list);
    }
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_vlan_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_vlan_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_vlan_api_t mlnx_vlan_api = {
    mlnx_create_vlan,
    mlnx_remove_vlan,
    mlnx_set_vlan_attribute,
    mlnx_get_vlan_attribute,
    mlnx_create_vlan_member,
    mlnx_remove_vlan_member,
    mlnx_set_vlan_member_attribute,
    mlnx_get_vlan_member_attribute,
    mlnx_get_vlan_stats,
    mlnx_clear_vlan_stats
};
