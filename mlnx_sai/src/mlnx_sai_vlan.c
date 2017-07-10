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

#undef  __MODULE__
#define __MODULE__ SAI_VLAN

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static sai_status_t mlnx_vlan_id_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);

sai_status_t sai_object_to_vlan(sai_object_id_t oid, uint16_t *vlan_id)
{
    mlnx_object_id_t vlan_obj_id;
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_VLAN, oid, &vlan_obj_id);
    if (SAI_ERR(status)) {
        return status;
    }
    if (vlan_obj_id.object_type != SAI_OBJECT_TYPE_VLAN) {
        SX_LOG_ERR("Invalid object type %u - must be %u\n",
                   vlan_obj_id.object_type, SAI_OBJECT_TYPE_VLAN);

        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    *vlan_id = vlan_obj_id.id.vlan_id;
    return SAI_STATUS_SUCCESS;
}

sai_status_t validate_vlan(_In_ const sai_vlan_id_t vlan_id)
{
    SX_LOG_ENTER();

    if (!SXD_VID_CHECK_RANGE(vlan_id)) {
        SX_LOG_ERR("Invalid VLAN number: should be within a range [%u - %u]\n",
                   SXD_VID_MIN, SXD_VID_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
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
/** STP Instance that the VLAN is associated to [sai_object_id_t] **/
static sai_status_t mlnx_vlan_stp_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
static sai_status_t mlnx_vlan_stp_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg);
static const sai_vendor_attribute_entry_t vlan_vendor_attribs[] = {
    { SAI_VLAN_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_id_get, NULL,
      NULL, NULL },
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
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_stp_get, NULL,
      mlnx_vlan_stp_set, NULL },
    { SAI_VLAN_ATTR_LEARN_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_learn_get, NULL,
      mlnx_vlan_learn_set, NULL },
    { SAI_VLAN_ATTR_INGRESS_ACL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN },
    { SAI_VLAN_ATTR_EGRESS_ACL,
      { false, false, false, false },
      { false, false, false, false },
      mlnx_acl_bind_point_get, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN,
      mlnx_acl_bind_point_set, (void*)MLNX_ACL_BIND_POINT_TYPE_EGRESS_VLAN },
    { SAI_VLAN_ATTR_META_DATA,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static const sai_vendor_attribute_entry_t vlan_member_vendor_attribs[] = {
    { SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_VLAN_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_vlan_member_attrib_get, (void*)SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID,
      NULL, NULL },
    { SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_vlan_member_tagging_get, NULL,
      mlnx_vlan_member_tagging_set, NULL },
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};
static void vlan_key_to_str(_In_ sai_vlan_id_t vlan_id, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "vlan %u", vlan_id);
}

/**
 * @brief Vlan Id
 *
 * @type sai_uint16_t
 * @flags MANDATORY_ON_CREATE | CREATE_ONLY | KEY
 */
static sai_status_t mlnx_vlan_id_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    uint16_t     vlan_id;
    sai_status_t status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    value->u16 = vlan_id;

out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_member_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    uint8_t             extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t    *port_list = NULL;
    uint32_t            ports_cnt = 0;
    uint16_t            vlan_id;
    sx_status_t         status = SAI_STATUS_SUCCESS;
    mlnx_bridge_port_t *port;
    uint32_t            ii;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_read_lock();

    mlnx_vlan_ports_foreach(vlan_id, port, ii) {
        ports_cnt++;
    }

    if (!ports_cnt) {
        value->objlist.count = 0;
        goto out;
    }

    port_list = (sai_object_id_t*)malloc(sizeof(sai_object_id_t) * ports_cnt);
    if (!port_list) {
        SX_LOG_ERR("Can't allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    memset(extended_data, 0, sizeof(extended_data));
    extended_data[0] = vlan_id & 0xff;
    extended_data[1] = vlan_id >> 8;

    ports_cnt = 0;
    mlnx_vlan_ports_foreach(vlan_id, port, ii) {
        status = mlnx_create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, port->logical, extended_data,
                                    &port_list[ports_cnt++]);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_fill_objlist(port_list, ports_cnt, &value->objlist);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    free(port_list);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_vlan_learn_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    uint16_t            vlan_id;
    sx_status_t         status;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

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
    uint16_t            vlan_id;
    sx_status_t         status;
    sx_fdb_learn_mode_t mode;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

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

/* STP id getter */
static sai_status_t mlnx_vlan_stp_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sx_mstp_inst_id_t sx_stp_id;
    uint16_t          vlan_id;
    sai_status_t      status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Get STP by VLAN id */
    sai_db_read_lock();
    sx_stp_id = mlnx_vlan_stp_id_get(vlan_id);
    sai_db_unlock();

    /* Return STP id */
    status = mlnx_create_object(SAI_OBJECT_TYPE_STP, sx_stp_id,
                                NULL, &value->oid);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* STP id setter */
static sai_status_t mlnx_vlan_stp_set(_In_ const sai_object_key_t      *key,
                                      _In_ const sai_attribute_value_t *value,
                                      void                             *arg)
{
    sai_object_id_t   sai_stp_id = value->oid;
    sx_mstp_inst_id_t sx_stp_id;
    uint16_t          vlan_id;
    sai_status_t      status;
    uint32_t          data;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(key->key.object_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* Get new STP id */
    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get STP id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    /* validate STP id */
    if (!SX_MSTP_INST_ID_CHECK_RANGE(sx_stp_id)) {
        SX_LOG_ERR("Invalid STP id: should be within a range [%u - %u]\n",
                   SX_MSTP_INST_ID_MIN, SX_MSTP_INST_ID_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Remove VLAN from its' current STP */
    assert(NULL != g_sai_db_ptr);
    sai_db_write_lock();

    status = mlnx_vlan_stp_unbind(vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unmap VLAN [%u] from its' STP\n", vlan_id);
        goto out;
    }

    /* Bind VLAN to the new STP */
    status = mlnx_vlan_stp_bind(vlan_id, sx_stp_id);
    if (SAI_ERR(status)) {
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
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
static sai_status_t mlnx_set_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];
    uint16_t               vid;
    sai_status_t           status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(vlan_id, &vid);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_key_to_str(vid, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs, attr);
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
static sai_status_t mlnx_get_vlan_attribute(_In_ sai_object_id_t     vlan_id,
                                            _In_ uint32_t            attr_count,
                                            _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .key.object_id = vlan_id };
    char                   key_str[MAX_KEY_STR_LEN];
    uint16_t               vid;
    sai_status_t           status;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(vlan_id, &vid);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan_key_to_str(vid, key_str);
    return sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Create a VLAN
 *
 * @param[out] vlan_id VLAN ID
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
sai_status_t mlnx_create_vlan(_Out_ sai_object_id_t      *sai_vlan_id,
                              _In_ sai_object_id_t        switch_id,
                              _In_ uint32_t               attr_count,
                              _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    const sai_attribute_value_t *vid = NULL, *stp = NULL, *learn = NULL;
    uint32_t                     vid_index, stp_index, learn_index;
    sx_mstp_inst_id_t            sx_stp_id = mlnx_stp_get_default_stp();
    mlnx_object_id_t             stp_obj_id;
    mlnx_object_id_t             vlan_obj_id;
    sai_object_id_t              vlan_oid;
    sai_status_t                 status;
    const sai_attribute_value_t *attr_ing_acl  = NULL;
    acl_index_t                  ing_acl_index = ACL_INDEX_INVALID;
    uint32_t                     ing_acl_attr_index;

    SX_LOG_ENTER();

    status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN, vlan_vendor_attribs,
                                    SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create VLAN, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_VLAN_ID, &vid, &vid_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = validate_vlan(vid->u16);
    if (SAI_ERR(status)) {
        return status;
    }

    memset(&vlan_obj_id, 0, sizeof(vlan_obj_id));
    vlan_obj_id.id.vlan_id = vid->u16;

    status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, &vlan_oid);
    if (SAI_ERR(status)) {
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_STP_INSTANCE, &stp, &stp_index);
    if (stp) {
        status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_STP, stp->oid, &stp_obj_id);
        if (SAI_ERR(status)) {
            return status;
        }
        sx_stp_id = stp_obj_id.id.stp_inst_id;
    }

    /* no need to call SDK */

    assert(NULL != g_sai_db_ptr);
    sai_db_write_lock();
    acl_global_lock();

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_INGRESS_ACL, &attr_ing_acl, &ing_acl_attr_index);
    if (status == SAI_STATUS_SUCCESS) {
        status = mlnx_acl_bind_point_attrs_check_and_fetch(attr_ing_acl->oid, MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN,
                                                           ing_acl_attr_index, &ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }

        status = mlnx_acl_vlan_bind_point_set(vlan_oid, MLNX_ACL_BIND_POINT_TYPE_INGRESS_VLAN, ing_acl_index);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status = mlnx_vlan_stp_bind(vid->u16, sx_stp_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    if (SAI_STATUS_SUCCESS ==
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_VLAN_ATTR_LEARN_DISABLE, &learn, &learn_index))) {
        sai_object_key_t key = { .key.object_id = vlan_oid };

        status = mlnx_vlan_learn_set(&key, learn, NULL);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    status       = SAI_STATUS_SUCCESS;
    *sai_vlan_id = vlan_oid;
    SX_LOG_NTC("Created vlan oid %" PRIx64 "\n", vlan_oid);

out:
    acl_global_unlock();
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
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
static sai_status_t mlnx_remove_vlan(_In_ sai_object_id_t sai_vlan_id)
{
    char                key_str[MAX_KEY_STR_LEN];
    mlnx_bridge_port_t *port;
    uint16_t            vlan_id;
    sai_status_t        status;
    uint32_t            port_idx;

    SX_LOG_ENTER();

    status = sai_object_to_vlan(sai_vlan_id, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    /* check if specified VLAN does exist */
    status = validate_vlan(vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    sai_db_write_lock();

    mlnx_vlan_ports_foreach(vlan_id, port, port_idx) {
        SX_LOG_ERR("Failed to remove vlan which has vlan members\n");
        status = SAI_STATUS_OBJECT_IN_USE;
        goto out;
    }

    vlan_key_to_str(vlan_id, key_str);
    SX_LOG_NTC("Remove %s\n", key_str);

    /* no need to call SDK */

    status = mlnx_acl_vlan_bind_point_clear(sai_vlan_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_stp_unbind(vlan_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to unmap VLAN [%u] from STP\n", vlan_id);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Get vlan statistics counters.
 *
 * @param[in] vlan_id VLAN id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_vlan_stats(_In_ sai_object_id_t        sai_vlan_id,
                                        _In_ uint32_t               number_of_counters,
                                        _In_ const sai_vlan_stat_t *counter_ids,
                                        _Out_ uint64_t             *counters)
{
    UNREFERENCED_PARAMETER(sai_vlan_id);
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
 * @brief Clear vlan statistics counters.
 *
 * @param[in] vlan_id Vlan id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_clear_vlan_stats(_In_ sai_object_id_t        sai_vlan_id,
                                          _In_ uint32_t               number_of_counters,
                                          _In_ const sai_vlan_stat_t *counter_ids)
{
    UNREFERENCED_PARAMETER(sai_vlan_id);
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

bool mlnx_vlan_port_is_set(uint16_t vid, mlnx_bridge_port_t *port)
{
    return array_bit_test(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
}

void mlnx_vlan_port_set(uint16_t vid, mlnx_bridge_port_t *port, bool is_set)
{
    assert(port->index < MAX_PORTS * 2);

    if (is_set && !mlnx_vlan_port_is_set(vid, port)) {
        array_bit_set(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        mlnx_fdb_port_event_handle(port, vid, SAI_PORT_EVENT_ADD);
        port->vlans++;
    } else if (!is_set && mlnx_vlan_port_is_set(vid, port)) {
        array_bit_clear(g_sai_db_ptr->vlans_db[vid - 1].ports_map, port->index);
        mlnx_fdb_port_event_handle(port, vid, SAI_PORT_EVENT_DELETE);
        port->vlans--;
    }
}

sai_status_t mlnx_vlan_port_add(uint16_t vid, sai_vlan_tagging_mode_t mode, mlnx_bridge_port_t *port)
{
    sx_vlan_ports_t vlan_port_list;
    sx_status_t     sx_status;

    memset(&vlan_port_list, 0, sizeof(vlan_port_list));

    vlan_port_list.log_port = port->logical;

    switch (mode) {
    case SAI_VLAN_TAGGING_MODE_UNTAGGED:
        vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
        break;

    case SAI_VLAN_TAGGING_MODE_TAGGED:
        vlan_port_list.is_untagged = SX_TAGGED_MEMBER;
        break;

    case SAI_VLAN_TAGGING_MODE_PRIORITY_TAGGED:
        SX_LOG_ERR("Vlan port priority tagged not supported\n");
        return SAI_STATUS_NOT_SUPPORTED;

    default:
        SX_LOG_ERR("Invalid tagging mode %d\n", mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, vid, &vlan_port_list, 1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    mlnx_vlan_port_set(vid, port, true);
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_port_del(uint16_t vid, mlnx_bridge_port_t *port)
{
    sx_vlan_ports_t port_list;
    sx_status_t     sx_status;

    memset(&port_list, 0, sizeof(port_list));

    port_list.log_port = port->logical;

    if (!mlnx_vlan_port_is_set(vid, port)) {
        return SAI_STATUS_SUCCESS;
    }

    sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, vid, &port_list, 1);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to add vlan ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    mlnx_vlan_port_set(vid, port, false);
    return SAI_STATUS_SUCCESS;
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
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    const sai_attribute_value_t *vid = NULL, *port = NULL, *tagging = NULL;
    uint32_t                     vid_index, port_index, tagging_index;
    sai_vlan_tagging_mode_t      mode = SAI_VLAN_TAGGING_MODE_UNTAGGED;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    sx_port_log_id_t             log_port;
    mlnx_bridge_port_t          *port_cfg;
    uint16_t                     vlan_id;
    sai_status_t                 status;

    SX_LOG_ENTER();

    memset(extended_data, 0, sizeof(extended_data));

    if (NULL == vlan_member_id) {
        SX_LOG_ERR("NULL vlan member ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_VLAN_MEMBER, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create vlan member, %s\n", list_str);

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_VLAN_ID, &vid, &vid_index);
    assert(SAI_STATUS_SUCCESS == status);
    status = sai_object_to_vlan(vid->oid, &vlan_id);
    if (SAI_ERR(status)) {
        return status;
    }

    status = find_attrib_in_list(attr_count, attr_list, SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, &port, &port_index);
    assert(SAI_STATUS_SUCCESS == status);

    status = mlnx_bridge_port_sai_to_log_port(port->oid, &log_port);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to convert bridge port %" PRIx64 " to log port\n", port->oid);
        return status;
    }

    /* skip CPU port, which doesn't need to be added/removed to vlan */
    if (CPU_PORT == log_port) {
        SX_LOG_NTC("add port to vlan %u - Skip CPU port\n", vlan_id);
        return SAI_STATUS_SUCCESS;
    }

    status = find_attrib_in_list(attr_count,
                                 attr_list,
                                 SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
                                 &tagging,
                                 &tagging_index);
    if (!SAI_ERR(status)) {
        mode = tagging->s32;
    }

    sai_db_write_lock();

    status = mlnx_bridge_port_by_log(log_port, &port_cfg);
    if (SAI_ERR(status)) {
        goto out;
    }

    status = mlnx_vlan_port_add(vlan_id, mode, port_cfg);
    if (SAI_ERR(status)) {
        goto out;
    }

    extended_data[0] = vlan_id & 0xff;
    extended_data[1] = vlan_id >> 8;

    status = mlnx_create_object(SAI_OBJECT_TYPE_VLAN_MEMBER, port_cfg->logical, extended_data, vlan_member_id);
    if (SAI_ERR(status)) {
        goto out;
    }

    vlan_member_key_to_str(*vlan_member_id, key_str);
    SX_LOG_NTC("Created vlan member %s\n", key_str);

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
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
    mlnx_bridge_port_t *port;
    uint16_t            vlan;

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    SX_LOG_NTC("Remove vlan member interface %s\n", key_str);

    status = mlnx_object_to_type(vlan_member_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data);
    if (SAI_ERR(status)) {
        return status;
    }

    vlan = ((uint16_t)extended_data[1]) << 8 | extended_data[0];
    if (!SXD_VID_CHECK_RANGE(vlan)) {
        SX_LOG_ERR("Invalid vlan id %u\n", vlan);
        return SAI_STATUS_INVALID_VLAN_ID;
    }

    /* skip CPU port, which doesn't need to be added/removed to vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("Remove port from vlan %u - Skip CPU port\n", vlan);
        return SAI_STATUS_SUCCESS;
    }

    sai_db_write_lock();

    status = mlnx_bridge_port_by_log(port_data, &port);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

    if (!mlnx_vlan_port_is_set(vlan, port)) {
        SX_LOG_ERR("Vlan member does not exist for this vlan %u and bridge port %x\n",
                   vlan, port->logical);

        status = SAI_STATUS_INVALID_OBJECT_ID;
        goto out_unlock;
    }

    status = mlnx_vlan_port_del(vlan, port);
    if (SAI_ERR(status)) {
        goto out_unlock;
    }

out_unlock:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Bulk vlan members creation.
 *
 * @param[in] switch_id SAI Switch object id
 * @param[in] object_count Number of objects to create
 * @param[in] attr_count List of attr_count. Caller passes the number
 *         of attribute for each object to create.
 * @param[in] attrs List of attributes for every object.
 * @param[in] type bulk operation type.
 *
 * @param[out] object_id List of object ids returned
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are created or #SAI_STATUS_FAILURE when
 * any of the objects fails to create. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_create_vlan_members(_In_ sai_object_id_t         switch_id,
                                      _In_ uint32_t                object_count,
                                      _In_ const uint32_t         *attr_count,
                                      _In_ const sai_attribute_t **attrs,
                                      _In_ sai_bulk_op_type_t      type,
                                      _Out_ sai_object_id_t       *object_id,
                                      _Out_ sai_status_t          *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Bulk vlan members removal.
 *
 * @param[in] object_count Number of objects to create
 * @param[in] object_id List of object ids
 * @param[in] type bulk operation type.
 * @param[out] object_statuses List of status for every object. Caller needs to allocate the buffer.
 *
 * @return #SAI_STATUS_SUCCESS on success when all objects are removed or #SAI_STATUS_FAILURE when
 * any of the objects fails to remove. When there is failure, Caller is expected to go through the
 * list of returned statuses to find out which fails and which succeeds.
 */
sai_status_t mlnx_remove_vlan_members(_In_ uint32_t               object_count,
                                      _In_ const sai_object_id_t *object_id,
                                      _In_ sai_bulk_op_type_t     type,
                                      _Out_ sai_status_t         *object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
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
    const sai_object_key_t key = { .key.object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_vendor_attribs, attr);
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
    const sai_object_key_t key = { .key.object_id = vlan_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    vlan_member_key_to_str(vlan_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              SAI_OBJECT_TYPE_VLAN_MEMBER,
                              vlan_member_vendor_attribs,
                              attr_count,
                              attr_list);
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
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    mlnx_object_id_t vlan_obj_id;
    uint32_t         port_data;
    sx_status_t      status;

    SX_LOG_ENTER();

    memset(&vlan_obj_id, 0, sizeof(vlan_obj_id));

    assert((SAI_VLAN_MEMBER_ATTR_VLAN_ID == (long)arg) ||
           (SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID == (long)arg));

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }

    switch ((long)arg) {
    case SAI_VLAN_MEMBER_ATTR_VLAN_ID:
        vlan_obj_id.id.vlan_id = ((uint16_t)extended_data[1]) << 8 | extended_data[0];

        status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_VLAN, &vlan_obj_id, &value->oid);
        if (SAI_ERR(status)) {
            return status;
        }
        break;

    case SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID:
        status = mlnx_log_port_to_sai_bridge_port(port_data, &value->oid);
        if (SAI_ERR(status)) {
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
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
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
    case SAI_VLAN_TAGGING_MODE_UNTAGGED:
        sx_vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
        break;

    case SAI_VLAN_TAGGING_MODE_TAGGED:
        sx_vlan_port_list.is_untagged = SX_TAGGED_MEMBER;
        break;

    case SAI_VLAN_TAGGING_MODE_PRIORITY_TAGGED:
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
        (status = mlnx_object_to_type(key->key.object_id, SAI_OBJECT_TYPE_VLAN_MEMBER, &port_data, extended_data))) {
        return status;
    }
    vlan = ((uint16_t)extended_data[1]) << 8 | extended_data[0];

    /* skip CPU port, which isn't actual member of vlan */
    if (CPU_PORT == port_data) {
        SX_LOG_NTC("get tagging vlan %u - Skip CPU port\n", vlan);
        value->s32 = SAI_VLAN_TAGGING_MODE_UNTAGGED;
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
                value->s32 = SAI_VLAN_TAGGING_MODE_UNTAGGED;
            } else {
                value->s32 = SAI_VLAN_TAGGING_MODE_TAGGED;
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

sai_status_t mlnx_vlan_stp_bind(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id)
{
    sx_status_t       status;
    mlnx_mstp_inst_t *stp_db_entry;

    SX_LOG_ENTER();

    /*
     * Set VLANs to STP instance through SDK,
     * so later we can get VLANs by STP.
     */
    SX_LOG_NTC("Map VLAN [%u] to STP [%u]\n", vlan_id, sx_stp_id);
    status = sx_api_mstp_inst_vlan_list_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                            sx_stp_id, &vlan_id, 1);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to set STP to vlan %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* Write a pair VLAN:STP into database (so later we can get STP by VLAN)*/
    mlnx_vlan_stp_id_set(vlan_id, sx_stp_id);

    /* Increment VLAN counter for that STP id */
    stp_db_entry = get_stp_db_entry(sx_stp_id);
    (stp_db_entry->vlan_count)++;

    SX_LOG_DBG("Increment VLAN count(to %u) for STP=%u\n", stp_db_entry->vlan_count, sx_stp_id);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_vlan_stp_unbind(sai_vlan_id_t vlan_id)
{
    sx_status_t       status;
    sx_mstp_inst_id_t sx_stp_id_curr;
    mlnx_mstp_inst_t *stp_db_entry;

    SX_LOG_ENTER();

    /* Remove map through SDK */
    sx_stp_id_curr = mlnx_vlan_stp_id_get(vlan_id);
    SX_LOG_NTC("Unmapping VLAN [%u] from STP [%u]\n", vlan_id, sx_stp_id_curr);
    status = sx_api_mstp_inst_vlan_list_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                            sx_stp_id_curr, &vlan_id, 1);
    if (SX_ERR(status)) {
        SX_LOG_ERR("Failed to unmap VLAN [%u] from STP [%u]\n", vlan_id, sx_stp_id_curr);
        return sdk_to_sai(status);
    }

    SX_LOG_DBG("Passed an SDK api (vlan_list_set)\n");
    /* Remove map VLAN:STP from database */
    mlnx_vlan_stp_id_set(vlan_id, SAI_INVALID_STP_INSTANCE);

    /* Decrement VLAN counter for that STP id */
    stp_db_entry = get_stp_db_entry(sx_stp_id_curr);
    if (stp_db_entry->vlan_count != 0) {
        (stp_db_entry->vlan_count)--;
    }
    SX_LOG_DBG("Decrement VLAN count (to %u) for STP=%u\n",
               stp_db_entry->vlan_count, sx_stp_id_curr);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sx_mstp_inst_id_t mlnx_vlan_stp_id_get(sai_vlan_id_t vlan_id)
{
    return (g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].stp_id);
}

void mlnx_vlan_stp_id_set(sai_vlan_id_t vlan_id, sx_mstp_inst_id_t sx_stp_id)
{
    g_sai_db_ptr->vlans_db[vlan_id - SXD_VID_MIN].stp_id = sx_stp_id;
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
    mlnx_create_vlan_members,
    mlnx_remove_vlan_members,
    mlnx_get_vlan_stats,
    mlnx_clear_vlan_stats
};
