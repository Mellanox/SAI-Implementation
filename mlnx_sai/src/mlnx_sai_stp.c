/*
 *  Copyright (C) 2014-2015. Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
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
#define __MODULE__ SAI_STP


static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/*..... Function Prototypes ..................*/
static sai_status_t mlnx_stp_vlanlist_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          _In_ void                     *arg);

/* STP INSTANCE ATTRIBUTES */
static const sai_attribute_entry_t        stp_attribs[] = {
    { SAI_STP_ATTR_VLAN_LIST, false, false, false, true,
      "List of VLANs associated", SAI_ATTR_VAL_TYPE_VLANLIST },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t stp_vendor_attribs[] = {
    { SAI_STP_ATTR_VLAN_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_stp_vlanlist_get, NULL,
      NULL, NULL }
};
static void stp_id_to_str(_In_ sai_object_id_t sai_stp_id, _Out_ char *key_str)
{
    uint32_t     data;
    sai_status_t status;

    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP_INSTANCE,
                                 &data, NULL);
    if (SX_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid STP instance id");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "STP instance id [%u]", (sx_mstp_inst_id_t)data);
    }
}

/* Generate instance id (will be passed to SDK API) */
static sai_status_t create_stp_id(_Out_ sx_mstp_inst_id_t* sx_stp_id)
{
    sai_status_t      status;
    sx_mstp_inst_id_t ii;
    mlnx_mstp_inst_t *stp_db_entry;

    SX_LOG_ENTER();

    /* look for unused element */
    for (ii = SX_MSTP_INST_ID_MIN; ii <= SX_MSTP_INST_ID_MAX; ii++) {
        stp_db_entry = get_stp_db_entry(ii);
        if (stp_db_entry->is_used == false) {
            /* return instance id */
            *sx_stp_id            = ii;
            stp_db_entry->is_used = true;
            SX_LOG_DBG("Generated STP id [%u]\n", ii);
            status = SAI_STATUS_SUCCESS;
            goto out;
        }
    }

    /* if no free id found, return errorcode */
    SX_LOG_ERR("STP instances DB is full\n");
    status = SAI_STATUS_TABLE_FULL;

out:
    SX_LOG_EXIT();
    return status;
}

/* remove instance id from database */
static void remove_stp_id(_In_ sx_mstp_inst_id_t sx_stp_id)
{
    mlnx_mstp_inst_t *stp_db_entry;

    SX_LOG_ENTER();

    SX_LOG_NTC("Removing instance id [%u] from STP db \n", sx_stp_id);

    stp_db_entry          = get_stp_db_entry(sx_stp_id);
    stp_db_entry->is_used = false;

    SX_LOG_EXIT();
}

/*
 * Routine Description:
 *    Create STP instance
 * Arguments:
 *    [out] sai_stp_id - id of STP instance created
 *    [in]  attr_count - number of attributes
 *    [in]  attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_create_stp(_Out_ sai_object_id_t      *sai_stp_id,
                                    _In_ uint32_t               attr_count,
                                    _In_ const sai_attribute_t *attr_list)
{
    sx_status_t status;
    /* is this OK? */
    sx_mstp_inst_id_t sx_stp_id = SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID;

    SX_LOG_ENTER();

    if (sai_stp_id == NULL) {
        SX_LOG_ERR("NULL object id\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* check attribs validity */
    status = check_attribs_metadata(attr_count, attr_list, stp_attribs,
                                    stp_vendor_attribs, SAI_COMMON_API_CREATE);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    /* generate instance id */
    assert(NULL != g_sai_db_ptr);
    sai_db_write_lock();

    status = create_stp_id(&sx_stp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to generate STP instance id\n");
        goto out;
    }

    SX_LOG_DBG("Creating new STP instance [%u]\n", sx_stp_id);

    /* create STP instance */
    status = sx_api_mstp_inst_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                  DEFAULT_ETH_SWID, sx_stp_id);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        remove_stp_id(sx_stp_id);
        status = sdk_to_sai(status);
        goto out;
    }

    /* return STP id */
    status = mlnx_create_object(SAI_OBJECT_TYPE_STP_INSTANCE, sx_stp_id,
                                NULL, sai_stp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to create object of stp_id [%u]\n", sx_stp_id);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return status;
}

/*
 * Routine Description:
 *    Remove STP instance
 * Arguments:
 *    [in] sai_stp_id - id of STP instance created
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_remove_stp(_In_ sai_object_id_t sai_stp_id)
{
    sx_status_t       status;
    uint32_t          data;
    sx_mstp_inst_id_t sx_stp_id;
    sx_mstp_inst_id_t def_stp_id;
    uint32_t          vlan_cnt;      /* number of VLANs associated */

    SX_LOG_ENTER();

    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP_INSTANCE,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get STP instance id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    SX_LOG_NTC("Removing STP number [%u]\n", sx_stp_id);

    assert(NULL != g_sai_db_ptr);
    sai_db_read_lock();

    def_stp_id = mlnx_stp_get_default_stp();
    sai_db_unlock();

    if (sx_stp_id == def_stp_id) {
        SX_LOG_ERR("Removing default STP is not permitted\n");
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    /* check for VLANs associated */
    status = sx_api_mstp_inst_vlan_list_get(gh_sdk, DEFAULT_ETH_SWID, sx_stp_id, NULL, &vlan_cnt);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    } else if (vlan_cnt != 0) {
        SX_LOG_ERR("Failed to remove STP number [%u]: it still has some VLANs\n", sx_stp_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    /* remove STP instance */
    status = sx_api_mstp_inst_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID, sx_stp_id);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    assert(NULL != g_sai_db_ptr);
    sai_db_write_lock();

    /* remove instance id from db */
    remove_stp_id(sx_stp_id);

    sai_db_unlock();

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Update stp state of a port in specified stp instance
 *
 * Arguments:
 *    [in] sai_stp_id - STP instance id
 *    [in] port_id - state fo the port
 *    [in] sai_port_state - state to set the port
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_set_stp_port_state(_In_ sai_object_id_t           sai_stp_id,
                                            _In_ sai_object_id_t           sai_port_id,
                                            _In_ sai_port_stp_port_state_t sai_port_state)
{
    sx_status_t               status;
    sx_mstp_inst_port_state_t sx_port_state;
    sx_port_log_id_t          sx_port_id;
    uint32_t                  data;
    sx_mstp_inst_id_t         sx_stp_id;

    SX_LOG_ENTER();

    /* Get sx_stp_id */
    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP_INSTANCE,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get stp_id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    /* Get SDK portstate by SAI portstate */
    switch (sai_port_state) {
    case SAI_PORT_STP_STATE_LEARNING:
        sx_port_state = SX_MSTP_INST_PORT_STATE_LEARNING;
        break;

    case SAI_PORT_STP_STATE_FORWARDING:
        sx_port_state = SX_MSTP_INST_PORT_STATE_FORWARDING;
        break;

    case SAI_PORT_STP_STATE_BLOCKING:
        sx_port_state = SX_MSTP_INST_PORT_STATE_DISCARDING;
        break;

    default:
        SX_LOG_ERR("Invalid port state passed\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Get sx_port_id */
    status = mlnx_object_to_type(sai_port_id, SAI_OBJECT_TYPE_PORT,
                                 &sx_port_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port_id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    SX_LOG_DBG("Setting state for port number [%u] of STP [%u]\n", sx_port_id, sx_stp_id);

    /**  Call SDK to set port state **/
    status = sx_api_mstp_inst_port_state_set(gh_sdk, DEFAULT_ETH_SWID, sx_stp_id,
                                             sx_port_id, sx_port_state);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Retrieve port state in specified stp instance
 *
 * Arguments:
 *    [in] sai_stp_id - STP instance id
 *    [in] port_id - state fo the port
 *    [out] sai_port_state - retrieved port state
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_stp_port_state(_In_ sai_object_id_t             sai_stp_id,
                                            _In_ sai_object_id_t             sai_port_id,
                                            _Out_ sai_port_stp_port_state_t *sai_port_state)
{
    sx_status_t               status;
    sx_mstp_inst_port_state_t sx_port_state;
    sx_port_log_id_t          sx_port_id;
    sx_mstp_inst_id_t         sx_stp_id;
    uint32_t                  data;

    SX_LOG_ENTER();

    /* Get sx_stp_id */
    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP_INSTANCE,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get stp_id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    /* Get sx_port_id */
    status = mlnx_object_to_type(sai_port_id, SAI_OBJECT_TYPE_PORT,
                                 &sx_port_id, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get port_id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    SX_LOG_DBG("Getting state of port [%u] of STP [%u]\n", sx_port_id, sx_stp_id);

    /* Call SDK to get sx_port_state */
    status = sx_api_mstp_inst_port_state_get(gh_sdk, DEFAULT_ETH_SWID, sx_stp_id,
                                             sx_port_id, &sx_port_state);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* Get SAI portstate by SDK portstate */
    switch (sx_port_state) {
    case SX_MSTP_INST_PORT_STATE_LEARNING:
        *sai_port_state = SAI_PORT_STP_STATE_LEARNING;
        break;

    case SX_MSTP_INST_PORT_STATE_FORWARDING:
        *sai_port_state = SAI_PORT_STP_STATE_FORWARDING;
        break;

    case SX_MSTP_INST_PORT_STATE_DISCARDING:
        *sai_port_state = SAI_PORT_STP_STATE_BLOCKING;
        break;

    default:
        SX_LOG_ERR("Invalid port state was got\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set specified attribute of STP instance.
 *
 * Arguments:
 *    [in] sai_stp_id - STP instance id
 *    [in] attr - instance attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_stp_attribute(_In_ sai_object_id_t sai_stp_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = {.object_id = sai_stp_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    /* Get sx_stp_id */
    stp_id_to_str(sai_stp_id, key_str);

    status = sai_set_attribute(&key, key_str, stp_attribs, stp_vendor_attribs, attr);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Get specified attribute of STP instance.
 *
 * Arguments:
 *    [in] sai_stp_id - STP instance id
 *    [in] attr_count - number of the attributes
 *    [inout] attr - attribute of the instance
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t mlnx_get_stp_attribute(_In_ const sai_object_id_t sai_stp_id,
                                           _In_ uint32_t              attr_count,
                                           _Inout_ sai_attribute_t   *attr_list)
{
    const sai_object_key_t key = { .object_id = sai_stp_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           status;

    SX_LOG_ENTER();

    /* Get sx_stp_id */
    stp_id_to_str(sai_stp_id, key_str);

    status = sai_get_attributes(&key, key_str, stp_attribs, stp_vendor_attribs, attr_count, attr_list);
    if (SAI_ERR(status)) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* vlanlist getter */
static sai_status_t mlnx_stp_vlanlist_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          _In_ void                     *arg)
{
    sx_status_t           status;
    const sai_object_id_t sai_stp_id = key->object_id;
    sx_mstp_inst_id_t     sx_stp_id;
    uint32_t              data;
    mlnx_mstp_inst_t     *stp_db_entry;

    SX_LOG_ENTER();

    /* Get sx_stp_id */
    status = mlnx_object_to_type(sai_stp_id, SAI_OBJECT_TYPE_STP_INSTANCE,
                                 &data, NULL);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to get stp_id of object [%" PRIx64 "]\n", sai_stp_id);
        return status;
    }

    sx_stp_id = (sx_mstp_inst_id_t)data;

    /* validate STP id */
    if (!SX_MSTP_INST_ID_CHECK_RANGE(sx_stp_id)) {
        SX_LOG_ERR("Invalid STP id: should be within a range [%u - %u]\n",
                   SX_MSTP_INST_ID_MIN, SX_MSTP_INST_ID_MAX);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    /* Get number of VLANS added to specified STP instance */
    assert(NULL != g_sai_db_ptr);
    sai_db_read_lock();

    stp_db_entry = get_stp_db_entry(sx_stp_id);

    /* Check if user has got enough memory to store the vlanlist */
    if (value->vlanlist.count < stp_db_entry->vlan_count) {
        SX_LOG_ERR("Not enough memory to store %u VLANs\n", stp_db_entry->vlan_count);
        status = SAI_STATUS_BUFFER_OVERFLOW;
        goto out;
    }

    /* Call SDK API to read VLAN list */
    status = sx_api_mstp_inst_vlan_list_get(gh_sdk, DEFAULT_ETH_SWID, sx_stp_id,
                                            value->vlanlist.list,
                                            &value->vlanlist.count);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

out:
    sai_db_unlock();
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* STP initializer. */
/* Called when switch is starting. */
sai_status_t mlnx_stp_initialize()
{
    sx_status_t status;

    SX_LOG_ENTER();

    /* set MSTP mode */
    status = sx_api_mstp_mode_set(gh_sdk, DEFAULT_ETH_SWID, SX_MSTP_MODE_MSTP);
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    /* Generate default STP instance id */
    SX_LOG_DBG("Generating default STP id\n");

    status = create_stp_id(&g_sai_db_ptr->def_stp_id);
    if (SAI_ERR(status)) {
        SX_LOG_ERR("Failed to generate default STP id\n");
        goto out;
    }

    SX_LOG_DBG("Default STP id = %u\n", mlnx_stp_get_default_stp());

    /* Create default STP instance */
    status = sx_api_mstp_inst_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                  DEFAULT_ETH_SWID, mlnx_stp_get_default_stp());
    if (SX_ERR(status)) {
        SX_LOG_ERR("%s\n", SX_STATUS_MSG(status));
        remove_stp_id(mlnx_stp_get_default_stp());
        status = sdk_to_sai(status);
        goto out;
    }

    /* init VLAN db with INVALID STPs */
    sai_vlan_id_t ii;
    mlnx_vlan_id_foreach(ii) {
        mlnx_vlan_stp_id_set(ii, SAI_INVALID_STP_INSTANCE);
    }

    /* Add VLAN 1 to default STP */
    status = mlnx_vlan_stp_bind(DEFAULT_VLAN, mlnx_stp_get_default_stp());
    if (SAI_ERR(status)) {
        remove_stp_id(mlnx_stp_get_default_stp());
        SX_LOG_ERR("Failed to add VLAN %u to default STP\n", DEFAULT_VLAN);
        goto out;
    }

out:
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_stp_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_mstp_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH,
                                                              level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

sx_mstp_inst_id_t mlnx_stp_get_default_stp()
{
    return (g_sai_db_ptr->def_stp_id);
}

mlnx_mstp_inst_t * get_stp_db_entry(sx_mstp_inst_id_t sx_stp_id)
{
    return (&g_sai_db_ptr->mlnx_mstp_inst_db[sx_stp_id - SX_MSTP_INST_ID_MIN]);
}

/* Method table */
const sai_stp_api_t mlnx_stp_api = {
    mlnx_create_stp,
    mlnx_remove_stp,
    mlnx_set_stp_attribute,
    mlnx_get_stp_attribute,
    mlnx_set_stp_port_state,
    mlnx_get_stp_port_state,
};
