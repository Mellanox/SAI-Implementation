#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"

#undef  __MODULE__
#define __MODULE__ SAI_LAG

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;
static const sai_attribute_entry_t lag_attribs[] = {
    { SAI_LAG_ATTR_PORT_LIST, false, true, true, true,
      "LAG ID for LAG Member", SAI_ATTR_VAL_TYPE_OBJLIST },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_lag_port_list_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg);
static sai_status_t mlnx_lag_port_list_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg);
static const sai_vendor_attribute_entry_t lag_vendor_attribs[] = {
    { SAI_LAG_ATTR_PORT_LIST,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_lag_port_list_get, NULL,
      mlnx_lag_port_list_set, NULL },
};
static const sai_attribute_entry_t        lag_member_attribs[] = {
    { SAI_LAG_MEMBER_ATTR_LAG_ID, true, true, false, true,
      "LAG ID for LAG Member", SAI_ATTR_VAL_TYPE_OID },
    { SAI_LAG_MEMBER_ATTR_PORT_ID, true, true, false, true,
      "PORT ID for LAG Member", SAI_ATTR_VAL_TYPE_OID },
    { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, false, true, true, true,
      "LAG Member Egress Disable", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, false, true, true, true,
      "LAG Member Ingress Disable", SAI_ATTR_VAL_TYPE_BOOL },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static sai_status_t mlnx_lag_member_lag_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_lag_member_port_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
static sai_status_t mlnx_lag_member_egress_disable_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg);
static sai_status_t mlnx_lag_member_egress_disable_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg);
static sai_status_t mlnx_lag_member_ingress_disable_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t mlnx_lag_member_ingress_disable_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static const sai_vendor_attribute_entry_t lag_member_vendor_attribs[] = {
    { SAI_LAG_MEMBER_ATTR_LAG_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_lag_member_lag_id_get, NULL,
      NULL, NULL },
    { SAI_LAG_MEMBER_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_lag_member_port_id_get, NULL,
      NULL, NULL },
    { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_lag_member_egress_disable_get, NULL,
      mlnx_lag_member_egress_disable_set, NULL },
    { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_lag_member_ingress_disable_get, NULL,
      mlnx_lag_member_ingress_disable_set, NULL },
};
static void lag_key_to_str(_In_ sai_object_id_t lag_id, _Out_ char *key_str)
{
    uint32_t lagid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lagid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG ID %u", lagid);
    }
}

static void lag_member_key_to_str(_In_ sai_object_id_t lag_member_id, _Out_ char *key_str)
{
    uint32_t lag_memberid;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER, &lag_memberid, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid LAG Member ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "LAG ID Member %u", lag_memberid);
    }
}

static sai_status_t mlnx_lag_setup_lag(sx_port_log_id_t lag_log_port_id)
{
    sx_status_t                sx_status;
    sx_port_speed_capability_t admin_speed;
    sx_vlan_ports_t            vlan_port;

    memset(&admin_speed, 0, sizeof(admin_speed));
    admin_speed.mode_40GB_CR4     = true;
    admin_speed.mode_40GB_SR4     = true;
    admin_speed.mode_40GB_LR4_ER4 = true;
    memset(&vlan_port, 0, sizeof(vlan_port));
    vlan_port.is_untagged = true;

    /* Initialize LAG as we did to port in mlnx_dvs_mng_stage() to have same default value */
    if (SX_STATUS_SUCCESS != (sx_status = sx_api_rstp_port_state_set(gh_sdk, lag_log_port_id,
                                                                     SX_MSTP_INST_PORT_STATE_FORWARDING))) {
        SX_LOG_ERR("port rstp state set %x failed - %s.\n", lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_port_speed_admin_set(gh_sdk, lag_log_port_id,
                                                                      &admin_speed))) {
        SX_LOG_ERR("port admin speed set %x failed - %s.\n", lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_port_state_set(gh_sdk, lag_log_port_id,
                                                                SX_PORT_ADMIN_STATUS_UP))) {
        SX_LOG_ERR("port state set %x failed - %s.\n", lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_vlan_port_pvid_set(gh_sdk, SX_ACCESS_CMD_ADD,
                                                                    lag_log_port_id, DEFAULT_VLAN))) {
        SX_LOG_ERR("port pvid set %x failed - %s.\n", lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    vlan_port.log_port = lag_log_port_id;
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_vlan_ports_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID, DEFAULT_VLAN,
                                           &vlan_port, 1))) {
        SX_LOG_ERR("port add port %x to vlan %u failed - %s.\n", lag_log_port_id,
                   DEFAULT_VLAN, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SX_STATUS_SUCCESS != (sx_status = sx_api_vlan_port_ingr_filter_set(gh_sdk, lag_log_port_id,
                                                                           SX_INGR_FILTER_ENABLE))) {
        SX_LOG_ERR("port ingress filter set %x failed - %s.\n", lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = sx_api_cos_port_trust_set(gh_sdk, lag_log_port_id, SX_COS_TRUST_LEVEL_PORT);
    if (sx_status != SX_STATUS_SUCCESS) {
        SX_LOG_ERR("port trust level set %x failed - %s.\n",
                   lag_log_port_id, SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    sx_status = mlnx_hash_ecmp_cfg_apply_on_port(lag_log_port_id);
    if (sx_status != SAI_STATUS_SUCCESS) {
        return sx_status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_align_ports_to_lag(sai_object_id_t lag_id, const sai_attribute_value_t *port_list)
{
    sai_status_t                       status;
    sx_status_t                        sx_status;
    sx_port_log_id_t                   lag_log_port_id;
    sx_port_log_id_t                  *log_port_list = NULL;
    uint32_t                           log_port_cnt  = 0;
    sx_router_ecmp_port_hash_params_t  hash_params;
    sx_router_ecmp_hash_field_enable_t hash_field_enable_list[FIELDS_ENABLES_NUM];
    uint32_t                           enables_cnt = FIELDS_ENABLES_NUM;
    sx_router_ecmp_hash_field_t        hash_field_list[FIELDS_NUM];
    uint32_t                           fields_cnt = FIELDS_NUM;
    uint8_t                            ii;

    if (port_list == NULL) {
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    /* get ecmp hash params of lag */
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_router_ecmp_port_hash_params_get(gh_sdk, lag_log_port_id,
                                                             &hash_params, hash_field_enable_list, &enables_cnt,
                                                             hash_field_list, &fields_cnt))) {
        SX_LOG_ERR("Failed to get lag ecmp hash - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* set params of ports to the ones of lag */
    log_port_cnt = port_list->objlist.count;
    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        for (ii = 0; ii < log_port_cnt; ii++) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(port_list->objlist.list[ii], SAI_OBJECT_TYPE_PORT, &log_port_list[ii],
                                         NULL))) {
                free(log_port_list);
                return status;
            }

            if (SX_STATUS_SUCCESS !=
                (sx_status = sx_api_router_ecmp_port_hash_params_set(gh_sdk, SX_ACCESS_CMD_SET,
                                                                     log_port_list[ii], &hash_params,
                                                                     hash_field_enable_list, enables_cnt,
                                                                     hash_field_list, fields_cnt))) {
                SX_LOG_ERR("Failed to set port ecmp hash - %s.\n", SX_STATUS_MSG(status));
                free(log_port_list);
                return sdk_to_sai(status);
            }
        }

        free(log_port_list);
    }

    return SX_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_remove_all_ports(sai_object_id_t lag_id)
{
    sai_status_t      status;
    sx_port_log_id_t  lag_log_port_id;
    sx_status_t       sx_status;
    sx_port_log_id_t *log_port_list = NULL;
    uint32_t          log_port_cnt  = 0;
    uint32_t          ii            = 0, jj = 0;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    /*  Remove all ports from the LAG first */
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                               lag_log_port_id, NULL, &log_port_cnt))) {
        return sdk_to_sai(sx_status);
    }

    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                   lag_log_port_id, log_port_list, &log_port_cnt))) {
            free(log_port_list);
            return sdk_to_sai(sx_status);
        }

        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                                   &lag_log_port_id, log_port_list, log_port_cnt))) {
            free(log_port_list);
            return sdk_to_sai(sx_status);
        }

        /* restore port settings */
        for (ii = 0; ii < log_port_cnt; ii++) {
            sx_status = mlnx_hash_ecmp_cfg_apply_on_port(log_port_list[ii]);
            if (sx_status != SAI_STATUS_SUCCESS) {
                return sx_status;
            }

            sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, log_port_list[ii], SX_FDB_LEARN_MODE_AUTO_LEARN);
            if (SX_STATUS_SUCCESS != sx_status) {
                SX_LOG_ERR("Failed to set port learning mode - %s.\n", SX_STATUS_MSG(sx_status));
                return sdk_to_sai(sx_status);
            }
        }

        /* Update port config - clear lag id */
        sai_db_write_lock();
        for (ii = 0; ii < log_port_cnt; ii++) {
            for (jj = 0; jj < g_sai_db_ptr->ports_number; jj++) {
                if (log_port_list[ii] == g_sai_db_ptr->ports_db[jj].logical) {
                    g_sai_db_ptr->ports_db[jj].lag_id = SAI_NULL_OBJECT_ID;
                }
            }
        }
        sai_db_sync();
        sai_db_unlock();
    }

    free(log_port_list);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_add_ports(sai_object_id_t lag_id, const sai_attribute_value_t *port_list)
{
    sai_status_t      status;
    sx_port_log_id_t  lag_log_port_id;
    uint32_t          ii;
    sx_status_t       sx_status;
    sx_port_log_id_t *log_port_list = NULL;
    uint32_t          log_port_cnt  = 0;
    uint32_t          port_index    = 0;

    if (port_list == NULL) {
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    log_port_cnt = port_list->objlist.count;
    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        for (ii = 0; ii < log_port_cnt; ii++) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_object_to_type(port_list->objlist.list[ii], SAI_OBJECT_TYPE_PORT, &log_port_list[ii],
                                         NULL))) {
                free(log_port_list);
                return status;
            }
        }

        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_ADD, DEFAULT_ETH_SWID,
                                                   &lag_log_port_id, log_port_list, log_port_cnt))) {
            SX_LOG_ERR("Failed to set lag ports %s.\n", SX_STATUS_MSG(sx_status));
            free(log_port_list);
            return sdk_to_sai(sx_status);
        }

        for (ii = 0; ii < log_port_cnt; ii++) {
            if (SX_STATUS_SUCCESS !=
                (sx_status = sx_api_lag_port_collector_set
                                 (gh_sdk, lag_log_port_id, log_port_list[ii], COLLECTOR_ENABLE))) {
                return sdk_to_sai(sx_status);
            }
            if (SX_STATUS_SUCCESS !=
                (sx_status = sx_api_lag_port_distributor_set
                                 (gh_sdk, lag_log_port_id, log_port_list[ii], DISTRIBUTOR_ENABLE))) {
                return sdk_to_sai(sx_status);
            }
        }

        /* Update port config with new lag value */
        sai_db_write_lock();
        status = SAI_STATUS_SUCCESS;
        for (ii = 0; ii < log_port_cnt; ii++) {
            status = find_port_in_db(port_list->objlist.list[ii], &port_index);
            if (SAI_STATUS_SUCCESS != status) {
                break;
            }
            g_sai_db_ptr->ports_db[port_index].lag_id = lag_id;
        }
        sai_db_sync();
        sai_db_unlock();
        free(log_port_list);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_port_list_get(_In_ const sai_object_key_t   *key,
                                           _Inout_ sai_attribute_value_t *value,
                                           _In_ uint32_t                  attr_index,
                                           _Inout_ vendor_cache_t        *cache,
                                           void                          *arg)
{
    sai_status_t      status;
    sai_object_id_t   lag_id = key->object_id;
    sx_port_log_id_t  lag_log_port_id;
    sx_port_log_id_t *log_port_list = NULL;
    uint32_t          log_port_cnt  = 0;
    uint32_t          ii;
    sx_status_t       sx_status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                               lag_log_port_id, NULL, &log_port_cnt))) {
        return sdk_to_sai(sx_status);
    }

    if (value->objlist.count < log_port_cnt) {
        SX_LOG_ERR("Insufficient list buffer size. Allocated %u needed %u\n",
                   value->objlist.count, log_port_cnt);
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    if (log_port_cnt) {
        log_port_list = (sx_port_log_id_t*)malloc(sizeof(sx_port_log_id_t) * log_port_cnt);
        if (NULL == log_port_list) {
            SX_LOG_ERR("Can't allocate memory\n");
            return SAI_STATUS_NO_MEMORY;
        }

        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_group_get(gh_sdk, DEFAULT_ETH_SWID,
                                                   lag_log_port_id, log_port_list, &log_port_cnt))) {
            free(log_port_list);
            return sdk_to_sai(sx_status);
        }

        for (ii = 0; ii < log_port_cnt; ii++) {
            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_create_object(SAI_OBJECT_TYPE_PORT, (uint32_t)log_port_list[ii], NULL,
                                        &value->objlist.list[ii]))) {
                free(log_port_list);
                return status;
            }
        }
        free(log_port_list);
    }
    value->objlist.count = log_port_cnt;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_port_list_set(_In_ const sai_object_key_t      *key,
                                           _In_ const sai_attribute_value_t *value,
                                           void                             *arg)
{
    sai_status_t    status;
    sai_object_id_t lag_id = key->object_id;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_lag_remove_all_ports(lag_id))) {
        return status;
    }
    /* TODO: Align ports to lag as workaround */
    if (SAI_STATUS_SUCCESS != (status = mlnx_lag_align_ports_to_lag(lag_id, value))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_lag_add_ports(lag_id, value))) {
        SX_LOG_ERR("Failed to add ports to lag \n");
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_lag_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, lag_log_port_id, NULL, &value->oid))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_port_id_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg)
{
    sai_status_t     status;
    sx_port_log_id_t log_port_id;
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, log_port_id, NULL, &value->oid))) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_egress_disable_get(_In_ const sai_object_key_t   *key,
                                                       _Inout_ sai_attribute_value_t *value,
                                                       _In_ uint32_t                  attr_index,
                                                       _Inout_ vendor_cache_t        *cache,
                                                       void                          *arg)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_port_log_id_t      lag_log_port_id = 0;
    sx_port_log_id_t      log_port_id;
    uint8_t               extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t       lag_member_id = key->object_id;
    sx_distributor_mode_t distributor_mode;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_distributor_get(gh_sdk, lag_log_port_id, log_port_id, &distributor_mode))) {
        return sdk_to_sai(sx_status);
    }

    if (distributor_mode == DISTRIBUTOR_DISABLE) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_egress_disable_set(_In_ const sai_object_key_t      *key,
                                                       _In_ const sai_attribute_value_t *value,
                                                       void                             *arg)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_distributor_set
                         (gh_sdk, lag_log_port_id, log_port_id,
                         value->booldata ? DISTRIBUTOR_DISABLE : DISTRIBUTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_ingress_disable_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    sai_status_t        status;
    sx_status_t         sx_status;
    sx_port_log_id_t    lag_log_port_id = 0;
    sx_port_log_id_t    log_port_id;
    uint8_t             extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t     lag_member_id = key->object_id;
    sx_collector_mode_t collector_mode;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_get(gh_sdk, lag_log_port_id, log_port_id, &collector_mode))) {
        return sdk_to_sai(sx_status);
    }

    if (collector_mode == COLLECTOR_DISABLE) {
        value->booldata = true;
    } else {
        value->booldata = false;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_lag_member_ingress_disable_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    sai_object_id_t  lag_member_id = key->object_id;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_collector_set
                         (gh_sdk, lag_log_port_id, log_port_id,
                         value->booldata ? COLLECTOR_DISABLE : COLLECTOR_ENABLE))) {
        return sdk_to_sai(sx_status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_create_lag(_Out_ sai_object_id_t* lag_id,
                                    _In_ uint32_t          attr_count,
                                    _In_ const sai_attribute_t  *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    const sai_attribute_value_t *port_list = NULL;
    uint32_t                     port_list_index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_port_log_id_t             lag_log_port_id;
    uint32_t                     ii = 0;

    SX_LOG_ENTER();

    if (NULL == lag_id) {
        SX_LOG_ERR("NULL lag id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, lag_attribs, lag_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, lag_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag, %s\n", list_str);

    /* CREATE LAG first */
    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_CREATE, DEFAULT_ETH_SWID,
                                               &lag_log_port_id, NULL, 0))) {
        SX_LOG_ERR("Failed to lag ports %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_create_object(SAI_OBJECT_TYPE_LAG, (uint32_t)lag_log_port_id, NULL, lag_id))) {
        return status;
    }

    /* Add to lag_db */
    sai_db_write_lock();
    for (ii = 0; ii < SAI_LAG_NUM_MAX; ii++) {
        if (g_sai_db_ptr->lag_db[ii] == 0) {
            g_sai_db_ptr->lag_db[ii] = lag_log_port_id;
            break;
        }
    }
    sai_db_sync();
    sai_db_unlock();
    if (ii == SAI_LAG_NUM_MAX) {
        /* Should not reach this place */
        SX_LOG_ERR("Failed to save lag id in SAI DB\n.");
    }

    lag_key_to_str(*lag_id, key_str);
    SX_LOG_NTC("Created LAG %s\n", key_str);

    /* TODO: set default values in lag as workaround */
    mlnx_lag_setup_lag(lag_log_port_id);

    /* ADD ports to LAG */
    /* TODO: check if ports exceed SAI_SWITCH_ATTR_LAG_MEMBERS */
    if (SAI_STATUS_SUCCESS == find_attrib_in_list(attr_count,
                                                  attr_list,
                                                  SAI_LAG_ATTR_PORT_LIST,
                                                  &port_list,
                                                  &port_list_index)) {
        /* TODO: Align ports to lag as workaround */
        if (SAI_STATUS_SUCCESS != (status = mlnx_lag_align_ports_to_lag(*lag_id, port_list))) {
            return status;
        }
        if (SAI_STATUS_SUCCESS != (status = mlnx_lag_add_ports(*lag_id, port_list))) {
            return status;
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_lag(_In_ sai_object_id_t lag_id)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id;
    uint32_t         ii = 0;

    SX_LOG_NTC("Remove SAI LAG %" PRIx64 "\n", (uint64_t)lag_id);

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    /*  Remove all ports from the LAG first */
    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_lag_remove_all_ports(lag_id))) {
        return status;
    }

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DESTROY, DEFAULT_ETH_SWID,
                                               &lag_log_port_id, NULL, 0))) {
        return sdk_to_sai(sx_status);
    }

    /* Remove from lag_db */
    sai_db_write_lock();
    for (ii = 0; ii < SAI_LAG_NUM_MAX; ii++) {
        if (g_sai_db_ptr->lag_db[ii] == lag_log_port_id) {
            g_sai_db_ptr->lag_db[ii] = 0;
            break;
        }
    }
    sai_db_sync();
    sai_db_unlock();
    if (ii == SAI_LAG_NUM_MAX) {
        /* Should not reach this place */
        SX_LOG_ERR("Failed to find lag id in SAI DB.\n");
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_lag_attribute(_In_ sai_object_id_t lag_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_set_attribute(&key, key_str, lag_attribs, lag_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_attribute(_In_ sai_object_id_t     lag_id,
                                           _In_ uint32_t            attr_count,
                                           _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = lag_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_key_to_str(lag_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              lag_attribs,
                              lag_vendor_attribs,
                              attr_count,
                              attr_list);
}

static sai_status_t mlnx_create_lag_member(_Out_ sai_object_id_t* lag_member_id,
                                           _In_ uint32_t          attr_count,
                                           _In_ const sai_attribute_t  *attr_list)
{
    sai_status_t                 status;
    sx_status_t                  sx_status;
    const sai_attribute_value_t *attr_lag_id, *attr_port_id, *attr_egress_disable, *attr_ingress_disable;
    sai_object_id_t              lag_id, port_id;
    sai_attribute_value_t        port_list;
    uint32_t                     index;
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    sx_port_log_id_t             lag_log_port_id;
    sx_port_log_id_t             log_port_id;
    uint8_t                      extended_data[EXTENDED_DATA_SIZE];

    SX_LOG_ENTER();

    memset(extended_data, 0, sizeof(extended_data));

    if (NULL == lag_member_id) {
        SX_LOG_ERR("NULL lag member id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, lag_member_attribs, lag_member_vendor_attribs,
                                    SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, lag_member_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create lag member, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count,
                               attr_list,
                               SAI_LAG_MEMBER_ATTR_LAG_ID,
                               &attr_lag_id,
                               &index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count,
                               attr_list,
                               SAI_LAG_MEMBER_ATTR_PORT_ID,
                               &attr_port_id,
                               &index));

    lag_id  = attr_lag_id->oid;
    port_id = attr_port_id->oid;

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(lag_id, SAI_OBJECT_TYPE_LAG, &lag_log_port_id, NULL))) {
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(port_id, SAI_OBJECT_TYPE_PORT, &log_port_id, NULL))) {
        return status;
    }

    /* Add port to lag */
    port_list.objlist.count = 1;
    port_list.objlist.list  = &port_id;
    /* TODO: Align ports to lag as workaround */
    if (SAI_STATUS_SUCCESS != (status = mlnx_lag_align_ports_to_lag(lag_id, &port_list))) {
        return status;
    }
    if (SAI_STATUS_SUCCESS != (status = mlnx_lag_add_ports(lag_id, &port_list))) {
        return status;
    }

    /* set egress and ingress mode */
    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list,
                                      SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, &attr_egress_disable, &index))) {
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_distributor_set(gh_sdk, lag_log_port_id,
                                                         log_port_id,
                                                         attr_egress_disable->booldata ? DISTRIBUTOR_DISABLE :
                                                         DISTRIBUTOR_ENABLE))) {
            return sdk_to_sai(sx_status);
        }
    }
    if (SAI_STATUS_SUCCESS ==
        (status = find_attrib_in_list(attr_count, attr_list,
                                      SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, &attr_ingress_disable, &index))) {
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_lag_port_collector_set(gh_sdk, lag_log_port_id,
                                                       log_port_id,
                                                       attr_ingress_disable->booldata ? COLLECTOR_DISABLE :
                                                       COLLECTOR_ENABLE))) {
            return sdk_to_sai(sx_status);
        }
    }

    /* create lag member id */
    extended_data[2] = SX_PORT_SUB_ID_GET(lag_log_port_id);     /* Port-Sub-ID */
    extended_data[1] = SX_PORT_LAG_ID_GET(lag_log_port_id);     /* LAG-ID */
    extended_data[0] = SX_PORT_TYPE_ID_GET(lag_log_port_id);    /* Type-ID: SX_PORT_TYPE_LAG */
    if (SAI_STATUS_SUCCESS !=
        (status =
             mlnx_create_object(SAI_OBJECT_TYPE_LAG_MEMBER, log_port_id, extended_data, lag_member_id))) {
        return status;
    }

    /* TODO: another approach is to create list with lag member, port, and lag */

    lag_member_key_to_str(*lag_member_id, key_str);
    SX_LOG_NTC("Created LAG member %s\n", key_str);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_remove_lag_member(_In_ sai_object_id_t lag_member_id)
{
    sai_status_t     status;
    sx_status_t      sx_status;
    sx_port_log_id_t lag_log_port_id = 0;
    sx_port_log_id_t log_port_id;
    uint8_t          extended_data[EXTENDED_DATA_SIZE];
    uint32_t         ii;

    if (SAI_STATUS_SUCCESS != (status = mlnx_object_to_type(lag_member_id, SAI_OBJECT_TYPE_LAG_MEMBER,
                                                            &log_port_id, extended_data))) {
        return status;
    }

    SX_PORT_TYPE_ID_SET(lag_log_port_id, extended_data[0]);
    SX_PORT_LAG_ID_SET(lag_log_port_id, extended_data[1]);
    SX_PORT_SUB_ID_SET(lag_log_port_id, extended_data[2]);

    if (SX_STATUS_SUCCESS !=
        (sx_status = sx_api_lag_port_group_set(gh_sdk, SX_ACCESS_CMD_DELETE, DEFAULT_ETH_SWID,
                                               &lag_log_port_id, &log_port_id, 1))) {
        return sdk_to_sai(sx_status);
    }

    sx_status = mlnx_hash_ecmp_cfg_apply_on_port(log_port_id);
    if (sx_status != SAI_STATUS_SUCCESS) {
        return sx_status;
    }

    sx_status = sx_api_fdb_port_learn_mode_set(gh_sdk, log_port_id, SX_FDB_LEARN_MODE_AUTO_LEARN);
    if (SX_STATUS_SUCCESS != sx_status) {
        SX_LOG_ERR("Failed to set port learning mode - %s.\n", SX_STATUS_MSG(sx_status));
        return sdk_to_sai(sx_status);
    }

    /* Update port config - clear lag id */
    sai_db_write_lock();
    for (ii = 0; ii < g_sai_db_ptr->ports_number; ii++) {
        if (log_port_id == g_sai_db_ptr->ports_db[ii].logical) {
            g_sai_db_ptr->ports_db[ii].lag_id = SAI_NULL_OBJECT_ID;
        }
    }
    sai_db_sync();
    sai_db_unlock();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_set_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_set_attribute(&key, key_str, lag_member_attribs, lag_member_vendor_attribs, attr);
}

static sai_status_t mlnx_get_lag_member_attribute(_In_ sai_object_id_t     lag_member_id,
                                                  _In_ uint32_t            attr_count,
                                                  _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key = { .object_id = lag_member_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    lag_member_key_to_str(lag_member_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              lag_member_attribs,
                              lag_member_vendor_attribs,
                              attr_count,
                              attr_list);
}

sai_status_t mlnx_lag_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        return sdk_to_sai(sx_api_lag_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

const sai_lag_api_t mlnx_lag_api = {
    mlnx_create_lag,
    mlnx_remove_lag,
    mlnx_set_lag_attribute,
    mlnx_get_lag_attribute,
    mlnx_create_lag_member,
    mlnx_remove_lag_member,
    mlnx_set_lag_member_attribute,
    mlnx_get_lag_member_attribute
};
