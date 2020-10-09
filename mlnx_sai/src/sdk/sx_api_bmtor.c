#include <complib/sx_log.h>
#include <complib/cl_mem.h>

#include <fx_base_api.h>
#include <flextrum_types.h>

#include <sdk/sx_api_bmtor.h>

#undef __MODULE__
#define __MODULE__ SX_API_BMTOR

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;

/************************************************
 *  API functions implementation
 ***********************************************/

sx_status_t sx_api_bmtor_log_verbosity_level_set(const sx_api_handle_t           handle,
                                                 const sx_log_verbosity_target_t verbosity_target,
                                                 const sx_verbosity_level_t      module_verbosity_level,
                                                 const sx_verbosity_level_t      api_verbosity_level)
{
    return SX_STATUS_SUCCESS;
}

fx_action_id_t __get_table_meta_tunnel_fx_action(sx_table_meta_tunnel_action_t action)
{
    switch (action) {
    case SX_TABLE_META_TUNNEL_TUNNEL_ENCAP_ACTION:
        return CONTROL_OUT_RIF_TUNNEL_ENCAP_ID;
        break;

    case SX_TABLE_META_TUNNEL_NOACTION_ACTION:
        return NOACTION_ID;
        break;

    default:
        SX_LOG_ERR("Invalid table_meta_tunnel action %d\n", action);
        return FX_ACTION_INVALID_ID;
    }

    return FX_ACTION_INVALID_ID;
}

void __fill_table_meta_tunnel_keys(const sx_table_meta_tunnel_entry_key_data_t    *key_data_p,
                                     fx_key_list_t                  *table_meta_tunnel_key_list_p)
{
    static fx_key_t table_meta_tunnel_keys[1];
    int             keys_idx = 0;

    SX_LOG_ENTER();

    memset(table_meta_tunnel_keys, 0, sizeof(table_meta_tunnel_keys));


    table_meta_tunnel_keys[keys_idx].key.data = (uint8_t *)&key_data_p->in_rif_metadata_field;
    table_meta_tunnel_keys[keys_idx].key.len  = sizeof(key_data_p->in_rif_metadata_field);
    keys_idx++;


    table_meta_tunnel_key_list_p->len  = keys_idx;
    table_meta_tunnel_key_list_p->keys = table_meta_tunnel_keys;
}

void __fill_table_meta_tunnel_params(const sx_table_meta_tunnel_entry_action_data_t    *action_data_p,
                                     fx_param_list_t                  *table_meta_tunnel_param_list)
{
    static fx_param_t table_meta_tunnel_params[3];
    int               params_idx = 0;

    SX_LOG_ENTER();

    memset(table_meta_tunnel_params, 0, sizeof(table_meta_tunnel_params));

    switch (action_data_p->action) {
    case SX_TABLE_META_TUNNEL_TUNNEL_ENCAP_ACTION:
        table_meta_tunnel_params[params_idx].data = (uint8_t *)&action_data_p->data.tunnel_encap_params.dst_mac;
        table_meta_tunnel_params[params_idx].len  = sizeof(action_data_p->data.tunnel_encap_params.dst_mac);
        params_idx++;

        table_meta_tunnel_params[params_idx].data = (uint8_t *)&action_data_p->data.tunnel_encap_params.tunnel_id;
        table_meta_tunnel_params[params_idx].len  = sizeof(action_data_p->data.tunnel_encap_params.tunnel_id);
        params_idx++;

        table_meta_tunnel_params[params_idx].data = (uint8_t *)&action_data_p->data.tunnel_encap_params.underlay_dip;
        table_meta_tunnel_params[params_idx].len  = sizeof(action_data_p->data.tunnel_encap_params.underlay_dip);
        params_idx++;

    break;

    case SX_TABLE_META_TUNNEL_NOACTION_ACTION:
    break;

    default:
        SX_LOG_ERR("Invalid action %d\n", action_data_p->action);
    }

    table_meta_tunnel_param_list->len    = params_idx;
    table_meta_tunnel_param_list->params = table_meta_tunnel_params;
}

sx_status_t __sx_table_meta_tunnel_entry_create(const sx_api_handle_t *handle,
                                               const fx_key_list_t   *table_meta_tunnel_key_list,
                                               const fx_param_list_t *table_meta_tunnel_param_list,
                                               fx_action_id_t         flextrum_action,
                                               uint32_t              *priority_p)
{
    fx_handle_t *p_fx_handle = NULL;
    sx_status_t  status;

    SX_LOG_ENTER();

    /* Lazy initialization */
    if (SX_STATUS_SUCCESS != (status = fx_default_handle_get(&p_fx_handle, handle, 1))) {
        SX_LOG_ERR("Failure in obtaining the default fx_handle\n");
        return status;
    }

    return fx_table_entry_add(*p_fx_handle,
                              CONTROL_OUT_RIF_TABLE_META_TUNNEL_ID,
                              flextrum_action,
                              *table_meta_tunnel_key_list,
                              *table_meta_tunnel_param_list,
                              priority_p);
}

sx_status_t __sx_table_meta_tunnel_entry_delete(const sx_api_handle_t *handle,
                                                const fx_key_list_t   *table_meta_tunnel_key_list,
                                                uint32_t               priority)
{
    fx_handle_t *p_fx_handle = NULL;
    sx_status_t  status;

    /* Lazy initialization */
    if (SX_STATUS_SUCCESS != (status = fx_default_handle_get(&p_fx_handle, handle, 1))) {
        SX_LOG_ERR("Failure in obtaining the default fx_handle\n");
        return status;
    }

    SX_LOG_ENTER();

    if (priority == 0) {
        status = fx_table_entry_offset_find(*p_fx_handle,
                                            CONTROL_OUT_RIF_TABLE_META_TUNNEL_ID,
                                            *table_meta_tunnel_key_list,
                                            &priority);

        if (SX_STATUS_SUCCESS != status) {
            return status;
        }
    }

    return fx_table_entry_remove(*p_fx_handle,
                                CONTROL_OUT_RIF_TABLE_META_TUNNEL_ID,
                                priority);
}

sx_status_t sx_api_table_meta_tunnel_entry_set(const sx_api_handle_t                           handle,
                                               const sx_access_cmd_t                           cmd,
                                               const sx_table_meta_tunnel_entry_key_data_t    *key_data_p,
                                               const sx_table_meta_tunnel_entry_action_data_t *action_data_p)

{
    fx_key_list_t   table_meta_tunnel_key_list;
    fx_param_list_t table_meta_tunnel_param_list;
    fx_action_id_t  flextrum_action = FX_ACTION_INVALID_ID;

    SX_LOG_ENTER();

    switch (cmd) {
    case SX_ACCESS_CMD_CREATE:
        __fill_table_meta_tunnel_keys(key_data_p, &table_meta_tunnel_key_list);
        __fill_table_meta_tunnel_params(action_data_p, &table_meta_tunnel_param_list);
        flextrum_action = __get_table_meta_tunnel_fx_action(action_data_p->action);
        return __sx_table_meta_tunnel_entry_create(
                &handle,
                &table_meta_tunnel_key_list,
                &table_meta_tunnel_param_list,
                flextrum_action,
                (uint32_t*)&key_data_p->priority);
        break;
    case SX_ACCESS_CMD_DELETE:
        __fill_table_meta_tunnel_keys(key_data_p, &table_meta_tunnel_key_list);
        return __sx_table_meta_tunnel_entry_delete(&handle, &table_meta_tunnel_key_list, key_data_p->priority);
        break;
    default:
        SX_LOG_ERR("Invalid parameter cmd\n");
        return SX_STATUS_PARAM_ERROR;
    }
    return SX_STATUS_SUCCESS;
}

