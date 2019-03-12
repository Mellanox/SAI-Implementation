// stub functions
// and test main

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_flex_acl.h>
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_lib_flex_acl.h>
#include <sx/sdk/sx_port.h>
#include <sx/sdk/sx_router.h>

#include "fx_base_api.h"

#ifdef TEST_MAIN
int main(int argc, char *const argv[]) {
    uint16_t ports[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint16_t rifs[16] = {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116};

    fx_handle_t handle;
    fx_init(&handle);
    // fx_extern_init(handle);
    fx_pipe_create(handle, FX_IN_PORT, &ports[0], 16);
    fx_pipe_create(handle, FX_IN_RIF, &rifs[0], 32);
    fx_pipe_create(handle, FX_OUT_RIF, &rifs[0], 32);
    fx_pipe_create(handle, FX_OUT_PORT, &ports[0], 16);
    // fx_extern_deinit(handle);
    fx_deinit(handle);
    return 0;
}
#endif

sx_status_t sx_api_acl_custom_bytes_set(sx_api_handle_t                             handle,
                                        sx_access_cmd_t                             cmd,
                                        const sx_acl_custom_bytes_set_attributes_t *custom_bytes_set_attributes,
                                        sx_acl_key_t                               *custom_bytes_set_key_id_p,
                                        uint32_t                                   *custom_bytes_set_key_id_cnt_p)
{
    if (custom_bytes_set_key_id_cnt_p && custom_bytes_set_key_id_p) {
        for (int i =0; i < *custom_bytes_set_key_id_cnt_p; i++) {
            sx_acl_key_t *key = custom_bytes_set_key_id_p + i;
            if (*key == FLEX_ACL_KEY_INVALID) {
                *key = (sx_acl_key_t)(FLEX_ACL_KEY_CUSTOM_BYTES_START + i);
            }
        }
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_acl_flex_key_set(const sx_api_handle_t handle,
                                    const sx_access_cmd_t cmd,
                                    const sx_acl_key_t  * key_list_p,
                                    const uint32_t        key_count,
                                    sx_acl_key_type_t   * key_handle_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }



sx_status_t sx_api_acl_flex_rules_get(const sx_api_handle_t    handle,
                                      const sx_acl_region_id_t region_id,
                                      sx_acl_rule_offset_t    *offsets_list_p,
                                      sx_flex_acl_flex_rule_t *rules_list_p,
                                      uint32_t               * rules_cnt_p)
{
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;
}


sx_status_t sx_api_acl_flex_rules_set(const sx_api_handle_t          handle,
                                      const sx_access_cmd_t          cmd,
                                      const sx_acl_region_id_t       region_id,
                                      sx_acl_rule_offset_t          *offsets_list_p,
                                      const sx_flex_acl_flex_rule_t *rules_list_p,
                                      const uint32_t                 rules_cnt)
{
    static sx_acl_rule_offset_t rule_offset = 0;
    if (cmd == SX_ACCESS_CMD_SET && rules_cnt > 0) {
        *offsets_list_p = ++rule_offset;
    }
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;

}

sx_status_t sx_api_acl_group_set(const sx_api_handle_t    handle,
                                 const sx_access_cmd_t    cmd,
                                 const sx_acl_direction_t acl_direction,
                                 const sx_acl_id_t       *acl_id_list_p,
                                 const uint32_t           acl_id_cnt,
                                 sx_acl_id_t             *group_id_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_acl_port_bind_set(const sx_api_handle_t  handle,
                                     const sx_access_cmd_t  cmd,
                                     const sx_port_log_id_t log_port,
                                     const sx_acl_id_t      acl_id)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_acl_region_set(const sx_api_handle_t      handle,
                                  const sx_access_cmd_t      cmd,
                                  const sx_acl_key_type_t    key_type,
                                  const sx_acl_action_type_t action_type,
                                  const sx_acl_size_t        region_size,
                                  sx_acl_region_id_t        *region_id_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_acl_rif_bind_set(const sx_api_handle_t handle,
                                    const sx_access_cmd_t cmd,
                                    const sx_rif_id_t     rif_id,
                                    const sx_acl_id_t     acl_id)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_acl_set(const sx_api_handle_t        handle,
                           const sx_access_cmd_t        cmd,
                           const sx_acl_type_t          acl_type,
                           const sx_acl_direction_t     acl_direction,
                           const sx_acl_region_group_t *acl_region_group_p,
                           sx_acl_id_t                 *acl_id_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_flow_counter_clear_set(const sx_api_handle_t      handle,
                                          const sx_flow_counter_id_t counter_id)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_flow_counter_get(const sx_api_handle_t      handle,
                                    const sx_access_cmd_t      cmd,
                                    const sx_flow_counter_id_t counter_id,
                                    sx_flow_counter_set_t     *counter_set_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_flow_counter_set(const sx_api_handle_t        handle,
                                    const sx_access_cmd_t        cmd,
                                    const sx_flow_counter_type_t counter_type,
                                    sx_flow_counter_id_t        *counter_id_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_open(sx_log_cb_t      logging_cb,
                        sx_api_handle_t *handle)
{
    if (handle != 0) {
        *handle = -1;
        return SX_STATUS_SUCCESS;
    }
    return SX_STATUS_ERROR;
}

sx_status_t sx_api_close(sx_api_handle_t *handle)
{
    return (handle == 0 || *handle == 0) ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_port_device_get(const sx_api_handle_t handle,
                                   const sx_device_id_t  device_id,
                                   const sx_swid_t       swid,
                                   sx_port_attributes_t *port_attributes_list_p,
                                   uint32_t             *port_cnt_p)
{
    if (port_attributes_list_p != 0 && port_cnt_p != 0) {
        for (int i=0; i<*port_cnt_p; i++) {
            port_attributes_list_p[i].log_port = (i << 16) | i;
            port_attributes_list_p[i].port_mode = SX_PORT_MODE_EXTERNAL;
            port_attributes_list_p[i].port_mapping.module_port = (*port_cnt_p)-i-1;
            port_attributes_list_p[i].port_mapping.local_port = i;
        }
    }
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_vport_set(const sx_api_handle_t  handle,
                                  const sx_access_cmd_t  cmd,
                                  const sx_port_log_id_t log_port,
                                  const sx_vlan_id_t     vlan_id,
                                  sx_port_log_id_t      *log_vport_p)
{
    if (log_vport_p != 0) {
        *log_vport_p = vlan_id + 100;
    }
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_vport_get(const sx_api_handle_t  handle,
                                  const sx_port_log_id_t log_port,
                                  sx_vlan_id_t          *vlan_id_list_p,
                                  uint32_t              *vport_vlan_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_router_interface_iter_get(const sx_api_handle_t        handle,
                                             const sx_access_cmd_t        cmd,
                                             const sx_router_interface_t *rif_key_p,
                                             const sx_rif_filter_t       *filter_p,
                                             sx_router_interface_t       *rif_list_p,
                                             uint32_t                    *rif_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

// Behavior copied from actual SDK. This function deallocates
sx_status_t sx_lib_flex_acl_rule_deinit(sx_flex_acl_flex_rule_t *rule)
{
    if (rule == NULL) return SX_STATUS_PARAM_ERROR;
    if (NULL != rule->key_desc_list_p) {
        free(rule->key_desc_list_p);
        rule->key_desc_list_p = NULL;
        rule->key_desc_count = 0;
    }
    if (NULL != rule->action_list_p) {
        free(rule->action_list_p);
        rule->action_list_p = NULL;
        rule->action_count = 0;
    }
    return SX_STATUS_SUCCESS;
}

// Behavior copied from actual SDK. This function allocates
sx_status_t sx_lib_flex_acl_rule_init(const sx_acl_key_type_t  key_handle,
                                      uint32_t                 num_of_actions,
                                      sx_flex_acl_flex_rule_t *rule)
{
    if (rule == NULL) return SX_STATUS_PARAM_ERROR;

    /* allocate place for keys */
    uint32_t    keys_count = 20;
    rule->key_desc_list_p = (sx_flex_acl_key_desc_t*)malloc(
        sizeof(sx_flex_acl_key_desc_t) * keys_count);
    if (NULL == rule->key_desc_list_p) {
        // SX_LOG(SX_LOG_ERROR, "Failed memory allocation for flex rule keys\n");
        return SX_STATUS_MEMORY_ERROR;
    }
    memset(rule->key_desc_list_p, 0, sizeof(sx_flex_acl_key_desc_t) * keys_count);
    rule->key_desc_count = keys_count;

    /* allocate place for actions */
    rule->action_list_p = (sx_flex_acl_flex_action_t*)malloc(
        sizeof(sx_flex_acl_flex_action_t) * num_of_actions);
    if (NULL == rule->action_list_p) {
        // X_LOG(SX_LOG_ERROR, "Failed memory allocation for flex rule actions\n");
        free(rule->key_desc_list_p);
        return SX_STATUS_MEMORY_ERROR;
    }
    memset(rule->action_list_p, 0, sizeof(sx_flex_acl_flex_action_t) * num_of_actions);
    rule->action_count = num_of_actions;

    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_vlan_set(const sx_api_handle_t handle,
        const sx_access_cmd_t cmd,
        const sx_swid_t       swid,
        sx_vlan_id_t         *vlan_list_p,
        uint32_t             *vlan_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_vlan_get(const sx_api_handle_t handle,
                            const sx_swid_t       swid,
                            sx_vlan_id_t         *vlan_list_p,
                            uint32_t             *vlan_cnt_p)
{
    if (vlan_cnt_p != 0 && *vlan_cnt_p == 0) {
        *vlan_cnt_p = 4096;
    }
    else if (vlan_cnt_p != 0) {
        for (int i = 0; i < *vlan_cnt_p; i++) {
            vlan_list_p[i] = i + 1;
        }
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_vlan_ports_set(const sx_api_handle_t  handle,
        const sx_access_cmd_t  cmd,
        const sx_swid_t        swid,
        const sx_vid_t         vid,
        const sx_vlan_ports_t *vlan_port_list_p,
        const uint32_t         port_cnt)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_vlan_ports_get(const sx_api_handle_t handle,
                                  const sx_swid_t       swid,
                                  const sx_vid_t        vid,
                                  sx_vlan_ports_t      *vlan_port_list_p,
                                  uint32_t             *port_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_vlan_port_pvid_set(const sx_api_handle_t  handle,
                                      const sx_access_cmd_t  cmd,
                                      const sx_port_log_id_t log_port,
                                      const sx_vid_t         pvid)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_vlan_port_pvid_get(const sx_api_handle_t  handle,
                                      const sx_port_log_id_t log_port,
                                      sx_vid_t              *pvid_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_set(const sx_api_handle_t         handle,
        const sx_access_cmd_t         cmd,
        const sx_router_attributes_t *router_attr,
        sx_router_id_t               *vrid)
{
    static uint32_t vrf = 0;
    if (handle != 0 && vrid != 0) {
        (*vrid) = ++vrf;
        return SX_STATUS_SUCCESS;
    }
    else {
        return SX_STATUS_ERROR;
    }
}

sx_status_t sx_api_router_init_set(const sx_api_handle_t              handle,
        const sx_router_general_param_t   *general_params_p,
        const sx_router_resources_param_t *router_resource_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_deinit_set(const sx_api_handle_t handle)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_interface_set(const sx_api_handle_t              handle,
                                        const sx_access_cmd_t              cmd,
                                        const sx_router_id_t               vrid,
                                        const sx_router_interface_param_t *ifc_p,
                                        const sx_interface_attributes_t   *ifc_attr_p,
                                        sx_router_interface_t             *rif_p)
{
    static uint32_t grif = 0;
    if (handle != 0 && rif_p != 0) {
        (*rif_p) = ++grif;
        return SX_STATUS_SUCCESS;
    }
    else {
        return SX_STATUS_ERROR;
    }
}

sx_status_t sx_api_router_interface_state_set(const sx_api_handle_t              handle,
                                              const sx_router_interface_t        rif,
                                              const sx_router_interface_state_t *rif_state_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_interface_mac_set(const sx_api_handle_t       handle,
                                            const sx_access_cmd_t       cmd,
                                            const sx_router_interface_t rif,
                                            const sx_mac_addr_t        *mac_addr_list_p,
                                            const uint32_t              mac_addr_cnt)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_router_counter_set(const sx_api_handle_t   handle,
                                      const sx_access_cmd_t   cmd,
                                      sx_router_counter_id_t *counter_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_counter_get(const sx_api_handle_t        handle,
                                      const sx_access_cmd_t        cmd,
                                      const sx_router_counter_id_t counter,
                                      sx_router_counter_set_t     *counter_set_p)
{
    counter_set_p->router_egress_good_unicast_packets = -1;
    counter_set_p->router_egress_good_unicast_bytes = -1;
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_router_interface_counter_bind_set(const sx_api_handle_t        handle,
                                                     const sx_access_cmd_t        cmd,
                                                     const sx_router_counter_id_t counter,
                                                     const sx_router_interface_t  rif)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_router_interface_mac_get(const sx_api_handle_t       handle,
                                            const sx_router_interface_t rif,
                                            sx_mac_addr_t              *mac_addr_list_p,
                                            uint32_t                  * mac_addr_cnt_p)
{
    *mac_addr_cnt_p = -1;
    return SX_STATUS_SUCCESS;
}


sx_status_t sx_api_router_neigh_set(const sx_api_handle_t       handle,
                                    const sx_access_cmd_t       cmd,
                                    const sx_router_interface_t rif,
                                    const sx_ip_addr_t         *ip_addr_p,
                                    const sx_neigh_data_t      *neigh_data_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_port_swid_port_list_get(const sx_api_handle_t handle,
        const sx_swid_t       swid,
        sx_port_log_id_t     *log_port_list_p,
        uint32_t             *port_cnt_p)
{
    if (log_port_list_p == NULL) {
        *port_cnt_p = 32;
        return SX_STATUS_SUCCESS;
    }
    for (int i = 0; i < *port_cnt_p; i++) {
        log_port_list_p[i] = ((i+1) << 8) | (i+1);
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_device_base_mac_get(const sx_api_handle_t handle,
                                            const sx_device_id_t  device_id,
                                            sx_mac_addr_t        *base_mac_addr_p)
{
#ifdef __APPLE__
    base_mac_addr_p->octet[0] =  0x11;
    base_mac_addr_p->octet[1] =  0x22;
    base_mac_addr_p->octet[2] =  0x33;
    base_mac_addr_p->octet[3] =  0x44;
    base_mac_addr_p->octet[4] =  0x55;
    base_mac_addr_p->octet[5] =  0x66;
#endif
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_counter_cli_get(const sx_api_handle_t  handle,
                                        const sx_access_cmd_t  cmd,
                                        const sx_port_log_id_t log_port,
                                        sx_port_cntr_cli_t    *cntr_cli_p)
{
    static uint32_t ct = 0;
    if (cntr_cli_p != 0) {
        cntr_cli_p->port_tx_unicast = ct++;
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_counter_rfc_2819_get(const sx_api_handle_t    handle,
                                             const sx_access_cmd_t    cmd,
                                             const sx_port_log_id_t   log_port,
                                             sx_port_cntr_rfc_2819_t *cntr_rfc_2819_p)
{
    static uint32_t ct = 0;
    if (cntr_rfc_2819_p != 0) {
        cntr_rfc_2819_p->ether_stats_pkts = ct++;
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_counter_rfc_2863_get(const sx_api_handle_t    handle,
                                             const sx_access_cmd_t    cmd,
                                             const sx_port_log_id_t   log_port,
                                             sx_port_cntr_rfc_2863_t *cntr_rfc_2863_p)
{
    static uint32_t ct = 0;
    if (cntr_rfc_2863_p != 0) {
        cntr_rfc_2863_p->if_in_octets = ct*32;
        cntr_rfc_2863_p->if_out_octets = ct*32;
        cntr_rfc_2863_p->if_in_ucast_pkts = ct;
        cntr_rfc_2863_p->if_out_ucast_pkts = ct++;
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_router_ecmp_get(const sx_api_handle_t handle,
                                   const sx_ecmp_id_t    ecmp_id,
                                   sx_next_hop_t        *next_hop_list_p,
                                   uint32_t             *next_hop_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_router_ecmp_set(const sx_api_handle_t handle,
                                   const sx_access_cmd_t cmd,
                                   sx_ecmp_id_t         *ecmp_id_p,
                                   sx_next_hop_t        *next_hop_list_p,
                                   uint32_t             *next_hop_cnt_p)
{
    static uint32_t gecmp = 0;
    if (ecmp_id_p != 0) {
        (*ecmp_id_p) = ++gecmp;
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_router_ecmp_attributes_set(const sx_api_handle_t       handle,
                                              const sx_ecmp_id_t          ecmp_id,
                                              const sx_ecmp_attributes_t *attr_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_ecmp_port_hash_params_set(const sx_api_handle_t                     handle,
                                                    const sx_access_cmd_t                     cmd,
                                                    const sx_port_log_id_t                    log_port,
                                                    const sx_router_ecmp_port_hash_params_t  *ecmp_hash_params_p,
                                                    const sx_router_ecmp_hash_field_enable_t *hash_field_enable_list_p,
                                                    const uint32_t                            hash_field_enable_list_cnt,
                                                    const sx_router_ecmp_hash_field_t        *hash_field_list_p,
                                                    const uint32_t                            hash_field_list_cnt)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_router_uc_route_set(const sx_api_handle_t handle,
                                       const sx_access_cmd_t cmd,
                                       const sx_router_id_t  vrid,
                                       const sx_ip_prefix_t *network_addr,
                                       sx_uc_route_data_t   *uc_route_data_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_router_uc_route_get(const sx_api_handle_t     handle,
                                       const sx_access_cmd_t     cmd,
                                       const sx_router_id_t      vrid,
                                       const sx_ip_prefix_t     *network_addr,
                                       sx_uc_route_key_filter_t *filter_p,
                                       sx_uc_route_get_entry_t  *uc_route_get_entries_list_p,
                                       uint32_t                 *uc_route_get_entries_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_fdb_uc_mac_addr_set(const sx_api_handle_t        handle,
                                       const sx_access_cmd_t        cmd,
                                       const sx_swid_t              swid,
                                       sx_fdb_uc_mac_addr_params_t *mac_list_p,
                                       uint32_t                    *data_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_fdb_uc_count_get(const sx_api_handle_t handle,
                                    const sx_swid_t       swid,
                                    uint32_t             *data_cnt_p)
{
    *data_cnt_p = -1;
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_host_ifc_trap_group_set(const sx_api_handle_t             handle,
                                           const sx_swid_id_t                swid,
                                           const sx_trap_group_t             trap_group,
                                           const sx_trap_group_attributes_t* trap_group_attributes_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_host_ifc_trap_id_set(const sx_api_handle_t  handle,
                                        const sx_swid_t        swid,
                                        const sx_trap_id_t     trap_id,
                                        const sx_trap_group_t  trap_group,
                                        const sx_trap_action_t trap_action)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_host_ifc_trap_id_register_set(const sx_api_handle_t    handle,
                                                 const sx_access_cmd_t    cmd,
                                                 const sx_swid_t          swid,
                                                 const sx_trap_id_t       trap_id,
                                                 const sx_user_channel_t *user_channel_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_host_ifc_open(const sx_api_handle_t handle,
                                 sx_fd_t              *fd_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_host_ifc_close(const sx_api_handle_t handle,
                                  sx_fd_t              *fd_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_lib_host_ifc_recv(const sx_fd_t     *fd,
                                 void              *packet,
                                 uint32_t          *packet_size,
                                 sx_receive_info_t *receive_info)
{
    if (packet_size !=0) {
        *packet_size = 0;
    }
    return SX_STATUS_SUCCESS;
}

sx_status_t sx_api_mpls_init_set(const sx_api_handle_t           handle,
                                 const sx_mpls_general_params_t *general_params)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_mpls_ilm_init_set(const sx_api_handle_t        handle,
                                     const sx_access_cmd_t        cmd,
                                     const sx_mpls_ilm_table_id_t ilm_table)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_mpls_router_interface_attributes_set(const sx_api_handle_t                 handle,
                                                        const sx_router_interface_t           rif,
                                                        const sx_mpls_router_interface_attr_t rif_mpls_attr)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_mpls_in_segment_set(const sx_api_handle_t              handle,
                                       const sx_access_cmd_t              cmd,
                                       const sx_mpls_in_segment_key_t    *in_segment_key_p,
                                       const sx_mpls_in_segment_params_t *in_segment_params_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_mpls_in_segment_get(const sx_api_handle_t           handle,
                                       const sx_mpls_in_segment_key_t *in_segment_key_p,
                                       sx_mpls_in_segment_params_t    *in_segment_params_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


sx_status_t sx_api_mpls_deinit_set(const sx_api_handle_t handle)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_lib_host_ifc_unicast_ctrl_send(const sx_fd_t         * fd_p,
                                              const void            * packet_p,
                                              const uint32_t          packet_size,
                                              const sx_swid_t         swid,
                                              const sx_port_log_id_t  egress_log_port,
                                              const sx_cos_priority_t prio)
{ return fd_p == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_port_counter_ieee_802_dot_3_get(const sx_api_handle_t          handle,
                                                   const sx_access_cmd_t          cmd,
                                                   const sx_port_log_id_t         log_port,
                                                   sx_port_cntr_ieee_802_dot_3_t *cntr_ieee_802_dot_3_p)
{
    static uint32_t rx_bytes = 0;
    static uint32_t tx_bytes = 0;
    static uint32_t rx_pkt = 0;
    static uint32_t tx_pkt = 0;
    if (cntr_ieee_802_dot_3_p) {
        rx_pkt += 2;
        tx_pkt++;
        rx_bytes += 100;
        tx_bytes +=50;
        cntr_ieee_802_dot_3_p->a_frames_received_ok = rx_pkt;
        cntr_ieee_802_dot_3_p->a_frames_transmitted_ok = tx_pkt;
        cntr_ieee_802_dot_3_p->a_octets_received_ok = rx_bytes;
        cntr_ieee_802_dot_3_p->a_octets_transmitted_ok = tx_bytes;
    }
    return SX_STATUS_SUCCESS;
}

static sx_port_admin_state_t current_admin = SX_PORT_ADMIN_STATUS_UP;

sx_status_t sx_api_port_state_set(const sx_api_handle_t       handle,
                                  const sx_port_log_id_t      log_port,
                                  const sx_port_admin_state_t admin_state)
{
    current_admin = admin_state;
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_state_get(const sx_api_handle_t   handle,
                                  const sx_port_log_id_t  log_port,
                                  sx_port_oper_state_t   *oper_state_p,
                                  sx_port_admin_state_t  *admin_state_p,
                                  sx_port_module_state_t *module_state_p)
{
    if (admin_state_p != 0) {
        *admin_state_p = current_admin;
    }
    if (oper_state_p != 0) {
        *oper_state_p = (current_admin == SX_PORT_ADMIN_STATUS_UP) ? SX_PORT_OPER_STATUS_UP : SX_PORT_OPER_STATUS_DOWN;
    }
    return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS;
}

sx_status_t sx_api_port_phy_mode_set(const sx_api_handle_t     handle,
                                     const sx_port_log_id_t    log_port,
                                     const sx_port_phy_speed_t speed,
                                     const sx_port_phy_mode_t  admin_mode)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_mpls_in_segment_iter_get(const sx_api_handle_t             handle,
                                            const sx_access_cmd_t             cmd,
                                            const sx_mpls_in_segment_key_t   *in_segment_key_p,
                                            const sx_in_segment_key_filter_t *filter_p,
                                            sx_mpls_in_segment_key_t         *in_segment_key_list_p,
                                            uint32_t                         *in_segment_get_entries_cnt_p)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }

sx_status_t sx_api_lag_port_group_set(const sx_api_handle_t   handle,
                                      const sx_access_cmd_t   cmd,
                                      const sx_swid_t         swid,
                                      sx_port_log_id_t       *lag_log_port_p,
                                      const sx_port_log_id_t *log_port_list_p,
                                      const uint32_t          log_port_cnt)
{ return handle == 0 ? SX_STATUS_ERROR : SX_STATUS_SUCCESS; }


#ifdef __cplusplus
}
#endif
