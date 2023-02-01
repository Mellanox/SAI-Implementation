%{
    sai_status_t sai_get_switch_api(sai_switch_api_t* out)
    {
        sai_switch_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SWITCH, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_port_api(sai_port_api_t* out)
    {
        sai_port_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_PORT, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_fdb_api(sai_fdb_api_t* out)
    {
        sai_fdb_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_FDB, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_vlan_api(sai_vlan_api_t* out)
    {
        sai_vlan_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_VLAN, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_virtual_router_api(sai_virtual_router_api_t* out)
    {
        sai_virtual_router_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_VIRTUAL_ROUTER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_route_api(sai_route_api_t* out)
    {
        sai_route_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_ROUTE, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_next_hop_api(sai_next_hop_api_t* out)
    {
        sai_next_hop_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_NEXT_HOP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_next_hop_group_api(sai_next_hop_group_api_t* out)
    {
        sai_next_hop_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_NEXT_HOP_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_router_interface_api(sai_router_interface_api_t* out)
    {
        sai_router_interface_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_ROUTER_INTERFACE, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_neighbor_api(sai_neighbor_api_t* out)
    {
        sai_neighbor_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_NEIGHBOR, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_acl_api(sai_acl_api_t* out)
    {
        sai_acl_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_ACL, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_hostif_api(sai_hostif_api_t* out)
    {
        sai_hostif_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_HOSTIF, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_mirror_api(sai_mirror_api_t* out)
    {
        sai_mirror_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_MIRROR, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_samplepacket_api(sai_samplepacket_api_t* out)
    {
        sai_samplepacket_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SAMPLEPACKET, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_stp_api(sai_stp_api_t* out)
    {
        sai_stp_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_STP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_lag_api(sai_lag_api_t* out)
    {
        sai_lag_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_LAG, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_policer_api(sai_policer_api_t* out)
    {
        sai_policer_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_POLICER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_wred_api(sai_wred_api_t* out)
    {
        sai_wred_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_WRED, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_qos_map_api(sai_qos_map_api_t* out)
    {
        sai_qos_map_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_QOS_MAP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_queue_api(sai_queue_api_t* out)
    {
        sai_queue_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_QUEUE, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_scheduler_api(sai_scheduler_api_t* out)
    {
        sai_scheduler_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SCHEDULER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_scheduler_group_api(sai_scheduler_group_api_t* out)
    {
        sai_scheduler_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SCHEDULER_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_buffer_api(sai_buffer_api_t* out)
    {
        sai_buffer_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_BUFFER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_hash_api(sai_hash_api_t* out)
    {
        sai_hash_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_HASH, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_udf_api(sai_udf_api_t* out)
    {
        sai_udf_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_UDF, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_tunnel_api(sai_tunnel_api_t* out)
    {
        sai_tunnel_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_TUNNEL, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_l2mc_api(sai_l2mc_api_t* out)
    {
        sai_l2mc_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_L2MC, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_ipmc_api(sai_ipmc_api_t* out)
    {
        sai_ipmc_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_IPMC, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_rpf_group_api(sai_rpf_group_api_t* out)
    {
        sai_rpf_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_RPF_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_l2mc_group_api(sai_l2mc_group_api_t* out)
    {
        sai_l2mc_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_L2MC_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_ipmc_group_api(sai_ipmc_group_api_t* out)
    {
        sai_ipmc_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_IPMC_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_mcast_fdb_api(sai_mcast_fdb_api_t* out)
    {
        sai_mcast_fdb_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_MCAST_FDB, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_bridge_api(sai_bridge_api_t* out)
    {
        sai_bridge_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_BRIDGE, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_tam_api(sai_tam_api_t* out)
    {
        sai_tam_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_TAM, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_srv6_api(sai_srv6_api_t* out)
    {
        sai_srv6_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SRV6, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_mpls_api(sai_mpls_api_t* out)
    {
        sai_mpls_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_MPLS, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_dtel_api(sai_dtel_api_t* out)
    {
        sai_dtel_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_DTEL, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_bfd_api(sai_bfd_api_t* out)
    {
        sai_bfd_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_BFD, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_isolation_group_api(sai_isolation_group_api_t* out)
    {
        sai_isolation_group_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_ISOLATION_GROUP, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_nat_api(sai_nat_api_t* out)
    {
        sai_nat_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_NAT, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_counter_api(sai_counter_api_t* out)
    {
        sai_counter_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_COUNTER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_debug_counter_api(sai_debug_counter_api_t* out)
    {
        sai_debug_counter_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_DEBUG_COUNTER, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_macsec_api(sai_macsec_api_t* out)
    {
        sai_macsec_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_MACSEC, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_system_port_api(sai_system_port_api_t* out)
    {
        sai_system_port_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_SYSTEM_PORT, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_my_mac_api(sai_my_mac_api_t* out)
    {
        sai_my_mac_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_MY_MAC, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_ipsec_api(sai_ipsec_api_t* out)
    {
        sai_ipsec_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_IPSEC, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_generic_programmable_api(sai_generic_programmable_api_t* out)
    {
        sai_generic_programmable_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_GENERIC_PROGRAMMABLE, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
    sai_status_t sai_get_bmtor_api(sai_bmtor_api_t* out)
    {
        sai_bmtor_api_t* api;
        sai_status_t status = sai_api_query((sai_api_t)SAI_API_BMTOR, (void**)&api);
        if (status == SAI_STATUS_SUCCESS)
        {
            *out = *api;
        }
        return status;
    }
%}
sai_status_t sai_get_switch_api(sai_switch_api_t* out);
sai_status_t sai_get_port_api(sai_port_api_t* out);
sai_status_t sai_get_fdb_api(sai_fdb_api_t* out);
sai_status_t sai_get_vlan_api(sai_vlan_api_t* out);
sai_status_t sai_get_virtual_router_api(sai_virtual_router_api_t* out);
sai_status_t sai_get_route_api(sai_route_api_t* out);
sai_status_t sai_get_next_hop_api(sai_next_hop_api_t* out);
sai_status_t sai_get_next_hop_group_api(sai_next_hop_group_api_t* out);
sai_status_t sai_get_router_interface_api(sai_router_interface_api_t* out);
sai_status_t sai_get_neighbor_api(sai_neighbor_api_t* out);
sai_status_t sai_get_acl_api(sai_acl_api_t* out);
sai_status_t sai_get_hostif_api(sai_hostif_api_t* out);
sai_status_t sai_get_mirror_api(sai_mirror_api_t* out);
sai_status_t sai_get_samplepacket_api(sai_samplepacket_api_t* out);
sai_status_t sai_get_stp_api(sai_stp_api_t* out);
sai_status_t sai_get_lag_api(sai_lag_api_t* out);
sai_status_t sai_get_policer_api(sai_policer_api_t* out);
sai_status_t sai_get_wred_api(sai_wred_api_t* out);
sai_status_t sai_get_qos_map_api(sai_qos_map_api_t* out);
sai_status_t sai_get_queue_api(sai_queue_api_t* out);
sai_status_t sai_get_scheduler_api(sai_scheduler_api_t* out);
sai_status_t sai_get_scheduler_group_api(sai_scheduler_group_api_t* out);
sai_status_t sai_get_buffer_api(sai_buffer_api_t* out);
sai_status_t sai_get_hash_api(sai_hash_api_t* out);
sai_status_t sai_get_udf_api(sai_udf_api_t* out);
sai_status_t sai_get_tunnel_api(sai_tunnel_api_t* out);
sai_status_t sai_get_l2mc_api(sai_l2mc_api_t* out);
sai_status_t sai_get_ipmc_api(sai_ipmc_api_t* out);
sai_status_t sai_get_rpf_group_api(sai_rpf_group_api_t* out);
sai_status_t sai_get_l2mc_group_api(sai_l2mc_group_api_t* out);
sai_status_t sai_get_ipmc_group_api(sai_ipmc_group_api_t* out);
sai_status_t sai_get_mcast_fdb_api(sai_mcast_fdb_api_t* out);
sai_status_t sai_get_bridge_api(sai_bridge_api_t* out);
sai_status_t sai_get_tam_api(sai_tam_api_t* out);
sai_status_t sai_get_srv6_api(sai_srv6_api_t* out);
sai_status_t sai_get_mpls_api(sai_mpls_api_t* out);
sai_status_t sai_get_dtel_api(sai_dtel_api_t* out);
sai_status_t sai_get_bfd_api(sai_bfd_api_t* out);
sai_status_t sai_get_isolation_group_api(sai_isolation_group_api_t* out);
sai_status_t sai_get_nat_api(sai_nat_api_t* out);
sai_status_t sai_get_counter_api(sai_counter_api_t* out);
sai_status_t sai_get_debug_counter_api(sai_debug_counter_api_t* out);
sai_status_t sai_get_macsec_api(sai_macsec_api_t* out);
sai_status_t sai_get_system_port_api(sai_system_port_api_t* out);
sai_status_t sai_get_my_mac_api(sai_my_mac_api_t* out);
sai_status_t sai_get_ipsec_api(sai_ipsec_api_t* out);
sai_status_t sai_get_generic_programmable_api(sai_generic_programmable_api_t* out);
sai_status_t sai_get_bmtor_api(sai_bmtor_api_t* out);
%include "saitypes.h"
typedef struct _sai_switch_api_t {
    sai_status_t create_switch(_Out_ sai_object_id_t *switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_switch(_In_ sai_object_id_t switch_id);
    sai_status_t set_switch_attribute(_In_ sai_object_id_t switch_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_switch_attribute(_In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_switch_stats(_In_ sai_object_id_t switch_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_switch_stats_ext(_In_ sai_object_id_t switch_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_switch_stats(_In_ sai_object_id_t switch_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t switch_mdio_read(_In_ sai_object_id_t switch_id, _In_ uint32_t device_addr, _In_ uint32_t start_reg_addr, _In_ uint32_t number_of_registers, _Out_ uint32_t *reg_val);
    sai_status_t switch_mdio_write(_In_ sai_object_id_t switch_id, _In_ uint32_t device_addr, _In_ uint32_t start_reg_addr, _In_ uint32_t number_of_registers, _In_ const uint32_t *reg_val);
    sai_status_t create_switch_tunnel(_Out_ sai_object_id_t *switch_tunnel_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_switch_tunnel(_In_ sai_object_id_t switch_tunnel_id);
    sai_status_t set_switch_tunnel_attribute(_In_ sai_object_id_t switch_tunnel_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_switch_tunnel_attribute(_In_ sai_object_id_t switch_tunnel_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t switch_mdio_cl22_read(_In_ sai_object_id_t switch_id, _In_ uint32_t device_addr, _In_ uint32_t start_reg_addr, _In_ uint32_t number_of_registers, _Out_ uint32_t *reg_val);
    sai_status_t switch_mdio_cl22_write(_In_ sai_object_id_t switch_id, _In_ uint32_t device_addr, _In_ uint32_t start_reg_addr, _In_ uint32_t number_of_registers, _In_ const uint32_t *reg_val);
} sai_switch_api_t;

typedef struct _sai_port_api_t {
    sai_status_t create_port(_Out_ sai_object_id_t *port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_port(_In_ sai_object_id_t port_id);
    sai_status_t set_port_attribute(_In_ sai_object_id_t port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_port_attribute(_In_ sai_object_id_t port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_port_stats(_In_ sai_object_id_t port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_port_stats_ext(_In_ sai_object_id_t port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_port_stats(_In_ sai_object_id_t port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t clear_port_all_stats(_In_ sai_object_id_t port_id);
    sai_status_t create_port_pool(_Out_ sai_object_id_t *port_pool_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_port_pool(_In_ sai_object_id_t port_pool_id);
    sai_status_t set_port_pool_attribute(_In_ sai_object_id_t port_pool_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_port_pool_attribute(_In_ sai_object_id_t port_pool_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_port_pool_stats(_In_ sai_object_id_t port_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_port_pool_stats_ext(_In_ sai_object_id_t port_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_port_pool_stats(_In_ sai_object_id_t port_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_port_connector(_Out_ sai_object_id_t *port_connector_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_port_connector(_In_ sai_object_id_t port_connector_id);
    sai_status_t set_port_connector_attribute(_In_ sai_object_id_t port_connector_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_port_connector_attribute(_In_ sai_object_id_t port_connector_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_port_serdes(_Out_ sai_object_id_t *port_serdes_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_port_serdes(_In_ sai_object_id_t port_serdes_id);
    sai_status_t set_port_serdes_attribute(_In_ sai_object_id_t port_serdes_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_port_serdes_attribute(_In_ sai_object_id_t port_serdes_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_ports(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_ports(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_ports_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_ports_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_port_api_t;

typedef struct _sai_fdb_api_t {
    sai_status_t create_fdb_entry(_In_ const sai_fdb_entry_t *fdb_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_fdb_entry(_In_ const sai_fdb_entry_t *fdb_entry);
    sai_status_t set_fdb_entry_attribute(_In_ const sai_fdb_entry_t *fdb_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_fdb_entry_attribute(_In_ const sai_fdb_entry_t *fdb_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t flush_fdb_entries(_In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t create_fdb_entries(_In_ uint32_t object_count, _In_ const sai_fdb_entry_t *fdb_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_fdb_entries(_In_ uint32_t object_count, _In_ const sai_fdb_entry_t *fdb_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_fdb_entries_attribute(_In_ uint32_t object_count, _In_ const sai_fdb_entry_t *fdb_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_fdb_entries_attribute(_In_ uint32_t object_count, _In_ const sai_fdb_entry_t *fdb_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_fdb_api_t;

typedef struct _sai_vlan_api_t {
    sai_status_t create_vlan(_Out_ sai_object_id_t *vlan_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_vlan(_In_ sai_object_id_t vlan_id);
    sai_status_t set_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_vlan_member(_Out_ sai_object_id_t *vlan_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_vlan_member(_In_ sai_object_id_t vlan_member_id);
    sai_status_t set_vlan_member_attribute(_In_ sai_object_id_t vlan_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_vlan_member_attribute(_In_ sai_object_id_t vlan_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_vlan_members(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_vlan_members(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_vlan_stats(_In_ sai_object_id_t vlan_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_vlan_stats_ext(_In_ sai_object_id_t vlan_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_vlan_stats(_In_ sai_object_id_t vlan_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_vlan_api_t;

typedef struct _sai_virtual_router_api_t {
    sai_status_t create_virtual_router(_Out_ sai_object_id_t *virtual_router_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_virtual_router(_In_ sai_object_id_t virtual_router_id);
    sai_status_t set_virtual_router_attribute(_In_ sai_object_id_t virtual_router_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_virtual_router_attribute(_In_ sai_object_id_t virtual_router_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_virtual_router_api_t;

typedef struct _sai_route_api_t {
    sai_status_t create_route_entry(_In_ const sai_route_entry_t *route_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_route_entry(_In_ const sai_route_entry_t *route_entry);
    sai_status_t set_route_entry_attribute(_In_ const sai_route_entry_t *route_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_route_entry_attribute(_In_ const sai_route_entry_t *route_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_route_entries(_In_ uint32_t object_count, _In_ const sai_route_entry_t *route_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_route_entries(_In_ uint32_t object_count, _In_ const sai_route_entry_t *route_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_route_entries_attribute(_In_ uint32_t object_count, _In_ const sai_route_entry_t *route_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_route_entries_attribute(_In_ uint32_t object_count, _In_ const sai_route_entry_t *route_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_route_api_t;

typedef struct _sai_next_hop_api_t {
    sai_status_t create_next_hop(_Out_ sai_object_id_t *next_hop_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_next_hop(_In_ sai_object_id_t next_hop_id);
    sai_status_t set_next_hop_attribute(_In_ sai_object_id_t next_hop_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_next_hop_attribute(_In_ sai_object_id_t next_hop_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_next_hop_api_t;

typedef struct _sai_next_hop_group_api_t {
    sai_status_t create_next_hop_group(_Out_ sai_object_id_t *next_hop_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_next_hop_group(_In_ sai_object_id_t next_hop_group_id);
    sai_status_t set_next_hop_group_attribute(_In_ sai_object_id_t next_hop_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_next_hop_group_attribute(_In_ sai_object_id_t next_hop_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_next_hop_group_member(_Out_ sai_object_id_t *next_hop_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_next_hop_group_member(_In_ sai_object_id_t next_hop_group_member_id);
    sai_status_t set_next_hop_group_member_attribute(_In_ sai_object_id_t next_hop_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_next_hop_group_member_attribute(_In_ sai_object_id_t next_hop_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_next_hop_group_members(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_next_hop_group_members(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t create_next_hop_group_map(_Out_ sai_object_id_t *next_hop_group_map_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_next_hop_group_map(_In_ sai_object_id_t next_hop_group_map_id);
    sai_status_t set_next_hop_group_map_attribute(_In_ sai_object_id_t next_hop_group_map_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_next_hop_group_map_attribute(_In_ sai_object_id_t next_hop_group_map_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_next_hop_group_members_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_next_hop_group_members_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_next_hop_group_api_t;

typedef struct _sai_router_interface_api_t {
    sai_status_t create_router_interface(_Out_ sai_object_id_t *router_interface_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_router_interface(_In_ sai_object_id_t router_interface_id);
    sai_status_t set_router_interface_attribute(_In_ sai_object_id_t router_interface_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_router_interface_attribute(_In_ sai_object_id_t router_interface_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_router_interface_stats(_In_ sai_object_id_t router_interface_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_router_interface_stats_ext(_In_ sai_object_id_t router_interface_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_router_interface_stats(_In_ sai_object_id_t router_interface_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_router_interface_api_t;

typedef struct _sai_neighbor_api_t {
    sai_status_t create_neighbor_entry(_In_ const sai_neighbor_entry_t *neighbor_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_neighbor_entry(_In_ const sai_neighbor_entry_t *neighbor_entry);
    sai_status_t set_neighbor_entry_attribute(_In_ const sai_neighbor_entry_t *neighbor_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_neighbor_entry_attribute(_In_ const sai_neighbor_entry_t *neighbor_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t remove_all_neighbor_entries(_In_ sai_object_id_t switch_id);
    sai_status_t create_neighbor_entries(_In_ uint32_t object_count, _In_ const sai_neighbor_entry_t *neighbor_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_neighbor_entries(_In_ uint32_t object_count, _In_ const sai_neighbor_entry_t *neighbor_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_neighbor_entries_attribute(_In_ uint32_t object_count, _In_ const sai_neighbor_entry_t *neighbor_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_neighbor_entries_attribute(_In_ uint32_t object_count, _In_ const sai_neighbor_entry_t *neighbor_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_neighbor_api_t;

typedef struct _sai_acl_api_t {
    sai_status_t create_acl_table(_Out_ sai_object_id_t *acl_table_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_table(_In_ sai_object_id_t acl_table_id);
    sai_status_t set_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_acl_entry(_Out_ sai_object_id_t *acl_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_entry(_In_ sai_object_id_t acl_entry_id);
    sai_status_t set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_acl_counter(_Out_ sai_object_id_t *acl_counter_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_counter(_In_ sai_object_id_t acl_counter_id);
    sai_status_t set_acl_counter_attribute(_In_ sai_object_id_t acl_counter_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_counter_attribute(_In_ sai_object_id_t acl_counter_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_acl_range(_Out_ sai_object_id_t *acl_range_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_range(_In_ sai_object_id_t acl_range_id);
    sai_status_t set_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_acl_table_group(_Out_ sai_object_id_t *acl_table_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_table_group(_In_ sai_object_id_t acl_table_group_id);
    sai_status_t set_acl_table_group_attribute(_In_ sai_object_id_t acl_table_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_table_group_attribute(_In_ sai_object_id_t acl_table_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_acl_table_group_member(_Out_ sai_object_id_t *acl_table_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_acl_table_group_member(_In_ sai_object_id_t acl_table_group_member_id);
    sai_status_t set_acl_table_group_member_attribute(_In_ sai_object_id_t acl_table_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_acl_table_group_member_attribute(_In_ sai_object_id_t acl_table_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_acl_api_t;

typedef struct _sai_hostif_api_t {
    sai_status_t create_hostif(_Out_ sai_object_id_t *hostif_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hostif(_In_ sai_object_id_t hostif_id);
    sai_status_t set_hostif_attribute(_In_ sai_object_id_t hostif_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hostif_attribute(_In_ sai_object_id_t hostif_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_hostif_table_entry(_Out_ sai_object_id_t *hostif_table_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hostif_table_entry(_In_ sai_object_id_t hostif_table_entry_id);
    sai_status_t set_hostif_table_entry_attribute(_In_ sai_object_id_t hostif_table_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hostif_table_entry_attribute(_In_ sai_object_id_t hostif_table_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_hostif_trap_group(_Out_ sai_object_id_t *hostif_trap_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hostif_trap_group(_In_ sai_object_id_t hostif_trap_group_id);
    sai_status_t set_hostif_trap_group_attribute(_In_ sai_object_id_t hostif_trap_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hostif_trap_group_attribute(_In_ sai_object_id_t hostif_trap_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_hostif_trap(_Out_ sai_object_id_t *hostif_trap_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hostif_trap(_In_ sai_object_id_t hostif_trap_id);
    sai_status_t set_hostif_trap_attribute(_In_ sai_object_id_t hostif_trap_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hostif_trap_attribute(_In_ sai_object_id_t hostif_trap_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_hostif_user_defined_trap(_Out_ sai_object_id_t *hostif_user_defined_trap_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hostif_user_defined_trap(_In_ sai_object_id_t hostif_user_defined_trap_id);
    sai_status_t set_hostif_user_defined_trap_attribute(_In_ sai_object_id_t hostif_user_defined_trap_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hostif_user_defined_trap_attribute(_In_ sai_object_id_t hostif_user_defined_trap_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t recv_hostif_packet(_In_ sai_object_id_t hostif_id, _Inout_ sai_size_t *buffer_size, _Out_ void *buffer, _Inout_ uint32_t *attr_count, _Out_ sai_attribute_t *attr_list);
    sai_status_t send_hostif_packet(_In_ sai_object_id_t hostif_id, _In_ sai_size_t buffer_size, _In_ const void *buffer, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t allocate_hostif_packet(_In_ sai_object_id_t hostif_id, _In_ sai_size_t buffer_size, _Out_ void **buffer, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t free_hostif_packet(_In_ sai_object_id_t hostif_id, _Inout_ void *buffer);
} sai_hostif_api_t;

typedef struct _sai_mirror_api_t {
    sai_status_t create_mirror_session(_Out_ sai_object_id_t *mirror_session_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_mirror_session(_In_ sai_object_id_t mirror_session_id);
    sai_status_t set_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_mirror_api_t;

typedef struct _sai_samplepacket_api_t {
    sai_status_t create_samplepacket(_Out_ sai_object_id_t *samplepacket_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_samplepacket(_In_ sai_object_id_t samplepacket_id);
    sai_status_t set_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_samplepacket_api_t;

typedef struct _sai_stp_api_t {
    sai_status_t create_stp(_Out_ sai_object_id_t *stp_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_stp(_In_ sai_object_id_t stp_id);
    sai_status_t set_stp_attribute(_In_ sai_object_id_t stp_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_stp_attribute(_In_ sai_object_id_t stp_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_stp_port(_Out_ sai_object_id_t *stp_port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_stp_port(_In_ sai_object_id_t stp_port_id);
    sai_status_t set_stp_port_attribute(_In_ sai_object_id_t stp_port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_stp_port_attribute(_In_ sai_object_id_t stp_port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_stp_ports(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_stp_ports(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_stp_api_t;

typedef struct _sai_lag_api_t {
    sai_status_t create_lag(_Out_ sai_object_id_t *lag_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_lag(_In_ sai_object_id_t lag_id);
    sai_status_t set_lag_attribute(_In_ sai_object_id_t lag_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_lag_attribute(_In_ sai_object_id_t lag_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_lag_member(_Out_ sai_object_id_t *lag_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_lag_member(_In_ sai_object_id_t lag_member_id);
    sai_status_t set_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_lag_members(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_lag_members(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_lag_api_t;

typedef struct _sai_policer_api_t {
    sai_status_t create_policer(_Out_ sai_object_id_t *policer_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_policer(_In_ sai_object_id_t policer_id);
    sai_status_t set_policer_attribute(_In_ sai_object_id_t policer_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_policer_attribute(_In_ sai_object_id_t policer_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_policer_stats(_In_ sai_object_id_t policer_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_policer_stats_ext(_In_ sai_object_id_t policer_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_policer_stats(_In_ sai_object_id_t policer_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_policer_api_t;

typedef struct _sai_wred_api_t {
    sai_status_t create_wred(_Out_ sai_object_id_t *wred_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_wred(_In_ sai_object_id_t wred_id);
    sai_status_t set_wred_attribute(_In_ sai_object_id_t wred_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_wred_attribute(_In_ sai_object_id_t wred_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_wred_api_t;

typedef struct _sai_qos_map_api_t {
    sai_status_t create_qos_map(_Out_ sai_object_id_t *qos_map_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_qos_map(_In_ sai_object_id_t qos_map_id);
    sai_status_t set_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_qos_map_api_t;

typedef struct _sai_queue_api_t {
    sai_status_t create_queue(_Out_ sai_object_id_t *queue_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_queue(_In_ sai_object_id_t queue_id);
    sai_status_t set_queue_attribute(_In_ sai_object_id_t queue_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_queue_attribute(_In_ sai_object_id_t queue_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_queue_stats(_In_ sai_object_id_t queue_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_queue_stats_ext(_In_ sai_object_id_t queue_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_queue_stats(_In_ sai_object_id_t queue_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_queue_api_t;

typedef struct _sai_scheduler_api_t {
    sai_status_t create_scheduler(_Out_ sai_object_id_t *scheduler_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_scheduler(_In_ sai_object_id_t scheduler_id);
    sai_status_t set_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_scheduler_api_t;

typedef struct _sai_scheduler_group_api_t {
    sai_status_t create_scheduler_group(_Out_ sai_object_id_t *scheduler_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_scheduler_group(_In_ sai_object_id_t scheduler_group_id);
    sai_status_t set_scheduler_group_attribute(_In_ sai_object_id_t scheduler_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_scheduler_group_attribute(_In_ sai_object_id_t scheduler_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_scheduler_group_api_t;

typedef struct _sai_buffer_api_t {
    sai_status_t create_buffer_pool(_Out_ sai_object_id_t *buffer_pool_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_buffer_pool(_In_ sai_object_id_t buffer_pool_id);
    sai_status_t set_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_buffer_pool_stats(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_buffer_pool_stats_ext(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_buffer_pool_stats(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_ingress_priority_group(_Out_ sai_object_id_t *ingress_priority_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ingress_priority_group(_In_ sai_object_id_t ingress_priority_group_id);
    sai_status_t set_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_ingress_priority_group_stats_ext(_In_ sai_object_id_t ingress_priority_group_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_buffer_profile(_Out_ sai_object_id_t *buffer_profile_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id);
    sai_status_t set_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_buffer_api_t;

typedef struct _sai_hash_api_t {
    sai_status_t create_hash(_Out_ sai_object_id_t *hash_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_hash(_In_ sai_object_id_t hash_id);
    sai_status_t set_hash_attribute(_In_ sai_object_id_t hash_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_hash_attribute(_In_ sai_object_id_t hash_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_fine_grained_hash_field(_Out_ sai_object_id_t *fine_grained_hash_field_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_fine_grained_hash_field(_In_ sai_object_id_t fine_grained_hash_field_id);
    sai_status_t set_fine_grained_hash_field_attribute(_In_ sai_object_id_t fine_grained_hash_field_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_fine_grained_hash_field_attribute(_In_ sai_object_id_t fine_grained_hash_field_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_hash_api_t;

typedef struct _sai_udf_api_t {
    sai_status_t create_udf(_Out_ sai_object_id_t *udf_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_udf(_In_ sai_object_id_t udf_id);
    sai_status_t set_udf_attribute(_In_ sai_object_id_t udf_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_udf_attribute(_In_ sai_object_id_t udf_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_udf_match(_Out_ sai_object_id_t *udf_match_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_udf_match(_In_ sai_object_id_t udf_match_id);
    sai_status_t set_udf_match_attribute(_In_ sai_object_id_t udf_match_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_udf_match_attribute(_In_ sai_object_id_t udf_match_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_udf_group(_Out_ sai_object_id_t *udf_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_udf_group(_In_ sai_object_id_t udf_group_id);
    sai_status_t set_udf_group_attribute(_In_ sai_object_id_t udf_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_udf_group_attribute(_In_ sai_object_id_t udf_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_udf_api_t;

typedef struct _sai_tunnel_api_t {
    sai_status_t create_tunnel_map(_Out_ sai_object_id_t *tunnel_map_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tunnel_map(_In_ sai_object_id_t tunnel_map_id);
    sai_status_t set_tunnel_map_attribute(_In_ sai_object_id_t tunnel_map_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tunnel_map_attribute(_In_ sai_object_id_t tunnel_map_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tunnel(_Out_ sai_object_id_t *tunnel_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tunnel(_In_ sai_object_id_t tunnel_id);
    sai_status_t set_tunnel_attribute(_In_ sai_object_id_t tunnel_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tunnel_attribute(_In_ sai_object_id_t tunnel_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_tunnel_stats(_In_ sai_object_id_t tunnel_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_tunnel_stats_ext(_In_ sai_object_id_t tunnel_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_tunnel_stats(_In_ sai_object_id_t tunnel_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_tunnel_term_table_entry(_Out_ sai_object_id_t *tunnel_term_table_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tunnel_term_table_entry(_In_ sai_object_id_t tunnel_term_table_entry_id);
    sai_status_t set_tunnel_term_table_entry_attribute(_In_ sai_object_id_t tunnel_term_table_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tunnel_term_table_entry_attribute(_In_ sai_object_id_t tunnel_term_table_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tunnel_map_entry(_Out_ sai_object_id_t *tunnel_map_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tunnel_map_entry(_In_ sai_object_id_t tunnel_map_entry_id);
    sai_status_t set_tunnel_map_entry_attribute(_In_ sai_object_id_t tunnel_map_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tunnel_map_entry_attribute(_In_ sai_object_id_t tunnel_map_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tunnels(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_tunnels(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_tunnels_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_tunnels_attribute(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_tunnel_api_t;

typedef struct _sai_l2mc_api_t {
    sai_status_t create_l2mc_entry(_In_ const sai_l2mc_entry_t *l2mc_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_l2mc_entry(_In_ const sai_l2mc_entry_t *l2mc_entry);
    sai_status_t set_l2mc_entry_attribute(_In_ const sai_l2mc_entry_t *l2mc_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_l2mc_entry_attribute(_In_ const sai_l2mc_entry_t *l2mc_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_l2mc_api_t;

typedef struct _sai_ipmc_api_t {
    sai_status_t create_ipmc_entry(_In_ const sai_ipmc_entry_t *ipmc_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipmc_entry(_In_ const sai_ipmc_entry_t *ipmc_entry);
    sai_status_t set_ipmc_entry_attribute(_In_ const sai_ipmc_entry_t *ipmc_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipmc_entry_attribute(_In_ const sai_ipmc_entry_t *ipmc_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_ipmc_api_t;

typedef struct _sai_rpf_group_api_t {
    sai_status_t create_rpf_group(_Out_ sai_object_id_t *rpf_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_rpf_group(_In_ sai_object_id_t rpf_group_id);
    sai_status_t set_rpf_group_attribute(_In_ sai_object_id_t rpf_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_rpf_group_attribute(_In_ sai_object_id_t rpf_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_rpf_group_member(_Out_ sai_object_id_t *rpf_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_rpf_group_member(_In_ sai_object_id_t rpf_group_member_id);
    sai_status_t set_rpf_group_member_attribute(_In_ sai_object_id_t rpf_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_rpf_group_member_attribute(_In_ sai_object_id_t rpf_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_rpf_group_api_t;

typedef struct _sai_l2mc_group_api_t {
    sai_status_t create_l2mc_group(_Out_ sai_object_id_t *l2mc_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_l2mc_group(_In_ sai_object_id_t l2mc_group_id);
    sai_status_t set_l2mc_group_attribute(_In_ sai_object_id_t l2mc_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_l2mc_group_attribute(_In_ sai_object_id_t l2mc_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_l2mc_group_member(_Out_ sai_object_id_t *l2mc_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_l2mc_group_member(_In_ sai_object_id_t l2mc_group_member_id);
    sai_status_t set_l2mc_group_member_attribute(_In_ sai_object_id_t l2mc_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_l2mc_group_member_attribute(_In_ sai_object_id_t l2mc_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_l2mc_group_api_t;

typedef struct _sai_ipmc_group_api_t {
    sai_status_t create_ipmc_group(_Out_ sai_object_id_t *ipmc_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipmc_group(_In_ sai_object_id_t ipmc_group_id);
    sai_status_t set_ipmc_group_attribute(_In_ sai_object_id_t ipmc_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipmc_group_attribute(_In_ sai_object_id_t ipmc_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_ipmc_group_member(_Out_ sai_object_id_t *ipmc_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipmc_group_member(_In_ sai_object_id_t ipmc_group_member_id);
    sai_status_t set_ipmc_group_member_attribute(_In_ sai_object_id_t ipmc_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipmc_group_member_attribute(_In_ sai_object_id_t ipmc_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_ipmc_group_api_t;

typedef struct _sai_mcast_fdb_api_t {
    sai_status_t create_mcast_fdb_entry(_In_ const sai_mcast_fdb_entry_t *mcast_fdb_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_mcast_fdb_entry(_In_ const sai_mcast_fdb_entry_t *mcast_fdb_entry);
    sai_status_t set_mcast_fdb_entry_attribute(_In_ const sai_mcast_fdb_entry_t *mcast_fdb_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_mcast_fdb_entry_attribute(_In_ const sai_mcast_fdb_entry_t *mcast_fdb_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_mcast_fdb_api_t;

typedef struct _sai_bridge_api_t {
    sai_status_t create_bridge(_Out_ sai_object_id_t *bridge_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_bridge(_In_ sai_object_id_t bridge_id);
    sai_status_t set_bridge_attribute(_In_ sai_object_id_t bridge_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_bridge_attribute(_In_ sai_object_id_t bridge_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_bridge_stats(_In_ sai_object_id_t bridge_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_bridge_stats_ext(_In_ sai_object_id_t bridge_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_bridge_stats(_In_ sai_object_id_t bridge_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_bridge_port(_Out_ sai_object_id_t *bridge_port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_bridge_port(_In_ sai_object_id_t bridge_port_id);
    sai_status_t set_bridge_port_attribute(_In_ sai_object_id_t bridge_port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_bridge_port_attribute(_In_ sai_object_id_t bridge_port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_bridge_port_stats(_In_ sai_object_id_t bridge_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_bridge_port_stats_ext(_In_ sai_object_id_t bridge_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_bridge_port_stats(_In_ sai_object_id_t bridge_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_bridge_api_t;

typedef struct _sai_tam_api_t {
    sai_status_t create_tam(_Out_ sai_object_id_t *tam_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam(_In_ sai_object_id_t tam_id);
    sai_status_t set_tam_attribute(_In_ sai_object_id_t tam_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_attribute(_In_ sai_object_id_t tam_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_math_func(_Out_ sai_object_id_t *tam_math_func_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_math_func(_In_ sai_object_id_t tam_math_func_id);
    sai_status_t set_tam_math_func_attribute(_In_ sai_object_id_t tam_math_func_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_math_func_attribute(_In_ sai_object_id_t tam_math_func_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_report(_Out_ sai_object_id_t *tam_report_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_report(_In_ sai_object_id_t tam_report_id);
    sai_status_t set_tam_report_attribute(_In_ sai_object_id_t tam_report_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_report_attribute(_In_ sai_object_id_t tam_report_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_event_threshold(_Out_ sai_object_id_t *tam_event_threshold_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_event_threshold(_In_ sai_object_id_t tam_event_threshold_id);
    sai_status_t set_tam_event_threshold_attribute(_In_ sai_object_id_t tam_event_threshold_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_event_threshold_attribute(_In_ sai_object_id_t tam_event_threshold_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_int(_Out_ sai_object_id_t *tam_int_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_int(_In_ sai_object_id_t tam_int_id);
    sai_status_t set_tam_int_attribute(_In_ sai_object_id_t tam_int_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_int_attribute(_In_ sai_object_id_t tam_int_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_tel_type(_Out_ sai_object_id_t *tam_tel_type_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_tel_type(_In_ sai_object_id_t tam_tel_type_id);
    sai_status_t set_tam_tel_type_attribute(_In_ sai_object_id_t tam_tel_type_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_tel_type_attribute(_In_ sai_object_id_t tam_tel_type_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_transport(_Out_ sai_object_id_t *tam_transport_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_transport(_In_ sai_object_id_t tam_transport_id);
    sai_status_t set_tam_transport_attribute(_In_ sai_object_id_t tam_transport_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_transport_attribute(_In_ sai_object_id_t tam_transport_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_telemetry(_Out_ sai_object_id_t *tam_telemetry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_telemetry(_In_ sai_object_id_t tam_telemetry_id);
    sai_status_t set_tam_telemetry_attribute(_In_ sai_object_id_t tam_telemetry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_telemetry_attribute(_In_ sai_object_id_t tam_telemetry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_collector(_Out_ sai_object_id_t *tam_collector_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_collector(_In_ sai_object_id_t tam_collector_id);
    sai_status_t set_tam_collector_attribute(_In_ sai_object_id_t tam_collector_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_collector_attribute(_In_ sai_object_id_t tam_collector_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_event_action(_Out_ sai_object_id_t *tam_event_action_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_event_action(_In_ sai_object_id_t tam_event_action_id);
    sai_status_t set_tam_event_action_attribute(_In_ sai_object_id_t tam_event_action_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_event_action_attribute(_In_ sai_object_id_t tam_event_action_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_event(_Out_ sai_object_id_t *tam_event_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_event(_In_ sai_object_id_t tam_event_id);
    sai_status_t set_tam_event_attribute(_In_ sai_object_id_t tam_event_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_event_attribute(_In_ sai_object_id_t tam_event_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_tam_api_t;

typedef struct _sai_srv6_api_t {
    sai_status_t create_srv6_sidlist(_Out_ sai_object_id_t *srv6_sidlist_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_srv6_sidlist(_In_ sai_object_id_t srv6_sidlist_id);
    sai_status_t set_srv6_sidlist_attribute(_In_ sai_object_id_t srv6_sidlist_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_srv6_sidlist_attribute(_In_ sai_object_id_t srv6_sidlist_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_srv6_sidlists(_In_ sai_object_id_t switch_id, _In_ uint32_t object_count, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_object_id_t *object_id, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_srv6_sidlists(_In_ uint32_t object_count, _In_ const sai_object_id_t *object_id, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t create_my_sid_entry(_In_ const sai_my_sid_entry_t *my_sid_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_my_sid_entry(_In_ const sai_my_sid_entry_t *my_sid_entry);
    sai_status_t set_my_sid_entry_attribute(_In_ const sai_my_sid_entry_t *my_sid_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_my_sid_entry_attribute(_In_ const sai_my_sid_entry_t *my_sid_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_my_sid_entries(_In_ uint32_t object_count, _In_ const sai_my_sid_entry_t *my_sid_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_my_sid_entries(_In_ uint32_t object_count, _In_ const sai_my_sid_entry_t *my_sid_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_my_sid_entries_attribute(_In_ uint32_t object_count, _In_ const sai_my_sid_entry_t *my_sid_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_my_sid_entries_attribute(_In_ uint32_t object_count, _In_ const sai_my_sid_entry_t *my_sid_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_srv6_api_t;

typedef struct _sai_mpls_api_t {
    sai_status_t create_inseg_entry(_In_ const sai_inseg_entry_t *inseg_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_inseg_entry(_In_ const sai_inseg_entry_t *inseg_entry);
    sai_status_t set_inseg_entry_attribute(_In_ const sai_inseg_entry_t *inseg_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_inseg_entry_attribute(_In_ const sai_inseg_entry_t *inseg_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_inseg_entries(_In_ uint32_t object_count, _In_ const sai_inseg_entry_t *inseg_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_inseg_entries(_In_ uint32_t object_count, _In_ const sai_inseg_entry_t *inseg_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_inseg_entries_attribute(_In_ uint32_t object_count, _In_ const sai_inseg_entry_t *inseg_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_inseg_entries_attribute(_In_ uint32_t object_count, _In_ const sai_inseg_entry_t *inseg_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
} sai_mpls_api_t;

typedef struct _sai_dtel_api_t {
    sai_status_t create_dtel(_Out_ sai_object_id_t *dtel_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_dtel(_In_ sai_object_id_t dtel_id);
    sai_status_t set_dtel_attribute(_In_ sai_object_id_t dtel_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_dtel_attribute(_In_ sai_object_id_t dtel_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_dtel_queue_report(_Out_ sai_object_id_t *dtel_queue_report_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_dtel_queue_report(_In_ sai_object_id_t dtel_queue_report_id);
    sai_status_t set_dtel_queue_report_attribute(_In_ sai_object_id_t dtel_queue_report_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_dtel_queue_report_attribute(_In_ sai_object_id_t dtel_queue_report_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_dtel_int_session(_Out_ sai_object_id_t *dtel_int_session_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_dtel_int_session(_In_ sai_object_id_t dtel_int_session_id);
    sai_status_t set_dtel_int_session_attribute(_In_ sai_object_id_t dtel_int_session_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_dtel_int_session_attribute(_In_ sai_object_id_t dtel_int_session_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_dtel_report_session(_Out_ sai_object_id_t *dtel_report_session_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_dtel_report_session(_In_ sai_object_id_t dtel_report_session_id);
    sai_status_t set_dtel_report_session_attribute(_In_ sai_object_id_t dtel_report_session_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_dtel_report_session_attribute(_In_ sai_object_id_t dtel_report_session_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_dtel_event(_Out_ sai_object_id_t *dtel_event_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_dtel_event(_In_ sai_object_id_t dtel_event_id);
    sai_status_t set_dtel_event_attribute(_In_ sai_object_id_t dtel_event_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_dtel_event_attribute(_In_ sai_object_id_t dtel_event_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_dtel_api_t;

typedef struct _sai_bfd_api_t {
    sai_status_t create_bfd_session(_Out_ sai_object_id_t *bfd_session_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_bfd_session(_In_ sai_object_id_t bfd_session_id);
    sai_status_t set_bfd_session_attribute(_In_ sai_object_id_t bfd_session_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_bfd_session_attribute(_In_ sai_object_id_t bfd_session_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_bfd_session_stats(_In_ sai_object_id_t bfd_session_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_bfd_session_stats_ext(_In_ sai_object_id_t bfd_session_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_bfd_session_stats(_In_ sai_object_id_t bfd_session_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_bfd_api_t;

typedef struct _sai_isolation_group_api_t {
    sai_status_t create_isolation_group(_Out_ sai_object_id_t *isolation_group_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_isolation_group(_In_ sai_object_id_t isolation_group_id);
    sai_status_t set_isolation_group_attribute(_In_ sai_object_id_t isolation_group_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_isolation_group_attribute(_In_ sai_object_id_t isolation_group_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_isolation_group_member(_Out_ sai_object_id_t *isolation_group_member_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_isolation_group_member(_In_ sai_object_id_t isolation_group_member_id);
    sai_status_t set_isolation_group_member_attribute(_In_ sai_object_id_t isolation_group_member_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_isolation_group_member_attribute(_In_ sai_object_id_t isolation_group_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_isolation_group_api_t;

typedef struct _sai_nat_api_t {
    sai_status_t create_nat_entry(_In_ const sai_nat_entry_t *nat_entry, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_nat_entry(_In_ const sai_nat_entry_t *nat_entry);
    sai_status_t set_nat_entry_attribute(_In_ const sai_nat_entry_t *nat_entry, _In_ const sai_attribute_t *attr);
    sai_status_t get_nat_entry_attribute(_In_ const sai_nat_entry_t *nat_entry, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_nat_entries(_In_ uint32_t object_count, _In_ const sai_nat_entry_t *nat_entry, _In_ const uint32_t *attr_count, _In_ const sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t remove_nat_entries(_In_ uint32_t object_count, _In_ const sai_nat_entry_t *nat_entry, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t set_nat_entries_attribute(_In_ uint32_t object_count, _In_ const sai_nat_entry_t *nat_entry, _In_ const sai_attribute_t *attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t get_nat_entries_attribute(_In_ uint32_t object_count, _In_ const sai_nat_entry_t *nat_entry, _In_ const uint32_t *attr_count, _Inout_ sai_attribute_t **attr_list, _In_ sai_bulk_op_error_mode_t mode, _Out_ sai_status_t *object_statuses);
    sai_status_t create_nat_zone_counter(_Out_ sai_object_id_t *nat_zone_counter_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_nat_zone_counter(_In_ sai_object_id_t nat_zone_counter_id);
    sai_status_t set_nat_zone_counter_attribute(_In_ sai_object_id_t nat_zone_counter_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_nat_zone_counter_attribute(_In_ sai_object_id_t nat_zone_counter_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_nat_api_t;

typedef struct _sai_counter_api_t {
    sai_status_t create_counter(_Out_ sai_object_id_t *counter_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_counter(_In_ sai_object_id_t counter_id);
    sai_status_t set_counter_attribute(_In_ sai_object_id_t counter_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_counter_attribute(_In_ sai_object_id_t counter_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_counter_stats(_In_ sai_object_id_t counter_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_counter_stats_ext(_In_ sai_object_id_t counter_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_counter_stats(_In_ sai_object_id_t counter_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_counter_api_t;

typedef struct _sai_debug_counter_api_t {
    sai_status_t create_debug_counter(_Out_ sai_object_id_t *debug_counter_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_debug_counter(_In_ sai_object_id_t debug_counter_id);
    sai_status_t set_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_debug_counter_api_t;

typedef struct _sai_macsec_api_t {
    sai_status_t create_macsec(_Out_ sai_object_id_t *macsec_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_macsec(_In_ sai_object_id_t macsec_id);
    sai_status_t set_macsec_attribute(_In_ sai_object_id_t macsec_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_macsec_attribute(_In_ sai_object_id_t macsec_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_macsec_port(_Out_ sai_object_id_t *macsec_port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_macsec_port(_In_ sai_object_id_t macsec_port_id);
    sai_status_t set_macsec_port_attribute(_In_ sai_object_id_t macsec_port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_macsec_port_attribute(_In_ sai_object_id_t macsec_port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_macsec_port_stats(_In_ sai_object_id_t macsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_macsec_port_stats_ext(_In_ sai_object_id_t macsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_macsec_port_stats(_In_ sai_object_id_t macsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_macsec_flow(_Out_ sai_object_id_t *macsec_flow_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_macsec_flow(_In_ sai_object_id_t macsec_flow_id);
    sai_status_t set_macsec_flow_attribute(_In_ sai_object_id_t macsec_flow_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_macsec_flow_attribute(_In_ sai_object_id_t macsec_flow_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_macsec_flow_stats(_In_ sai_object_id_t macsec_flow_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_macsec_flow_stats_ext(_In_ sai_object_id_t macsec_flow_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_macsec_flow_stats(_In_ sai_object_id_t macsec_flow_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_macsec_sc(_Out_ sai_object_id_t *macsec_sc_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_macsec_sc(_In_ sai_object_id_t macsec_sc_id);
    sai_status_t set_macsec_sc_attribute(_In_ sai_object_id_t macsec_sc_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_macsec_sc_attribute(_In_ sai_object_id_t macsec_sc_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_macsec_sc_stats(_In_ sai_object_id_t macsec_sc_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_macsec_sc_stats_ext(_In_ sai_object_id_t macsec_sc_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_macsec_sc_stats(_In_ sai_object_id_t macsec_sc_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_macsec_sa(_Out_ sai_object_id_t *macsec_sa_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_macsec_sa(_In_ sai_object_id_t macsec_sa_id);
    sai_status_t set_macsec_sa_attribute(_In_ sai_object_id_t macsec_sa_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_macsec_sa_attribute(_In_ sai_object_id_t macsec_sa_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_macsec_sa_stats(_In_ sai_object_id_t macsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_macsec_sa_stats_ext(_In_ sai_object_id_t macsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_macsec_sa_stats(_In_ sai_object_id_t macsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_macsec_api_t;

typedef struct _sai_system_port_api_t {
    sai_status_t create_system_port(_Out_ sai_object_id_t *system_port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_system_port(_In_ sai_object_id_t system_port_id);
    sai_status_t set_system_port_attribute(_In_ sai_object_id_t system_port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_system_port_attribute(_In_ sai_object_id_t system_port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_system_port_api_t;

typedef struct _sai_my_mac_api_t {
    sai_status_t create_my_mac(_Out_ sai_object_id_t *my_mac_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_my_mac(_In_ sai_object_id_t my_mac_id);
    sai_status_t set_my_mac_attribute(_In_ sai_object_id_t my_mac_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_my_mac_attribute(_In_ sai_object_id_t my_mac_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_my_mac_api_t;

typedef struct _sai_ipsec_api_t {
    sai_status_t create_ipsec(_Out_ sai_object_id_t *ipsec_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipsec(_In_ sai_object_id_t ipsec_id);
    sai_status_t set_ipsec_attribute(_In_ sai_object_id_t ipsec_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipsec_attribute(_In_ sai_object_id_t ipsec_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_ipsec_port(_Out_ sai_object_id_t *ipsec_port_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipsec_port(_In_ sai_object_id_t ipsec_port_id);
    sai_status_t set_ipsec_port_attribute(_In_ sai_object_id_t ipsec_port_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipsec_port_attribute(_In_ sai_object_id_t ipsec_port_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_ipsec_port_stats(_In_ sai_object_id_t ipsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_ipsec_port_stats_ext(_In_ sai_object_id_t ipsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_ipsec_port_stats(_In_ sai_object_id_t ipsec_port_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_ipsec_sa(_Out_ sai_object_id_t *ipsec_sa_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_ipsec_sa(_In_ sai_object_id_t ipsec_sa_id);
    sai_status_t set_ipsec_sa_attribute(_In_ sai_object_id_t ipsec_sa_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_ipsec_sa_attribute(_In_ sai_object_id_t ipsec_sa_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_ipsec_sa_stats(_In_ sai_object_id_t ipsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_ipsec_sa_stats_ext(_In_ sai_object_id_t ipsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_ipsec_sa_stats(_In_ sai_object_id_t ipsec_sa_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_ipsec_api_t;

typedef struct _sai_generic_programmable_api_t {
    sai_status_t create_generic_programmable(_Out_ sai_object_id_t *generic_programmable_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_generic_programmable(_In_ sai_object_id_t generic_programmable_id);
    sai_status_t set_generic_programmable_attribute(_In_ sai_object_id_t generic_programmable_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_generic_programmable_attribute(_In_ sai_object_id_t generic_programmable_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
} sai_generic_programmable_api_t;

typedef struct _sai_bmtor_api_t {
    sai_status_t create_table_bitmap_classification_entry(_Out_ sai_object_id_t *table_bitmap_classification_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_table_bitmap_classification_entry(_In_ sai_object_id_t table_bitmap_classification_entry_id);
    sai_status_t set_table_bitmap_classification_entry_attribute(_In_ sai_object_id_t table_bitmap_classification_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_table_bitmap_classification_entry_attribute(_In_ sai_object_id_t table_bitmap_classification_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_table_bitmap_classification_entry_stats(_In_ sai_object_id_t table_bitmap_classification_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_table_bitmap_classification_entry_stats_ext(_In_ sai_object_id_t table_bitmap_classification_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_table_bitmap_classification_entry_stats(_In_ sai_object_id_t table_bitmap_classification_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_table_bitmap_router_entry(_Out_ sai_object_id_t *table_bitmap_router_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_table_bitmap_router_entry(_In_ sai_object_id_t table_bitmap_router_entry_id);
    sai_status_t set_table_bitmap_router_entry_attribute(_In_ sai_object_id_t table_bitmap_router_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_table_bitmap_router_entry_attribute(_In_ sai_object_id_t table_bitmap_router_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_table_bitmap_router_entry_stats(_In_ sai_object_id_t table_bitmap_router_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_table_bitmap_router_entry_stats_ext(_In_ sai_object_id_t table_bitmap_router_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_table_bitmap_router_entry_stats(_In_ sai_object_id_t table_bitmap_router_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
    sai_status_t create_table_meta_tunnel_entry(_Out_ sai_object_id_t *table_meta_tunnel_entry_id, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_table_meta_tunnel_entry(_In_ sai_object_id_t table_meta_tunnel_entry_id);
    sai_status_t set_table_meta_tunnel_entry_attribute(_In_ sai_object_id_t table_meta_tunnel_entry_id, _In_ const sai_attribute_t *attr);
    sai_status_t get_table_meta_tunnel_entry_attribute(_In_ sai_object_id_t table_meta_tunnel_entry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_table_meta_tunnel_entry_stats(_In_ sai_object_id_t table_meta_tunnel_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _Out_ uint64_t *counters);
    sai_status_t get_table_meta_tunnel_entry_stats_ext(_In_ sai_object_id_t table_meta_tunnel_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids, _In_ sai_stats_mode_t mode, _Out_ uint64_t *counters);
    sai_status_t clear_table_meta_tunnel_entry_stats(_In_ sai_object_id_t table_meta_tunnel_entry_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t *counter_ids);
} sai_bmtor_api_t;

%ignore sai_switch_api_t;
%ignore sai_port_api_t;
%ignore sai_fdb_api_t;
%ignore sai_vlan_api_t;
%ignore sai_virtual_router_api_t;
%ignore sai_route_api_t;
%ignore sai_next_hop_api_t;
%ignore sai_next_hop_group_api_t;
%ignore sai_router_interface_api_t;
%ignore sai_neighbor_api_t;
%ignore sai_acl_api_t;
%ignore sai_hostif_api_t;
%ignore sai_mirror_api_t;
%ignore sai_samplepacket_api_t;
%ignore sai_stp_api_t;
%ignore sai_lag_api_t;
%ignore sai_policer_api_t;
%ignore sai_wred_api_t;
%ignore sai_qos_map_api_t;
%ignore sai_queue_api_t;
%ignore sai_scheduler_api_t;
%ignore sai_scheduler_group_api_t;
%ignore sai_buffer_api_t;
%ignore sai_hash_api_t;
%ignore sai_udf_api_t;
%ignore sai_tunnel_api_t;
%ignore sai_l2mc_api_t;
%ignore sai_ipmc_api_t;
%ignore sai_rpf_group_api_t;
%ignore sai_l2mc_group_api_t;
%ignore sai_ipmc_group_api_t;
%ignore sai_mcast_fdb_api_t;
%ignore sai_bridge_api_t;
%ignore sai_tam_api_t;
%ignore sai_srv6_api_t;
%ignore sai_mpls_api_t;
%ignore sai_dtel_api_t;
%ignore sai_bfd_api_t;
%ignore sai_isolation_group_api_t;
%ignore sai_nat_api_t;
%ignore sai_counter_api_t;
%ignore sai_debug_counter_api_t;
%ignore sai_macsec_api_t;
%ignore sai_system_port_api_t;
%ignore sai_my_mac_api_t;
%ignore sai_ipsec_api_t;
%ignore sai_generic_programmable_api_t;
%ignore sai_bmtor_api_t;
%include "sai.h"
%include "saiacl.h"
%include "saibfd.h"
%include "saibridge.h"
%include "saibuffer.h"
%include "saicounter.h"
%include "saidebugcounter.h"
%include "saidtel.h"
%include "saiexperimentalbmtor.h"
%include "saiextensions.h"
%include "saifdb.h"
%include "saigenericprogrammable.h"
%include "saihash.h"
%include "saihostif.h"
%include "saiipmc.h"
%include "saiipmcgroup.h"
%include "saiipsec.h"
%include "saiisolationgroup.h"
%include "sail2mc.h"
%include "sail2mcgroup.h"
%include "sailag.h"
%include "saimacsec.h"
%include "saimcastfdb.h"
%include "saimirror.h"
%include "saimpls.h"
%include "saimymac.h"
%include "sainat.h"
%include "saineighbor.h"
%include "sainexthop.h"
%include "sainexthopgroup.h"
%include "saiobject.h"
%include "saipolicer.h"
%include "saiport.h"
%include "saiqosmap.h"
%include "saiqueue.h"
%include "sairoute.h"
%include "sairouterinterface.h"
%include "sairpfgroup.h"
%include "saisamplepacket.h"
%include "saischeduler.h"
%include "saischedulergroup.h"
%include "saisrv6.h"
%include "saistatus.h"
%include "saistp.h"
%include "saiswitch.h"
%include "saiswitchextensions.h"
%include "saisystemport.h"
%include "saitam.h"
%include "saitunnel.h"
%include "saitypes.h"
%include "saitypesextensions.h"
%include "saiudf.h"
%include "saiversion.h"
%include "saivirtualrouter.h"
%include "saivlan.h"
%include "saiwred.h"
