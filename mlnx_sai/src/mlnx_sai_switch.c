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
#include "syslog.h"

#undef  __MODULE__
#define __MODULE__ SAI_SWITCH

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;
sx_api_handle_t           gh_sdk = 0;
sai_switch_notification_t g_notification_callbacks;
rm_resources_t            g_resource_limits;

void sai_log_cb(sx_log_severity_t severity, const char *module_name, char *msg);
sx_log_cb_t log_cb = NULL;

typedef struct trap_id {
    sx_trap_id_t       id; /* trap id */
    sx_trap_priority_t priority;     /* trap priority */
    sx_trap_action_t   trap_action;   /* trap action */
    sx_swid_t          swid; /* swid to set with the trap */
    bool               registeration_needed; /* register for trap needed */
} trap_id_t;

/* List of Trap ids we set */
static trap_id_t trap_ids_set[] = {
    { SX_TRAP_ID_ETH_L2_LLDP, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_OSPF, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L2_IGMP_TYPE_QUERY, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_MIRROR_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V1_REPORT, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_REPORT, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L2_IGMP_TYPE_V2_LEAVE, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_ARP_REQUEST, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_MIRROR_2_CPU, 0, true },
    { SX_TRAP_ID_ARP_RESPONSE, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_MIRROR_2_CPU, 0, true },
    { SX_TRAP_ID_FDB_EVENT, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_FDB, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_MIRROR_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L3_MTUERROR, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_ETH_L3_TTLERROR, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0, true },
    { SX_TRAP_ID_ETH_L3_RPF, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0,
      true },
    { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_LOW, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, true },
    { SX_TRAP_ID_L3_UC_IP_BASE + SX_TRAP_PRIORITY_MED, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, true },
    { SX_TRAP_ID_L3_MC_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0,
      false },
    { SX_TRAP_ID_L3_MC_IP_BASE + SX_TRAP_PRIORITY_LOW, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_L3_MC_IP_BASE + SX_TRAP_PRIORITY_MED, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_L3_MC_IP_BASE + SX_TRAP_PRIORITY_HIGH, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, false },
    { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_BEST_EFFORT, SX_TRAP_PRIORITY_LOW, SX_TRAP_ACTION_TRAP_2_CPU, 0,
      true },
    { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_LOW, SX_TRAP_PRIORITY_MED, SX_TRAP_ACTION_TRAP_2_CPU, 0, true },
    { SX_TRAP_ID_L3_NEIGH_IP_BASE + SX_TRAP_PRIORITY_MED, SX_TRAP_PRIORITY_HIGH, SX_TRAP_ACTION_TRAP_2_CPU, 0, true },
};

#define trap_ids_num_set sizeof(trap_ids_set) / sizeof(trap_ids_set[0])

static sx_status_t switch_open_trap_group(void);
static sx_status_t switch_close_trap_group(void);

sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg);
sai_status_t mlnx_switch_max_vr_get(_In_ const sai_object_key_t   *key,
                                    _Inout_ sai_attribute_value_t *value,
                                    _In_ uint32_t                  attr_index,
                                    _Inout_ vendor_cache_t        *cache,
                                    void                          *arg);
sai_status_t mlnx_switch_on_link_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
sai_status_t mlnx_switch_oper_status_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
sai_status_t mlnx_switch_mode_get(_In_ const sai_object_key_t   *key,
                                  _Inout_ sai_attribute_value_t *value,
                                  _In_ uint32_t                  attr_index,
                                  _Inout_ vendor_cache_t        *cache,
                                  void                          *arg);
sai_status_t mlnx_switch_default_port_vlan_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg);
sai_status_t mlnx_switch_aging_time_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
sai_status_t mlnx_switch_ecmp_hash_seed_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
sai_status_t mlnx_switch_ecmp_hash_type_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
sai_status_t mlnx_switch_ecmp_hash_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
sai_status_t mlnx_switch_ecmp_max_paths_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
sai_status_t mlnx_switch_mode_set(_In_ const sai_object_key_t      *key,
                                  _In_ const sai_attribute_value_t *value,
                                  void                             *arg);
sai_status_t mlnx_switch_default_port_vlan_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
sai_status_t mlnx_switch_aging_time_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
sai_status_t mlnx_switch_ecmp_hash_seed_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
sai_status_t mlnx_switch_ecmp_hash_type_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
sai_status_t mlnx_switch_ecmp_hash_fields_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg);
sai_status_t mlnx_switch_ecmp_max_paths_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg);
sai_status_t mlnx_switch_ttl_action_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);

static const sai_attribute_entry_t        switch_attribs[] = {
    { SAI_SWITCH_ATTR_PORT_NUMBER, false, false, false,
      "Switch ports number", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_CPU_PORT, false, false, false,
      "Switch CPU port", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS, false, false, false,
      "Switch max virtual routers", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_TABLE_SIZE, false, false, false,
      "Switch FDB table size", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED, false, false, false,
      "Switch on link route supported", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_OPER_STATUS, false, false, false,
      "Switch operational status", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_MAX_TEMP, false, false, false,
      "Switch maximum temperature", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_SWITCHING_MODE, false, false, true,
      "Switch switching mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE, false, false, true,
      "Switch broadcast flood control to cpu", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE, false, false, true,
      "Switch multicast flood control to cpu", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_SWITCH_ATTR_VIOLATION_TTL1_ACTION, false, false, true,
      "Switch action for packets with TTL0/TTL1", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_DEFAULT_PORT_VLAN_ID, false, false, true,
      "Switch port default vlan ID", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, false, false, true,
      "Switch source MAC address", SAI_ATTR_VAL_TYPE_MAC },
    { SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES, false, false, true,
      "Switch maximum number of learned MAC addresses", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_AGING_TIME, false, false, true,
      "Switch FDB aging time", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION, false, false, true,
      "Switch flood control for unknown unicast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION, false, false, true,
      "Switch flood control for unknown broadcast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION, false, false, true,
      "Switch flood control for unknown multicast address", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_ECMP_HASH_SEED, false, false, true,
      "Switch ECMP hash seed", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_SWITCH_ATTR_ECMP_HASH_TYPE, false, false, true,
      "Switch ECMP hash type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_ECMP_HASH_FIELDS, false, false, true,
      "Switch ECMP hash fields", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_SWITCH_ATTR_ECMP_MAX_PATHS, false, false, true,
      "Switch maximum number of ECMP paths", SAI_ATTR_VAL_TYPE_U32 },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};
static const sai_vendor_attribute_entry_t switch_vendor_attribs[] = {
    { SAI_SWITCH_ATTR_PORT_NUMBER,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_port_number_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CPU_PORT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_cpu_port_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_vr_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_TABLE_SIZE,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_on_link_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_OPER_STATUS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_oper_status_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_TEMP,
      { false, false, false, false },
      { false, false, false, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SWITCHING_MODE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_mode_get, NULL,
      mlnx_switch_mode_set, NULL },
    { SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_VIOLATION_TTL1_ACTION,
      { false, false, true, false },
      { false, false, true, true },
      NULL, NULL,
      mlnx_switch_ttl_action_set, NULL },
    { SAI_SWITCH_ATTR_DEFAULT_PORT_VLAN_ID,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_default_port_vlan_get, NULL,
      mlnx_switch_default_port_vlan_set, NULL },
    { SAI_SWITCH_ATTR_SRC_MAC_ADDRESS,
      { false, false, false, true },
      { false, false, true, true },
      mlnx_switch_src_mac_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_AGING_TIME,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_aging_time_get, NULL,
      mlnx_switch_aging_time_set, NULL },
    { SAI_SWITCH_ATTR_FDB_UNICAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION,
      { false, false, false, false },
      { false, false, true, true },
      NULL, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_ECMP_HASH_SEED,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_seed_get, NULL,
      mlnx_switch_ecmp_hash_seed_set, NULL },
    { SAI_SWITCH_ATTR_ECMP_HASH_TYPE,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_type_get, NULL,
      mlnx_switch_ecmp_hash_type_set, NULL },
    { SAI_SWITCH_ATTR_ECMP_HASH_FIELDS,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_hash_fields_get, NULL,
      mlnx_switch_ecmp_hash_fields_set, NULL },
    { SAI_SWITCH_ATTR_ECMP_MAX_PATHS,
      { false, false, true, true },
      { false, false, true, true },
      mlnx_switch_ecmp_max_paths_get, NULL,
      mlnx_switch_ecmp_max_paths_set, NULL },
};

#ifndef _WIN32
void sai_log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    int   level;
    char *level_str;

    /* translate SDK log level to syslog level */
    switch (severity) {
    case SX_LOG_NOTICE:
        level = LOG_NOTICE;
        level_str = "NOTICE";
        break;

    case SX_LOG_INFO:
        level = LOG_INFO;
        level_str = "INFO";
        break;

    case SX_LOG_ERROR:
        level = LOG_ERR;
        level_str = "ERR";
        break;

    case SX_LOG_WARNING:
        level = LOG_WARNING;
        level_str = "WARNING";
        break;

    case SX_LOG_FUNCS:
    case SX_LOG_FRAMES:
    case SX_LOG_DEBUG:
    case SX_LOG_ALL:
        level = LOG_DEBUG;
        level_str = "DEBUG";
        break;

    default:
        level = LOG_DEBUG;
        level_str = "DEBUG";
        break;
    }

    syslog(level, "[%s.%s] %s", module_name, level_str, msg);
}
#else
void sai_log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    UNREFERENCED_PARAMETER(severity);
    UNREFERENCED_PARAMETER(module_name);
    UNREFERENCED_PARAMETER(msg);
}
#endif

/*
 * Routine Description:
 *   SDK initialization. After the call the capability attributes should be
 *   ready for retrieval via sai_get_switch_attribute().
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in/opt] firmware_path_name - Vendor specific path name of the firmware
 *                                     to load
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t mlnx_initialize_switch(_In_ sai_switch_profile_id_t                           profile_id,
                                    _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char           * switch_hardware_id,
                                    _In_reads_opt_z_(SAI_MAX_FIRMWARE_PATH_NAME_LEN) char* firmware_path_name,
                                    _In_ sai_switch_notification_t                       * switch_notifications)
{
    sx_router_general_param_t   general_param;
    sx_router_resources_param_t resources_param;
    sx_status_t                 status;

    UNUSED_PARAM(profile_id);

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));

    /* TODO : launch SDK, burn FW */

    /* TODO : query the profile */

#ifndef _WIN32
    openlog("SAI", 0, LOG_USER);
#endif

    /* Open an handle */
    if (SX_STATUS_SUCCESS != (status = sx_api_open(log_cb, &gh_sdk))) {
        fprintf(stderr, "Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_NTC("Initialize switch\n");

    /* init router model, T1 config */
    /* TODO : in the future, get some/all of these params dynamically from the profile */
    memset(&resources_param, 0, sizeof(resources_param));
    memset(&general_param, 0, sizeof(general_param));

    resources_param.min_ipv4_uc_route_entries = 6000;
    resources_param.min_ipv6_uc_route_entries = 0;
    resources_param.min_ipv4_mc_route_entries = 0;
    resources_param.min_ipv6_mc_route_entries = 0;
    resources_param.max_virtual_routers_num = 1;
    resources_param.max_vlan_router_interfaces = 64;
    resources_param.max_port_router_interfaces = 64;
    resources_param.max_router_interfaces = 128;
    resources_param.min_ipv4_neighbor_entries = 64;
    resources_param.min_ipv6_neighbor_entries = 0;
    resources_param.max_ipv4_uc_route_entries = 6000;
    resources_param.max_ipv6_uc_route_entries = 0;
    resources_param.max_ipv4_mc_route_entries = 0;
    resources_param.max_ipv6_mc_route_entries = 0;
    resources_param.max_ipv4_neighbor_entries = 64;
    resources_param.max_ipv6_neighbor_entries = 0;

    general_param.ipv4_enable = 1;
    general_param.ipv6_enable = 0;
    general_param.ipv4_mc_enable = 0;
    general_param.ipv6_mc_enable = 0;
    general_param.rpf_enable = 0;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_init_set(gh_sdk, &general_param, &resources_param))) {
        SX_LOG_ERR("Router init failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS != (status = switch_open_trap_group())) {
        SX_LOG_ERR("Open trap group failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    db_init_next_hop_group();

    /* Set default aging time - 0 (disabled) */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_age_time_set(gh_sdk, DEFAULT_ETH_SWID, SX_FDB_AGE_TIME_MAX))) {
        SX_LOG_ERR("Failed to set fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_STATUS_SUCCESS !=
        (status = rm_chip_limits_get(SX_CHIP_TYPE_SWITCHX_A2, &g_resource_limits))) {
        SX_LOG_ERR("Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sx_status_t switch_open_trap_group(void)
{
    sx_trap_group_t            trap_group_high;
    sx_trap_group_attributes_t trap_group_attributes_high;
    sx_trap_group_t            trap_group_med;
    sx_trap_group_attributes_t trap_group_attributes_med;
    sx_trap_group_t            trap_group_low;
    sx_trap_group_attributes_t trap_group_attributes_low;
    sx_status_t                rc = 0;
    uint32_t                   i;
    sx_user_channel_t          user_channel;

    memset(&user_channel, 0, sizeof(user_channel));
    user_channel.type = SX_USER_CHANNEL_TYPE_NET;

    memset(&trap_group_high, 0, sizeof(trap_group_high));
    memset(&trap_group_attributes_high, 0, sizeof(trap_group_attributes_high));

    memset(&trap_group_med, 0, sizeof(trap_group_med));
    memset(&trap_group_attributes_med, 0, sizeof(trap_group_attributes_med));

    memset(&trap_group_low, 0, sizeof(trap_group_low));
    memset(&trap_group_attributes_low, 0, sizeof(trap_group_attributes_low));

    trap_group_high = SX_TRAP_PRIORITY_HIGH;
    trap_group_attributes_high.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes_high.truncate_size = 0;
    trap_group_attributes_high.prio = SX_TRAP_PRIORITY_HIGH;

    trap_group_attributes_med.prio = SX_TRAP_PRIORITY_MED;
    trap_group_attributes_med.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes_med.truncate_size = 0;
    trap_group_med = SX_TRAP_PRIORITY_MED;

    trap_group_attributes_low.prio = SX_TRAP_PRIORITY_LOW;
    trap_group_attributes_low.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
    trap_group_attributes_low.truncate_size = 0;
    trap_group_low = SX_TRAP_PRIORITY_LOW;

    rc = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                        trap_group_high, &trap_group_attributes_high);
    if (SX_CHECK_FAIL(rc)) {
        SX_LOG_ERR("failed to call %s", "sx_api_host_ifc_trap_group_set with high priority");
        return rc;
    }

    SX_LOG_DBG("succeeded to call %s with high with high priority", "sx_api_host_ifc_trap_group_set");

    rc = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                        trap_group_med, &trap_group_attributes_med);
    if (SX_CHECK_FAIL(rc)) {
        SX_LOG_ERR("failed to call %s", "sx_api_host_ifc_trap_group_set with medium priority");
        return rc;
    }

    SX_LOG_DBG("succeeded to call %s with high with medium priority", "sx_api_host_ifc_trap_group_set");

    rc = sx_api_host_ifc_trap_group_set(gh_sdk, DEFAULT_ETH_SWID,
                                        trap_group_low, &trap_group_attributes_low);
    if (SX_CHECK_FAIL(rc)) {
        SX_LOG_ERR("failed to call %s", "sx_api_host_ifc_trap_group_set with low priority");
        return rc;
    }

    SX_LOG_DBG("succeeded to call %s with low with low priority", "sx_api_host_ifc_trap_group_set");

    for (i = 0; i < trap_ids_num_set; i++) {
        rc = sx_api_host_ifc_trap_id_set(gh_sdk,
                                         DEFAULT_ETH_SWID,
                                         trap_ids_set[i].id,
                                         trap_ids_set[i].priority ==
                                         SX_TRAP_PRIORITY_HIGH ? trap_group_high : \
                                         trap_ids_set[i].priority ==
                                         SX_TRAP_PRIORITY_MED ? trap_group_med :
                                         trap_group_low,
                                         trap_ids_set[i].trap_action);
        if (SX_CHECK_FAIL(rc)) {
            SX_LOG_ERR("Failed to set for %u trap, error is %d\n", trap_ids_set[i].id, rc);
            return rc;
        }

        SX_LOG_DBG("succeeded to call %s on %u trap",
                   "sx_api_host_ifc_trap_id_set",
                   trap_ids_set[i].id);

        if (trap_ids_set[i].registeration_needed) {
            rc = sx_api_host_ifc_trap_id_register_set(gh_sdk, SX_ACCESS_CMD_REGISTER,
                                                      DEFAULT_ETH_SWID, trap_ids_set[i].id, &user_channel);

            if (SX_CHECK_FAIL(rc)) {
                SX_LOG_ERR("Failed to register for %u trap, error is %d\n", trap_ids_set[i].id, rc);
                return rc;
            }
        }
    }

    return SX_STATUS_SUCCESS;
}

static sx_status_t switch_close_trap_group(void)
{
    sx_status_t       rc = 0;
    uint32_t          i;
    sx_user_channel_t user_channel;

    memset(&user_channel, 0, sizeof(user_channel));
    user_channel.type = SX_USER_CHANNEL_TYPE_NET;

    for (i = 0; i < trap_ids_num_set; i++) {
        rc = sx_api_host_ifc_trap_id_register_set(gh_sdk, SX_ACCESS_CMD_DEREGISTER,
                                                  DEFAULT_ETH_SWID, trap_ids_set[i].id, &user_channel);

        if (SX_CHECK_FAIL(rc)) {
            SX_LOG_ERR("Failed to deregister for %u trap, error is %d\n", trap_ids_set[i].id, rc);
            return rc;
        }
    }

    return SX_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Release all resources associated with currently opened switch
 *
 * Arguments:
 *   [in] warm_restart_hint - hint that indicates controlled warm restart.
 *                            Since warm restart can be caused by crash
 *                            (therefore there are no guarantees for this call),
 *                            this hint is really a performance optimization.
 *
 * Return Values:
 *   None
 */
void mlnx_shutdown_switch(_In_ bool warm_restart_hint)
{
    sx_status_t status;

    SX_LOG_ENTER();

    SX_LOG_NTC("Shutdown switch\n");

    if (SX_STATUS_SUCCESS != (status = switch_close_trap_group())) {
        SX_LOG_ERR("Close trap group failed - %s.\n", SX_STATUS_MSG(status));
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_deinit_set(gh_sdk))) {
        SX_LOG_ERR("Router deinit failed.\n");
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));

    SX_LOG_EXIT();
}

/*
 * Routine Description:
 *   SDK connect. This API connects library to the initialized SDK.
 *   After the call the capability attributes should be ready for retrieval
 *   via sai_get_switch_attribute().
 *
 * Arguments:
 *   [in] profile_id - Handle for the switch profile.
 *   [in] switch_hardware_id - Switch hardware ID to open
 *   [in] switch_notifications - switch notification table
 * Return Values:
 *   SAI_STATUS_SUCCESS on success
 *   Failure status code on error
 */
sai_status_t mlnx_connect_switch(_In_ sai_switch_profile_id_t                profile_id,
                                 _In_reads_z_(SAI_MAX_HARDWARE_ID_LEN) char* switch_hardware_id,
                                 _In_ sai_switch_notification_t            * switch_notifications)
{
    sx_status_t status;

    UNUSED_PARAM(profile_id);

    if (NULL == switch_hardware_id) {
        fprintf(stderr, "NULL switch hardware ID passed to SAI switch connect\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == switch_notifications) {
        fprintf(stderr, "NULL switch notifications passed to SAI switch connect\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    memcpy(&g_notification_callbacks, switch_notifications, sizeof(g_notification_callbacks));

    /* Open an handle if not done already on init for init agent */
    if (0 == gh_sdk) {
#ifndef _WIN32
        openlog("SAI", 0, LOG_USER);
#endif

        if (SX_STATUS_SUCCESS != (status = sx_api_open(log_cb, &gh_sdk))) {
            fprintf(stderr, "Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SX_STATUS_SUCCESS !=
            (status = rm_chip_limits_get(SX_CHIP_TYPE_SWITCHX_A2, &g_resource_limits))) {
            SX_LOG_ERR("Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
    }

    db_init_next_hop_group();

    SX_LOG_NTC("Connect switch\n");

    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *   Disconnect this SAI library from the SDK.
 *
 * Arguments:
 *   None
 * Return Values:
 *   None
 */
void mlnx_disconnect_switch(void)
{
#ifndef _WIN32
    sx_status_t status;

    SX_LOG_NTC("Disconnect switch\n");

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));
#endif
}

/*
 * Routine Description:
 *    Set switch attribute value
 *
 * Arguments:
 *    [in] attr - switch attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_switch_attribute(_In_ const sai_attribute_t *attr)
{
    SX_LOG_ENTER();

    return sai_set_attribute(NULL, "", switch_attribs, switch_vendor_attribs, attr);
}

/* Switching mode [sai_switch_switching_mode_t]
 *  (default to SAI_SWITCHING_MODE_STORE_AND_FORWARD) */
sai_status_t mlnx_switch_mode_set(_In_ const sai_object_key_t *key, _In_ const sai_attribute_value_t *value, void *arg)
{
    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_SWITCHING_MODE_CUT_THROUGH:
        break;

    /* Note Mellanox implementation does not support store and forward.
    * The default is cut through, different then SAI defined default */
    case SAI_SWITCHING_MODE_STORE_AND_FORWARD:
        SX_LOG_ERR("Switching mode store and forward not supported\n");
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;

    default:
        SX_LOG_ERR("Invalid switching mode value %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VlanID for ports that are not members of
*  any vlans [sai_vlan_id_t]  (default to vlan 1)*/
sai_status_t mlnx_switch_default_port_vlan_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_default_vid_set(gh_sdk, DEFAULT_ETH_SWID, value->u16))) {
        SX_LOG_ERR("Failed to set default vid - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dynamic FDB entry aging time in seconds [uint32_t]
 *   Zero means aging is disabled.
 *  (default to zero)
 */
sai_status_t mlnx_switch_aging_time_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t      status;
    sx_fdb_age_time_t time;

    SX_LOG_ENTER();

    if (0 == value->u32) {
        time = SX_FDB_AGE_TIME_MAX;
    } else if (SX_FDB_AGE_TIME_MIN > value->u32) {
        time = SX_FDB_AGE_TIME_MIN;
    } else if (SX_FDB_AGE_TIME_MAX < value->u32) {
        time = SX_FDB_AGE_TIME_MAX;
    } else {
        time = value->u32;
    }

    if (SX_STATUS_SUCCESS !=
        (status = sx_api_fdb_age_time_set(gh_sdk, DEFAULT_ETH_SWID, time))) {
        SX_LOG_ERR("Failed to set fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t get_ecmp_hash_params(sx_router_ecmp_hash_params_t *ecmp)
{
    sai_status_t status;

    status = sx_api_router_ecmp_hash_params_get(gh_sdk, ecmp);

    /* Get only works after the first set has been done. In case set wasn't done, fill default values */
    if (SX_STATUS_DB_NOT_INITIALIZED == status) {
        memset(ecmp, 0, sizeof(*ecmp));
        ecmp->ecmp_hash = 0;
        ecmp->ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_CRC;
        ecmp->symmetric_hash = false;
        ecmp->seed = 0;
    } else if (SX_STATUS_SUCCESS != status) {
        SX_LOG_ERR("Failed to get ECMP hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing seed  [uint32_t] */
sai_status_t mlnx_switch_ecmp_hash_seed_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_router_ecmp_hash_params_t ecmp;
    sx_status_t                  status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    ecmp.seed = value->u32;

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_set(gh_sdk, &ecmp))) {
        SX_LOG_ERR("Failed to set ECMP hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing type  [sai_switch_ecmp_hash_type_t] */
sai_status_t mlnx_switch_ecmp_hash_type_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    sx_router_ecmp_hash_params_t ecmp;
    sx_status_t                  status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    switch (value->s32) {
    case SAI_SWITCH_ECMP_HASH_TYPE_XOR:
        ecmp.ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_XOR;
        break;

    case SAI_SWITCH_ECMP_HASH_TYPE_CRC:
        ecmp.ecmp_hash_type = SX_ROUTER_ECMP_HASH_TYPE_CRC;
        break;

    default:
        SX_LOG_ERR("Invalid hash type value %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_set(gh_sdk, &ecmp))) {
        SX_LOG_ERR("Failed to set ECMP hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing fields [sai_switch_ecmp_hash_fields_t] */
sai_status_t mlnx_switch_ecmp_hash_fields_set(_In_ const sai_object_key_t      *key,
                                              _In_ const sai_attribute_value_t *value,
                                              void                             *arg)
{
    sx_router_ecmp_hash_params_t ecmp;
    sx_status_t                  status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    ecmp.ecmp_hash = 0;
    if (value->s32 & SAI_SWITCH_ECMP_HASH_SRC_IP) {
        ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_SRC_IP;
    }
    if (value->s32 & SAI_SWITCH_ECMP_HASH_DST_IP) {
        ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_DST_IP;
    }
    if (value->s32 & SAI_SWITCH_ECMP_HASH_L4_SRC_PORT) {
        ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_TCP_UDP_SRC_PORT;
    }
    if (value->s32 & SAI_SWITCH_ECMP_HASH_L4_DST_PORT) {
        ecmp.ecmp_hash |= SX_ROUTER_ECMP_HASH_TCP_UDP_DST_PORT;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_router_ecmp_hash_params_set(gh_sdk, &ecmp))) {
        SX_LOG_ERR("Failed to set ECMP hash params - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP max number of paths per group [uint32_t]
 *  (default to 64) */
sai_status_t mlnx_switch_ecmp_max_paths_set(_In_ const sai_object_key_t      *key,
                                            _In_ const sai_attribute_value_t *value,
                                            void                             *arg)
{
    SX_LOG_ENTER();

    if (ECMP_MAX_PATHS < value->u32) {
        SX_LOG_ERR("ECMP max paths value %u over %u not supported\n", value->u32, ECMP_MAX_PATHS);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    /* no need to call SDK */

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Action for Packets with TTL 0 or 1 [sai_packet_action_t]
 *  (default to SAI_PACKET_ACTION_TRAP) */
sai_status_t mlnx_switch_ttl_action_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sx_status_t       status;
    sx_user_channel_t user_channel;
    sx_access_cmd_t   cmd;

    memset(&user_channel, 0, sizeof(user_channel));
    user_channel.type = SX_USER_CHANNEL_TYPE_NET;

    SX_LOG_ENTER();

    switch (value->s32) {
    case SAI_PACKET_ACTION_TRAP:
        cmd = SX_ACCESS_CMD_REGISTER;
        break;

    case SAI_PACKET_ACTION_DROP:
        cmd = SX_ACCESS_CMD_DEREGISTER;
        break;

    case SAI_PACKET_ACTION_FORWARD:
    case SAI_PACKET_ACTION_LOG:
        SX_LOG_ERR("TTL action forward/log not supported\n");
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;

    default:
        SX_LOG_ERR("Invalid ttl action %d\n", value->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(gh_sdk, cmd,
                                                                            DEFAULT_ETH_SWID,
                                                                            SX_TRAP_ID_ETH_L3_TTLERROR,
                                                                            &user_channel))) {
        SX_LOG_ERR("Failed to register %u for TTL trap - %s.\n", cmd, SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Get switch attribute value
 *
 * Arguments:
 *    [in] attr_count - number of switch attributes
 *    [inout] attr_list - array of switch attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_switch_attribute(_In_ uint32_t attr_count, _Inout_ sai_attribute_t *attr_list)
{
    SX_LOG_ENTER();

    return sai_get_attributes(NULL, "", switch_attribs, switch_vendor_attribs, attr_count, attr_list);
}

/* The number of ports on the switch [uint32_t] */
sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = SWITCH_PORT_NUM;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the CPU Port [sai_port_id_t] */
sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = CPU_PORT;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Max number of virtual routers supported [uint32_t] */
sai_status_t mlnx_switch_max_vr_get(_In_ const sai_object_key_t   *key,
                                    _Inout_ sai_attribute_value_t *value,
                                    _In_ uint32_t                  attr_index,
                                    _Inout_ vendor_cache_t        *cache,
                                    void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = SWITCH_MAX_VR;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *   Local subnet routing supported [bool]
 *   Routes with next hop set to "on-link"
 */
sai_status_t mlnx_switch_on_link_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    SX_LOG_ENTER();

    value->booldata = true;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Oper state [sai_switch_oper_status_t] */
sai_status_t mlnx_switch_oper_status_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_SWITCH_OPER_STATUS_UP;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Switching mode [sai_switch_switching_mode_t]
 *  (default to SAI_SWITCHING_MODE_STORE_AND_FORWARD) */
sai_status_t mlnx_switch_mode_get(_In_ const sai_object_key_t   *key,
                                  _Inout_ sai_attribute_value_t *value,
                                  _In_ uint32_t                  attr_index,
                                  _Inout_ vendor_cache_t        *cache,
                                  void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = SAI_SWITCHING_MODE_CUT_THROUGH;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default VlanID for ports that are not members of
*  any vlans [sai_vlan_id_t]  (default to vlan 1)*/
sai_status_t mlnx_switch_default_port_vlan_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    sai_status_t status;
    sx_vid_t     vid;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_vlan_default_vid_get(gh_sdk, DEFAULT_ETH_SWID, &vid))) {
        SX_LOG_ERR("Failed to get default vid - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u16 = vid;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Default switch MAC Address [sai_mac_t] */
sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    sai_status_t  status;
    sx_mac_addr_t mac;

    SX_LOG_ENTER();

    /* Use switch first port, and zero down lower 6 bits port part (64 ports) */
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_port_phys_addr_get(gh_sdk, FIRST_PORT, &mac))) {
        SX_LOG_ERR("Failed to get port address - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    mac.ether_addr_octet[5] &= PORT_MAC_BITMASK;

    memcpy(value->mac, &mac,  sizeof(value->mac));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Dynamic FDB entry aging time in seconds [uint32_t]
 *   Zero means aging is disabled.
 *  (default to zero)
 */
sai_status_t mlnx_switch_aging_time_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t      status;
    sx_fdb_age_time_t age_time;

    SX_LOG_ENTER();

    if (SX_STATUS_SUCCESS != (status = sx_api_fdb_age_time_get(gh_sdk, DEFAULT_ETH_SWID, &age_time))) {
        SX_LOG_ERR("Failed to get fdb age time - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    value->u32 = age_time;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing seed  [uint32_t] */
sai_status_t mlnx_switch_ecmp_hash_seed_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t                 status;
    sx_router_ecmp_hash_params_t ecmp;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    value->u32 = ecmp.seed;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing type  [sai_switch_ecmp_hash_type_t] */
sai_status_t mlnx_switch_ecmp_hash_type_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    sai_status_t                 status;
    sx_router_ecmp_hash_params_t ecmp;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    switch (ecmp.ecmp_hash_type) {
    case SX_ROUTER_ECMP_HASH_TYPE_CRC:
        value->s32 = SAI_SWITCH_ECMP_HASH_TYPE_CRC;
        break;

    case SX_ROUTER_ECMP_HASH_TYPE_XOR:
        value->s32 = SAI_SWITCH_ECMP_HASH_TYPE_XOR;
        break;

    default:
        SX_LOG_ERR("Unexpected ECMP hash type %u\n", ecmp.ecmp_hash_type);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP hashing fields [sai_switch_ecmp_hash_fields_t] */
sai_status_t mlnx_switch_ecmp_hash_fields_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg)
{
    sai_status_t                  status;
    sx_router_ecmp_hash_params_t  ecmp;
    sai_switch_ecmp_hash_fields_t fields = 0;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = get_ecmp_hash_params(&ecmp))) {
        return status;
    }

    if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_SRC_IP) {
        fields |= SAI_SWITCH_ECMP_HASH_SRC_IP;
    }
    if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_DST_IP) {
        fields |= SAI_SWITCH_ECMP_HASH_DST_IP;
    }
    if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_TCP_UDP_SRC_PORT) {
        fields |= SAI_SWITCH_ECMP_HASH_L4_SRC_PORT;
    }
    if (ecmp.ecmp_hash & SX_ROUTER_ECMP_HASH_TCP_UDP_DST_PORT) {
        fields |= SAI_SWITCH_ECMP_HASH_L4_DST_PORT;
    }

    value->s32 = fields;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* ECMP max number of paths per group [uint32_t]
 *  (default to 64) */
sai_status_t mlnx_switch_ecmp_max_paths_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = ECMP_MAX_PATHS;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_switch_api_t switch_api = {
    mlnx_initialize_switch,
    mlnx_shutdown_switch,
    mlnx_connect_switch,
    mlnx_disconnect_switch,
    mlnx_set_switch_attribute,
    mlnx_get_switch_attribute,
};
