/*
 *  Copyright (C) 2017-2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <errno.h>
#include "assert.h"
#ifndef _WIN32
#include <dirent.h>
#include <netinet/ether.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/mman.h>
#include <pthread.h>
#endif
#include <complib/cl_mem.h>
#include <complib/cl_passivelock.h>
#include <complib/cl_shared_memory.h>
#include <complib/cl_thread.h>
#include <math.h>
#include <limits.h>
#include <sx/sdk/sx_api_rm.h>
#include <sx/utils/dbg_utils.h>
#include "meta/saimetadata.h"
#include "mlnx_sai_prm_api.h"
#include "mlnx_sai_swid_api.h"

#ifdef _WIN32
#undef CONFIG_SYSLOG
#endif

#undef  __MODULE__
#define __MODULE__ SAI_SWITCH

typedef struct _sai_switch_notification_t {
    sai_switch_state_change_notification_fn     on_switch_state_change;
    sai_port_state_change_notification_fn       on_port_state_change;
    sai_switch_shutdown_request_notification_fn on_switch_shutdown_request;
    sai_packet_event_notification_fn            on_packet_event;
    sai_port_signal_degrade_notification_fn     on_signal_degrade;
    sai_port_module_plug_event_notification_fn  on_module_event;
} sai_switch_notification_t;

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define MAX_PORTS_PER_DEVICE 128
#define INVALID_IB_PORT      255
#define INVALID_SWID         255
/*As defined in MLNX-OS */
#define HWD_TRAP_GROUP       31
#define SAI_PORT_PROTOCOL_IB 2
#define SPLIT_READY_4X       0
#define SPLIT_READY_2X       1
#define SPLIT_READY_1X       2

sx_api_handle_t                  gh_sdk = 0;
static sai_switch_notification_t g_notification_callbacks;
sai_switch_profile_id_t          g_profile_id;
rm_resources_t                   g_resource_limits;
sai_db_t                        *g_sai_db_ptr = NULL;
static cl_thread_t               event_thread;
static cl_thread_t               dfw_thread;
static bool                      event_thread_asked_to_stop = false;
bool                             dfw_thread_asked_to_stop = false;
static bool                      g_uninit_data_plane_on_removal = true;
uint32_t                         g_mlnx_shm_rm_size = 0;
sxd_handle                       g_sxd_handle = 0;
sai_switch_type_t                g_switch_type = SAI_SWITCH_TYPE_IBV0;
uint32_t                         g_device_id = SX_DEVICE_ID;
uint32_t                         g_swid_id = DEFAULT_IB_SWID;
extern bool                      g_is_chipsim;

void log_cb(sx_log_severity_t severity, const char *module_name, char *msg);
void log_pause_cb(void);
#ifdef CONFIG_SYSLOG
sx_log_cb_t sai_log_cb = log_cb;
bool        g_log_init = false;
#else
sx_log_cb_t sai_log_cb = NULL;
#endif

sai_status_t mlnx_sai_log_levels_post_init(void);
static void event_thread_func(void *context);
sai_status_t sai_db_create();
static void sai_db_values_init();
sai_status_t mlnx_parse_config(const char *config_file);
void switch_key_to_str(_In_ sai_object_id_t switch_id, _Out_ char *key_str);
extern sai_status_t sai_db_unload(boolean_t erase_db);
extern sai_status_t mlnx_sai_rm_initialize(const char *config_file);
extern sai_status_t mlnx_sdk_start(mlnx_sai_boot_type_t boot_type);
extern sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                                _Inout_ sai_attribute_value_t *value,
                                                _In_ uint32_t                  attr_index,
                                                _Inout_ vendor_cache_t        *cache,
                                                void                          *arg);
extern sai_status_t mlnx_switch_max_ports_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
extern sai_status_t mlnx_switch_port_list_get(_In_ const sai_object_key_t   *key,
                                              _Inout_ sai_attribute_value_t *value,
                                              _In_ uint32_t                  attr_index,
                                              _Inout_ vendor_cache_t        *cache,
                                              void                          *arg);
extern sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
extern sai_status_t mlnx_switch_max_mtu_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
extern sai_status_t mlnx_switch_max_temp_get(_In_ const sai_object_key_t   *key,
                                             _Inout_ sai_attribute_value_t *value,
                                             _In_ uint32_t                  attr_index,
                                             _Inout_ vendor_cache_t        *cache,
                                             void                          *arg);
extern sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                            _Inout_ sai_attribute_value_t *value,
                                            _In_ uint32_t                  attr_index,
                                            _Inout_ vendor_cache_t        *cache,
                                            void                          *arg);
extern sai_status_t mlnx_switch_init_connect_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
extern sai_status_t mlnx_switch_profile_id_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_event_func_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_switch_infiniband_num_of_swids_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg);
static sai_status_t mlnx_switch_infiniband_adaptive_routing_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg);
static sai_status_t mlnx_switch_infiniband_ar_groups_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static sai_status_t mlnx_switch_infiniband_ib_routing_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg);
static sai_status_t mlnx_switch_infiniband_breakout_mode_get(_In_ const sai_object_key_t   *key,
                                                             _Inout_ sai_attribute_value_t *value,
                                                             _In_ uint32_t                  attr_index,
                                                             _Inout_ vendor_cache_t        *cache,
                                                             void                          *arg);
extern sai_status_t mlnx_restart_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
extern sai_status_t mlnx_nv_storage_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t mlnx_switch_event_func_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_switch_attr_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t mlnx_switch_attr_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg);
static sai_status_t mlnx_switch_node_description_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg);
static sai_status_t mlnx_switch_node_description_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg);
static sai_status_t mlnx_switch_image_guid_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg);
static sai_status_t mlnx_switch_image_guid_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg);
static sai_status_t mlnx_switch_operation_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg);
static sai_status_t mlnx_set_node_description_on_all_swids(void);
static sai_status_t mlnx_set_system_image_guid_on_all_swids(void);
static sai_status_t mlnx_set_system_image_guid(uint8_t swid, uint64_t guid_value);


/* DFW feature functions */
extern void mlnx_switch_dfw_thread_func(_In_ void *context);

static const sai_vendor_attribute_entry_t switch_vendor_attribs[] = {
    { SAI_SWITCH_ATTR_PORT_NUMBER,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_port_number_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_NUMBER_OF_SUPPORTED_PORTS,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_ports_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_LIST,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_port_list_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_PORT_MAX_MTU,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_mtu_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CPU_PORT,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_cpu_port_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_MAX_TEMP,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_switch_max_temp_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_RESTART_TYPE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_restart_type_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_NV_STORAGE_SIZE,
      { false, false, false, true },
      { false, false, false, true },
      mlnx_nv_storage_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SRC_MAC_ADDRESS,
      { false, false, false, true },
      { false, false, true, true },
      mlnx_switch_src_mac_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_INIT_SWITCH,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_init_connect_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SWITCH_PROFILE_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_profile_id_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY },
    { SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY },
    { SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY },
    { SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY },
    { SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY },
    { SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_event_func_get, (void*)SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY,
      mlnx_switch_event_func_set, (void*)SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY },
    { SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_attr_get, (void*)SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL,
      mlnx_switch_attr_set, (void*)SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL },
    { SAI_SWITCH_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_type_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_NUM_OF_SWIDS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_infiniband_num_of_swids_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_ADAPTIVE_ROUTING,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_infiniband_adaptive_routing_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_AR_GROUPS,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_infiniband_ar_groups_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_IB_ROUTING,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_infiniband_ib_routing_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_BREAKOUT_MODE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_switch_infiniband_breakout_mode_get, NULL,
      NULL, NULL },
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_NODE_DESCRIPTION,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_node_description_get, NULL,
      mlnx_switch_node_description_set, NULL},
    { SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_SYSTEM_IMAGE_GUID,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_switch_image_guid_get, NULL,
      mlnx_switch_image_guid_set, NULL},
    { SAI_SWITCH_ATTR_OPERATION_MODE_IB,
      { true, false, true, false },
      { true, false, true, false },
      mlnx_switch_operation_mode_get, NULL, NULL, NULL},
    { END_FUNCTIONALITY_ATTRIBS_ID,
      { false, false, false, false },
      { false, false, false, false },
      NULL, NULL,
      NULL, NULL }
};

static const mlnx_attr_enum_info_t switch_enum_info[] = {
    [SAI_SWITCH_ATTR_RESTART_TYPE] = ATTR_ENUM_VALUES_ALL(),
    [SAI_SWITCH_ATTR_TYPE] = ATTR_ENUM_VALUES_LIST(
        SAI_SWITCH_TYPE_IBV0),
};
static const sai_stat_capability_t switch_stats_capabilities[] = {};
const mlnx_obj_type_attrs_info_t   mlnx_switch_obj_type_info =
{ switch_vendor_attribs, OBJ_ATTRS_ENUMS_INFO(switch_enum_info), OBJ_STAT_CAP_INFO(switch_stats_capabilities)};

/* Profile conf */
#define IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES 1024
#define IB_RDQ_MAD_NUMBER_OF_ENTRIES     128
#define SAI_PATH                         "/sai_db"
#define IB_RDQ_QP0_DEFAULT_SIZE          350                      /* QP0 only, no N+1 port */
#define IB_RDQ_QP1_DEFAULT_SIZE          4096                      /* QP0 (Switch port 0), QP0+QP1 (Switch N+1 port) */
#define IB_RDQ_UD_DEFAULT_SIZE           4200
#define IB_INVALID_CHIP                  0
/* weights */
#define IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT      10
#define IB_RDQ_MULTI_SWID_DEFAULT_WEIGHT       10
#define IB_QP0_RDQ_CRITICAL_SINGLE_SWID_NUMBER 4
/*Any legal max adapting routing group must by a multiple of 128*/
#define IB_ADAPTIVE_ROUTING_GROUP_CAP_DIVISOR 128
/*Min valid max adapting routing group*/
#define IB_MIN_ADAPTIVE_ROUTING_GROUP_CAP IB_ADAPTIVE_ROUTING_GROUP_CAP_DIVISOR
/*Max valid max adapting routing group*/
#define IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP                     4096
#define IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY         (IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP / 2)
#define IB_MAX_ALLOWED_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY 1792

struct sx_pci_profile pci_profile_single_ib = {
    /*profile enum*/
    .pci_profile = PCI_PROFILE_IB_SINGLE_SWID,
    /*tx_prof */
    /* !!! IB DOES NOT HAVE STCLASS !!!*/
    .tx_prof = {
        { /**** swid 0 ****/
            {0, 2}, /*-0-*/
            {0, 2}, /*-1-*/
            {0, 2}, /*-2-*/
            {0, 2}, /*-3-*/
            {0, 2}, /*-4-for UD QPs*/
            {0, 1}, /*-5-for QP1*/
            {0, 0}, /*-6-for QP0*/
            {0, 2}, /*-7-*/
        }
    },
    /* emad_tx_prof */
    .emad_tx_prof = {0, 0},
    /* swid_type */
    .swid_type = {
        SX_KU_L2_TYPE_IB,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE,
        SX_KU_L2_TYPE_DONT_CARE
    },
    /* rdq_count */
    .rdq_count = {
        5,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    },
    /* rdq */
    .rdq = {
        {
            0,
            1,
            2,
            3,
            4
        }
    },
    /* emad_rdq (for events) */
    .emad_rdq = 21,
    /* rdq_properties
     * IMPORTANT: if the order of these queues changes, please change
     *      IB_QP0_RDQ_CRITICAL_SINGLE_SWID_NUMBER
     */
    .rdq_properties = {
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_UD_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-0-best effort priority*/
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_UD_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-1-low priority*/
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_UD_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-2-medium priority*/
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_UD_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-3-high priority*/
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_QP0_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-4-critical priority*/
        {0, 0, 0, 0}, /*-5-*/
        {0, 0, 0, 0}, /*-6-*/
        {0, 0, 0, 0}, /*-7-*/
        {0, 0, 0, 0}, /*-8-*/
        {0, 0, 0, 0}, /*-9-*/
        {0, 0, 0, 0}, /*-10-*/
        {0, 0, 0, 0}, /*-11-*/
        {0, 0, 0, 0}, /*-12-*/
        {0, 0, 0, 0}, /*-13-*/
        {0, 0, 0, 0}, /*-14-*/
        {0, 0, 0, 0}, /*-15-*/
        {0, 0, 0, 0}, /*-16-*/
        {0, 0, 0, 0}, /*-17-*/
        {0, 0, 0, 0}, /*-18-*/
        {0, 0, 0, 0}, /*-19-*/
        {0, 0, 0, 0}, /*-20-*/
        {IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES, IB_RDQ_UD_DEFAULT_SIZE, IB_RDQ_SINGLE_SWID_DEFAULT_WEIGHT, 0}, /*-21-*/
        {0, 0, 0, 0}, /*-22-*/
        {0, 0, 0, 0} /*-23-*/
    },
    /* cpu_egress_tclass */
    .cpu_egress_tclass = {
        2, /*-0-for QP0*/
        1, /*-1-for QP1*/
        0, /*-2-for UD QPs*/
        0, /*-3-*/
        0, /*-4-*/
        0, /*-5-*/
        0, /*-6-*/
        0, /*-7-*/
        0, /*-8-*/
        0, /*-9-*/
        0, /*-10-*/
        0, /*-11-*/
        0, /*-12-*/
        0, /*-13-*/
        0, /*-14-*/
        0, /*-15-*/
        0, /*-16-*/
        0, /*-17-*/
        0, /*-18-*/
        0, /*-19-*/
        0, /*-20-*/
        0, /*-21-*/
        0, /*-22-*/
        0 /*-23-*/
    }
};

/* device profile - IB */
struct ku_profile single_part_ib_device_profile = {
    .dev_id = SX_INVALID_DEVICE_ID,
    .set_mask_0_63 = 0xf3ff,
    .set_mask_64_127 = 0,
    .max_vepa_channels = 0,
    .max_lag = 0,
    .max_port_per_lag = 0,
    .max_mid = 0,
    .max_pgt = 0,
    .max_system_port = 0,
    .max_active_vlans = 0,  /* In PRM table max_vlan_groups */
    .max_regions = 0,
    .max_flood_tables = 0,
    .max_per_vid_flood_tables = 0,
    .flood_mode = 0,
    .max_ib_mc = 16, /*8k (16 * 512) multicast groups will be supported*/
    .max_pkey = 32,
    .ar_sec = 2,
    .adaptive_routing_group_cap = 2048,
    .arn = 1,
    .swid0_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_INFINIBAND
    },
    .swid1_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid2_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid3_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid4_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid5_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid6_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .swid7_config_type = {
        .mask = 1,
        .type = KU_SWID_TYPE_DISABLED
    },
    .chip_type = IB_INVALID_CHIP /*it will be assigned on mlnx_sai_get_ku_profile function. */
};

static uint32_t               g_num_of_swids = 1;
static bool                   g_adaptive_routing_en = true;
static uint32_t               g_adaptive_routing_group_cap = 2048;
static bool                   g_ib_routing_en = false;
static bool                   g_breakout_mode_en = false;
static bool                   g_ib_operation_mode = true;
static struct sx_pci_profile *g_pci_profile = NULL;

#define IB_IPOIB_IF_DEFAULT_NAME    "ib%u"
#define IB_IPOIB_IF_NAME_FORMAT     "ib%u"
#define IB_IPOIB_SMA_IF_NAME_FORMAT "sma_ib%u"

static sai_status_t mlnx_sai_get_pci_profile(sx_api_pci_profile_t* pci_profile_p)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     swid = 0, sdq_idx = 0, rdq_idx = 0, i = 0;

    switch (g_sai_db_ptr->profile) {
    case SYS_SWID_PROFILE_IB_SINGLE_SWID:
        memcpy(pci_profile_p, &(pci_profile_single_ib), sizeof(struct sx_pci_profile));
        pci_profile_p->rdq_properties[IB_QP0_RDQ_CRITICAL_SINGLE_SWID_NUMBER].number_of_entries =
            IB_RDQ_MAD_NUMBER_OF_ENTRIES;
        break;

    case SYS_SWID_PROFILE_IB_NAR_SINGLE_SWID:
        memcpy(pci_profile_p, &(pci_profile_single_ib), sizeof(struct sx_pci_profile));
        pci_profile_p->rdq_properties[IB_QP0_RDQ_CRITICAL_SINGLE_SWID_NUMBER].number_of_entries =
            IB_RDQ_MAD_NUMBER_OF_ENTRIES;
        pci_profile_p->pci_profile = PCI_PROFILE_IB_NAR_SINGLE_SWID;
        break;

    case SYS_SWID_PROFILE_IB_MULTI_SWID:
        pci_profile_p->pci_profile = PCI_PROFILE_IB_MULTI_SWID;
        pci_profile_p->max_pkey = 8;
        /* Run on number of SWIDs defined */
        for (swid = 0; swid < g_sai_db_ptr->num_of_swids; swid++) {
            /* Set SDQs for tx profile */
            for (i = 6; i >= 4; i--) {
                if (sdq_idx > NUMBER_OF_SDQS) {
                    MLNX_SAI_LOG_ERR("SDQ index:[%u] too big in SWID:[%u]", sdq_idx, swid);
                    status = SAI_STATUS_FAILURE;
                    goto out;
                }
                pci_profile_p->tx_prof[swid][i].sdq = sdq_idx++;
            }
            pci_profile_p->tx_prof[swid][0].sdq = pci_profile_p->tx_prof[swid][4].sdq;
            pci_profile_p->tx_prof[swid][1].sdq = pci_profile_p->tx_prof[swid][4].sdq;
            pci_profile_p->tx_prof[swid][2].sdq = pci_profile_p->tx_prof[swid][4].sdq;
            pci_profile_p->tx_prof[swid][3].sdq = pci_profile_p->tx_prof[swid][4].sdq;
            pci_profile_p->tx_prof[swid][7].sdq = pci_profile_p->tx_prof[swid][4].sdq;

            /* Set swid type to infiniband */
            pci_profile_p->swid_type[swid] = SX_KU_L2_TYPE_IB;

            /* Set IB routing capability */
            if (g_sai_db_ptr->ib_routing_en) {
                pci_profile_p->ipoib_router_port_enable[swid] = 1;
            }

            /* Set RDQs per SWID */
            pci_profile_p->rdq_count[swid] = 4;
            for (i = 0; i < pci_profile_p->rdq_count[swid]; i++) {
                if (rdq_idx >= NUMBER_OF_RDQS) {
                    MLNX_SAI_LOG_ERR("RDQ index:[%u] too big in SWID:[%u]", rdq_idx, swid);
                    status = SAI_STATUS_FAILURE;
                    goto out;
                }
                pci_profile_p->rdq_properties[rdq_idx].number_of_entries = IB_RDQ_DEFAULT_NUMBER_OF_ENTRIES;
                pci_profile_p->rdq_properties[rdq_idx].rdq_weight = IB_RDQ_MULTI_SWID_DEFAULT_WEIGHT;
                if (i == 0) {
                    pci_profile_p->rdq_properties[rdq_idx].entry_size = IB_RDQ_QP0_DEFAULT_SIZE;
                } else if (i == 1) {
                    pci_profile_p->rdq_properties[rdq_idx].entry_size = IB_RDQ_QP1_DEFAULT_SIZE;
                } else {
                    pci_profile_p->rdq_properties[rdq_idx].entry_size = IB_RDQ_UD_DEFAULT_SIZE;
                }
                pci_profile_p->rdq[swid][i] = rdq_idx++;
            }
        }
        break;

    default:
        MLNX_SAI_LOG_ERR("%s: reached default case on PCI profile switch",
                         __func__);
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    pci_profile_p->dev_id = g_device_id;
out:
    return status;
}

static sx_api_profile_t* mlnx_sai_get_ku_profile()
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    single_part_ib_device_profile.dev_id = g_device_id;
    switch (chip_type) {
    case SX_CHIP_TYPE_QUANTUM:
        single_part_ib_device_profile.chip_type = SXD_CHIP_TYPE_QUANTUM;
        return &single_part_ib_device_profile;

    case SX_CHIP_TYPE_SWITCH_IB2:
        single_part_ib_device_profile.chip_type = SXD_CHIP_TYPE_SWITCH_IB2;
        return &single_part_ib_device_profile;

    case SX_CHIP_TYPE_QUANTUM2:
        single_part_ib_device_profile.chip_type = SXD_CHIP_TYPE_QUANTUM2;
        return &single_part_ib_device_profile;

    case SX_CHIP_TYPE_QUANTUM3:
        single_part_ib_device_profile.chip_type = SXD_CHIP_TYPE_QUANTUM3;
        return &single_part_ib_device_profile;

    default:
        MLNX_SAI_LOG_ERR("g_sai_db_ptr->sxd_chip_type = %s\n", SX_CHIP_TYPE_STR(chip_type));
        return NULL;
    }

    return NULL;
}

static struct ku_swid_config* mlnx_get_swid_config_from_device_profile(struct ku_profile *device_profile_p,
                                                                       uint32_t           swid)
{
    struct ku_swid_config *swid_config = NULL;

    if (NULL == device_profile_p) {
        MLNX_SAI_LOG_ERR("%s: device profile was not initialized", __func__);
        goto out;
    }

    switch (swid) {
    case 0:
        swid_config = &device_profile_p->swid0_config_type;
        break;

    case 1:
        swid_config = &device_profile_p->swid1_config_type;
        break;

    case 2:
        swid_config = &device_profile_p->swid2_config_type;
        break;

    case 3:
        swid_config = &device_profile_p->swid3_config_type;
        break;

    case 4:
        swid_config = &device_profile_p->swid4_config_type;
        break;

    case 5:
        swid_config = &device_profile_p->swid5_config_type;
        break;

    case 6:
        swid_config = &device_profile_p->swid6_config_type;
        break;

    case 7:
        swid_config = &device_profile_p->swid7_config_type;
        break;

    default:
        MLNX_SAI_LOG_ERR("%s: got unsupported swid %u", __func__, swid);
        break;
    }
out:
    return swid_config;
}

/*
 *  Configure split ready parameter to SDK according to system type.
 *  This parameter control MAD reports to SM and MC table configurations.
 */
static void configure_split_ready(uint8_t* split_ready)
{
    switch (g_sai_db_ptr->sx_chip_type) {
    case SX_CHIP_TYPE_QUANTUM2:
        *split_ready = SPLIT_READY_2X;
        break;

    case SX_CHIP_TYPE_QUANTUM3:
        /*TODO: change according to system type (NVL/IB) */
        /* MOCK */
        *split_ready = SPLIT_READY_1X;
        break;

    default:
        *split_ready = SPLIT_READY_4X;
    }
}

static sai_status_t mlnx_ku_profile_prepare(sx_api_profile_t* ret_device_profile_p)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     swid = 0;

    switch (g_pci_profile->pci_profile) {
    case PCI_PROFILE_IB_SINGLE_SWID:
        break;

    case PCI_PROFILE_IB_NAR_SINGLE_SWID:
        ret_device_profile_p->arn = 0;
        ret_device_profile_p->max_ib_mc = 32;
        ret_device_profile_p->ar_sec = 0;
        ret_device_profile_p->adaptive_routing_group_cap = 0;
        break;

    case PCI_PROFILE_IB_MULTI_SWID:
        if ((g_sai_db_ptr->sx_chip_type == SX_CHIP_TYPE_SWITCH_IB2) && g_sai_db_ptr->breakout_mode_en) {
            MLNX_SAI_LOG_WRN("IB split enable on SWITCH_IB2 invalid");
            g_sai_db_ptr->breakout_mode_en = false;
        }
        if (g_sai_db_ptr->breakout_mode_en) {
            ret_device_profile_p->set_mask_0_63 = 0x14f3ff;
            configure_split_ready(&ret_device_profile_p->split_ready);
        } else {
            ret_device_profile_p->set_mask_0_63 = 0x4f3ff;
        }
        ret_device_profile_p->max_ib_mc = 27;
        ret_device_profile_p->max_pkey = 32;
        for (swid = 0; swid < NUMBER_OF_SWIDS; swid++) {
            struct ku_swid_config *swid_config = mlnx_get_swid_config_from_device_profile(ret_device_profile_p, swid);
            if (swid_config && (g_pci_profile->swid_type[swid] == SX_KU_L2_TYPE_IB)) {
                swid_config->type = KU_SWID_TYPE_INFINIBAND;

                if (g_pci_profile->ipoib_router_port_enable[swid]) {
                    /* IB Routing capability is enabled */
                    swid_config->mask = 3;
                    /* Bit 2 is set for enabling RPA */
                    swid_config->properties = 0x4;
                    ret_device_profile_p->ib_router_en = 1;
                } else {
                    swid_config->mask = 1;
                }
            }
        }
        if (g_sai_db_ptr->adaptive_routing_en) {
            ret_device_profile_p->arn = 1;
            if (g_sai_db_ptr->num_of_swids == 1) {
                g_sai_db_ptr->adaptive_routing_group_cap = 2048;
            } else {
                g_sai_db_ptr->adaptive_routing_group_cap = 256;
            }
            g_adaptive_routing_group_cap = g_sai_db_ptr->adaptive_routing_group_cap;
            ret_device_profile_p->adaptive_routing_group_cap = g_sai_db_ptr->adaptive_routing_group_cap;
            ret_device_profile_p->ar_sec = 2;
        }
        break;

    default:
        MLNX_SAI_LOG_ERR("%s: reached default case on PCI profile switch",
                         __func__);
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    if ((g_sai_db_ptr->adaptive_routing_group_cap >= IB_MIN_ADAPTIVE_ROUTING_GROUP_CAP) &&
        (g_sai_db_ptr->adaptive_routing_group_cap <= IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP)) {
        if (g_sai_db_ptr->adaptive_routing_group_cap % IB_ADAPTIVE_ROUTING_GROUP_CAP_DIVISOR) {
            MLNX_SAI_LOG_ERR("%s: adapting routing group capability must be a multiple of %d\n",
                             __func__, IB_ADAPTIVE_ROUTING_GROUP_CAP_DIVISOR);
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        ret_device_profile_p->adaptive_routing_group_cap = g_sai_db_ptr->adaptive_routing_group_cap;
    }
    if (ret_device_profile_p->split_ready) {
        if (g_sai_db_ptr->adaptive_routing_group_cap > IB_MAX_ALLOWED_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY) {
            /*This can't happen when user set max argc, since there are internal controls not to allow him that.
             * But if user didn't set, we will have default value for chip,
             * that may be greater than IB_MAX_ALLOWED_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY*/
            g_adaptive_routing_group_cap = IB_MAX_ALLOWED_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY;
            g_sai_db_ptr->adaptive_routing_group_cap = g_adaptive_routing_group_cap;
            ret_device_profile_p->adaptive_routing_group_cap = g_sai_db_ptr->adaptive_routing_group_cap;
        }

        /*The value of max_ib_mc should be configured accordingly as follow:
         * ((2048 - adaptive_routing_group_cap)*4)/512
         */
        ret_device_profile_p->max_ib_mc =
            (IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP_SPLIT_READY - ret_device_profile_p->adaptive_routing_group_cap) / 128;
    } else {
        /*The value of max_ib_mc should be configured accordingly as follow:
         * ((4096 - adaptive_routing_group_cap)*4)/512
         */
        ret_device_profile_p->max_ib_mc =
            (IB_MAX_ADAPTIVE_ROUTING_GROUP_CAP - ret_device_profile_p->adaptive_routing_group_cap) / 128;
    }

out:
    return status;
}


uint8_t mlnx_port_mac_mask_get(void)
{
    return PORT_MAC_BITMASK_QTM;
}

/* This function return 0 for now because we don't need shared memory.
 * when we use stats , we will need to implement it.*/
size_t mlnx_sai_rm_db_size_get(void)
{
    return 0;
}

sai_status_t mlnx_sai_db_initialize(const char *config_file, sx_chip_types_t chip_type)
{
    sai_status_t status = SAI_STATUS_FAILURE;

    if (SAI_STATUS_SUCCESS != (status = sai_db_create())) {
        MLNX_SAI_LOG_ERR("%s: failed to create sai db\n", __func__);
        return status;
    }

    sai_db_values_init();

    g_sai_db_ptr->sx_chip_type = chip_type;

    if (SAI_STATUS_SUCCESS != (status = mlnx_parse_config(config_file))) {
        MLNX_SAI_LOG_ERR("%s: failed to parse config file\n", __func__);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_resource_mng_stage(bool warm_recover, mlnx_sai_boot_type_t boot_type)
{
    sxd_status_t              sxd_ret = SXD_STATUS_SUCCESS;
    sxd_ctrl_pack_t           ctrl_pack;
    struct ku_dpt_path_add    path;
    struct ku_dpt_path_modify path_modify;
    struct ku_swid_details    swid_details;
    char                      dev_name[MAX_NAME_LEN];
    char                     *dev_names[1] = { dev_name };
    uint32_t                  dev_num = 1;
    uint32_t                  ii;
    const bool                initialize_dpt = !warm_recover;
    const bool                reset_asic = !warm_recover && (BOOT_TYPE_WARM != boot_type) &&
                                           (BOOT_TYPE_FAST != boot_type);

    memset(&ctrl_pack, 0, sizeof(sxd_ctrl_pack_t));
    memset(&swid_details, 0, sizeof(swid_details));
    memset(&path_modify, 0, sizeof(path_modify));

    /* allocate space for the arrays */
    g_pci_profile = (struct sx_pci_profile*)malloc(sizeof(struct sx_pci_profile));
    if (g_pci_profile == NULL) {
        MLNX_SAI_LOG_ERR("%s: failed to allocate memory\n", __func__);
        return SAI_STATUS_FAILURE;
    }
    memset(g_pci_profile, 0, sizeof(*g_pci_profile));

    /* sxd_dpt_init will destroy existing dpt shared memory and create new one.
     * For warmboot we want to keep the old shared memory before reboot */
    if (initialize_dpt) {
        sxd_ret = sxd_dpt_init(SYS_TYPE_IB, sai_log_cb, LOG_VAR_NAME(__MODULE__));
        if (SXD_CHECK_FAIL(sxd_ret)) {
            MLNX_SAI_LOG_ERR("Failed to init dpt - %s.\n", SXD_STATUS_MSG(sxd_ret));
            return SAI_STATUS_FAILURE;
        }
    }

    sxd_ret = sxd_dpt_set_access_control(g_device_id, READ_WRITE);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed to set dpt access control - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SAI_STATUS_FAILURE;
    }

    sxd_ret = sxd_access_reg_init(0, sai_log_cb, LOG_VAR_NAME(__MODULE__));
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed to init access reg - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return SAI_STATUS_FAILURE;
    }

    /* get device list from the devices directory */
    sxd_ret = sxd_get_dev_list(dev_names, &dev_num);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("sxd_get_dev_list error %s.\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    /* open the first device */
    sxd_ret = sxd_open_device(dev_name, &g_sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("sxd_open_device error %s.\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }

    MLNX_SAI_LOG_INF("sxd ioctl add path i2c start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_ADD_DEV_PATH;
    ctrl_pack.cmd_body = (void*)&(path);
    memset(&path, 0, sizeof(struct ku_dpt_path_add));
    path.dev_id = g_device_id;
    path.path_type = DPT_PATH_I2C;
    path.path_info.sx_i2c_info.sx_i2c_dev = 0x420248;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to add I2C dev path to DP table, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl add path i2c end\n");

    MLNX_SAI_LOG_INF("sxd ioctl add path pci start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_ADD_DEV_PATH;
    ctrl_pack.cmd_body = (void*)&(path);
    memset(&path, 0, sizeof(struct ku_dpt_path_add));
    path.dev_id = g_device_id;
    path.path_type = DPT_PATH_PCI_E;
    path.path_info.sx_pcie_info.pci_id = 18100;
    path.is_local = 1;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to add PCI dev path to DP table, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl add path pci end\n");

    MLNX_SAI_LOG_INF("sxd ioctl set cmd path start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_CMD_PATH;
    ctrl_pack.cmd_body = (void*)&(path_modify);
    path_modify.dev_id = g_device_id;
    path_modify.path_type = DPT_PATH_PCI_E;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to set cmd_ifc path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl set cmd path end\n");

    MLNX_SAI_LOG_INF("sxd ioctl set emad path start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_EMAD_PATH;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to set emad path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl set emad path end\n");

    MLNX_SAI_LOG_INF("sxd ioctl set mad path start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_MAD_PATH;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to set mad path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl set mad path end\n");

    MLNX_SAI_LOG_INF("sxd ioctl set cr access path start\n");
    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_CR_ACCESS_PATH;
    sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("failed to set cr access path in DP table to PCI, error: %s\n", strerror(errno));
        return SAI_STATUS_FAILURE;
    }
    MLNX_SAI_LOG_INF("sxd ioctl set cr access path end\n");


    if (reset_asic) {
        MLNX_SAI_LOG_INF("sxd set mad demux enable start\n");
        sxd_ret = sxd_set_mad_demux(g_device_id, true);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            MLNX_SAI_LOG_ERR("failed to set device MAD_DEMUX to enable, error: %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }
        MLNX_SAI_LOG_INF("sxd set mad demux enable end\n");

        MLNX_SAI_LOG_INF("sxd ioctl reset start\n");
        ctrl_pack.ctrl_cmd = CTRL_CMD_RESET;
        ctrl_pack.cmd_body = (void*)((intptr_t)g_device_id);
        sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            MLNX_SAI_LOG_ERR("failed to reset asic, error: %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }
        MLNX_SAI_LOG_INF("sxd ioctl reset end\n");

        if (SX_STATUS_SUCCESS != mlnx_sai_get_pci_profile(g_pci_profile)) {
            SX_LOG_ERR("Failed to prepare PCI profile\n");
            return SAI_STATUS_FAILURE;
        }

        MLNX_SAI_LOG_INF("sxd ioctl set pci profile start\n");
        ctrl_pack.ctrl_cmd = CTRL_CMD_SET_PCI_PROFILE;
        ctrl_pack.cmd_body = (void*)g_pci_profile;
        sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            MLNX_SAI_LOG_ERR("failed to set pci profile in asic, error: %s\n", strerror(errno));
            return SAI_STATUS_FAILURE;
        }
        MLNX_SAI_LOG_INF("sxd ioctl set pci profile end\n");

        /* enable device's swid */
        swid_details.dev_id = g_device_id;
        ctrl_pack.cmd_body = (void*)&(swid_details);
        ctrl_pack.ctrl_cmd = CTRL_CMD_ENABLE_SWID;
        for (ii = 0; ii < g_sai_db_ptr->num_of_swids; ++ii) {
            MLNX_SAI_LOG_INF("sxd ioctl enabled swid start\n");
            swid_details.swid = ii;
            swid_details.iptrap_synd = SXD_TRAP_ID_IPTRAP_MIN + ii;
            cl_plock_acquire(&g_sai_db_ptr->p_lock);
            swid_details.mac = SX_MAC_TO_U64(g_sai_db_ptr->base_mac_addr);
            cl_plock_release(&g_sai_db_ptr->p_lock);

            sxd_ret = sxd_ioctl(g_sxd_handle, &ctrl_pack);
            if (SXD_CHECK_FAIL(sxd_ret)) {
                MLNX_SAI_LOG_ERR("failed to enable swid %u : %s\n", ii, strerror(errno));
                return SAI_STATUS_FAILURE;
            }
            MLNX_SAI_LOG_INF("sxd ioctl enabled swid end\n");
        }
    }

    return SAI_STATUS_SUCCESS;
}


sx_status_t get_chip_type(enum sxd_chip_types* chip_type)
{
    uint16_t device_hw_revision;
    uint16_t device_id;
    FILE   * f = NULL;
    int      rc;

#ifdef _WIN32
#define SCNu16 "u"
#endif

    f = fopen("/sys/module/sx_core/parameters/chip_info_type", "r");
    if (f == NULL) {
        MLNX_SAI_LOG_ERR("failed to open /sys/module/sx_core/parameters/chip_info_type\n");
        return SX_STATUS_ERROR;
    }

    rc = fscanf(f, "%" SCNu16, &device_id);
    fclose(f);

    if (rc != 1) {
        MLNX_SAI_LOG_ERR("failed to open /sys/module/sx_core/parameters/chip_info_type\n");
        return SX_STATUS_ERROR;
    }

    f = fopen("/sys/module/sx_core/parameters/chip_info_revision", "r");
    if (f == NULL) {
        MLNX_SAI_LOG_ERR("failed to open /sys/module/sx_core/parameters/chip_info_revision\n");
        return SX_STATUS_ERROR;
    }

    rc = fscanf(f, "%" SCNu16, &device_hw_revision);
    fclose(f);

    if (rc != 1) {
        MLNX_SAI_LOG_ERR("failed to open /sys/module/sx_core/parameters/chip_info_revision\n");
        return SX_STATUS_ERROR;
    }

    switch (device_id) {
    case SXD_MGIR_HW_DEV_ID_QUANTUM:
        *chip_type = SXD_CHIP_TYPE_QUANTUM;
        break;

    case SXD_MGIR_HW_DEV_ID_QUANTUM2:
        *chip_type = SXD_CHIP_TYPE_QUANTUM2;
        break;

    case SXD_MGIR_HW_DEV_ID_SWITCH_IB2:
        *chip_type = SXD_CHIP_TYPE_SWITCH_IB2;
        break;

    case SXD_MGIR_HW_DEV_ID_QUANTUM3:
        *chip_type = SXD_CHIP_TYPE_QUANTUM3;
        break;

    default:
        MLNX_SAI_LOG_ERR("Unsupported device %u %u\n", device_id, device_hw_revision);
        return SX_STATUS_ERROR;
    }

    return SX_STATUS_SUCCESS;
}


static sai_status_t mlnx_chassis_mng_stage(mlnx_sai_boot_type_t boot_type, sx_api_profile_t    *ku_profile)
{
    sx_status_t                    status;
    sx_api_sx_sdk_init_t           sdk_init_params;
    sx_log_verbosity_target_attr_t log_verbosity_target_attr = { 0 };

    if (NULL == ku_profile) {
        return SAI_STATUS_FAILURE;
    }

    memset(&sdk_init_params, 0, sizeof(sdk_init_params));

    /* Open an handle */
    if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &gh_sdk))) {
        MLNX_SAI_LOG_ERR("Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    log_verbosity_target_attr.verbosity_target = SX_LOG_VERBOSITY_BOTH;
    log_verbosity_target_attr.enable = 1;
    if (SX_STATUS_SUCCESS !=
        (status = sx_api_system_log_enter_func_severity_set(gh_sdk, &log_verbosity_target_attr))) {
        SX_LOG_ERR("Set system log func severity failed - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }
    sx_log_funcs_severity_set(true);

    sdk_init_params.app_id = htonl(*((uint32_t*)"SDK1"));

    sdk_init_params.profile.do_not_config_profile_to_device = 1;

    sdk_init_params.port_params.max_dev_id = SX_DEV_ID_MAX;

    sdk_init_params.topo_params.max_num_of_tree_per_chip = 18; /* max num of trees */

    sdk_init_params.port_params.port_phy_bits_num = SX_PORT_UCR_ID_PHY_NUM_OF_BITS;
    sdk_init_params.port_params.port_pth_bits_num = 6;
    sdk_init_params.port_params.port_sub_bits_num = 4;

    memcpy(&(sdk_init_params.profile), ku_profile, sizeof(struct ku_profile));
    memcpy(&(sdk_init_params.pci_profile), g_pci_profile, sizeof(struct sx_pci_profile));
    sdk_init_params.applibs_mask = SX_API_HOST_IFC | SX_API_ETH_L2 | SX_API_IB | SX_API_MGMT_LIB;
    status = get_chip_type(&sdk_init_params.profile.chip_type);
    if (SX_ERR(status)) {
        SX_LOG_ERR("get_chip_type failed\n");
        return SAI_STATUS_FAILURE;
    }
    switch (boot_type) {
    case BOOT_TYPE_REGULAR:
        sdk_init_params.boot_mode_params.boot_mode = SX_BOOT_MODE_NORMAL_E;
        break;

    case BOOT_TYPE_WARM:
        break;

    case BOOT_TYPE_FAST:
        sdk_init_params.boot_mode_params.boot_mode = SX_BOOT_MODE_FAST_E;
        break;

    default:
        SX_LOG_ERR("Unsupported boot type %d\n", boot_type);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_INF("SDK init set start\n");
    if (SX_STATUS_SUCCESS != (status = sx_api_sdk_init_set(gh_sdk, &sdk_init_params))) {
        SX_LOG_ERR("Failed to initialize SDK (%s)\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    SX_LOG_NTC("SDK initialized successfully\n");

    status = mlnx_sai_log_levels_post_init();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}


bool mlnx_chip_is_qtm(void)
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(chip_type != SX_CHIP_TYPE_UNKNOWN);

    return chip_type == SX_CHIP_TYPE_QUANTUM;
}

bool mlnx_chip_is_qtm2(void)
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(chip_type != SX_CHIP_TYPE_UNKNOWN);

    return chip_type == SX_CHIP_TYPE_QUANTUM2;
}

bool mlnx_chip_is_qtm3(void)
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(chip_type != SX_CHIP_TYPE_UNKNOWN);

    return chip_type == SX_CHIP_TYPE_QUANTUM3;
}

bool mlnx_chip_is_sib2(void)
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(chip_type != SX_CHIP_TYPE_UNKNOWN);

    return chip_type == SX_CHIP_TYPE_SWITCH_IB2;
}

/*
 * This function is used only for Eth to parse port config from sai.xml
 */
sai_status_t parse_port_info(xmlDoc *doc, xmlNode * port_node)
{
    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_config_platform_parse(_In_ const char *platform)
{
    assert(platform);

    MLNX_SAI_LOG_NTC("platform: %s\n", platform);

    g_sai_db_ptr->platform_type = (mlnx_platform_type_t)atoi(platform);

    return SAI_STATUS_SUCCESS;
}


static void sai_db_values_init()
{
    uint32_t            ii;
    mlnx_port_config_t *port;

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    memset(&g_sai_db_ptr->base_mac_addr, 0, sizeof(g_sai_db_ptr->base_mac_addr));
    memset(g_sai_db_ptr->dev_mac, 0, sizeof(g_sai_db_ptr->dev_mac));
    g_sai_db_ptr->ports_configured = 0;
    g_sai_db_ptr->ports_number = 0;
    memset(g_sai_db_ptr->ports_db, 0, sizeof(g_sai_db_ptr->ports_db));
    memset(&g_sai_db_ptr->callback_channel, 0, sizeof(g_sai_db_ptr->callback_channel));
    g_sai_db_ptr->boot_type = 0;
    g_sai_db_ptr->platform_type = MLNX_PLATFORM_TYPE_INVALID;
    memset(&g_sai_db_ptr->dump_configuration, 0, sizeof(mlnx_dump_configuration_t));
    g_sai_db_ptr->breakout_mode_en = g_breakout_mode_en;
    g_sai_db_ptr->ib_operation_mode = g_ib_operation_mode;
    g_sai_db_ptr->num_of_swids = g_num_of_swids;
    g_sai_db_ptr->adaptive_routing_en = g_adaptive_routing_en;
    g_sai_db_ptr->adaptive_routing_group_cap = g_adaptive_routing_group_cap;
    g_sai_db_ptr->ib_routing_en = g_ib_routing_en;
    g_sai_db_ptr->switch_type = g_switch_type;
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);

    for (ii = 0; ii < MAX_PORTS * 2; ii++) {
        port = &g_sai_db_ptr->ports_db[ii];
        port->port_map.mapping_mode = SX_PORT_MAPPING_MODE_DISABLE;
        port->port_map.local_port = ii + 1;
        port->index = ii;
        port->down_by_signal_degrade = false;
    }

    if ((g_num_of_swids > 1) || g_breakout_mode_en) {
        g_sai_db_ptr->profile = SYS_SWID_PROFILE_IB_MULTI_SWID;
    } else if (!g_sai_db_ptr->adaptive_routing_en) {
        g_sai_db_ptr->profile = SYS_SWID_PROFILE_IB_NAR_SINGLE_SWID;
    } else {
        g_sai_db_ptr->profile = SYS_SWID_PROFILE_IB_SINGLE_SWID;
    }

    cl_plock_release(&g_sai_db_ptr->p_lock);
}

static sai_status_t mlnx_set_swid_per_port(uint32_t local_port, uint32_t swid)
{
    sai_status_t       status;
    struct ku_pspa_reg pspa_reg;

    memset(&pspa_reg, 0, sizeof(pspa_reg));
    pspa_reg.swid = swid;
    pspa_reg.sub_port = 0;
    pspa_reg.local_port = local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pspa_register(SXD_ACCESS_CMD_SET,
                                                                   g_swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pspa_reg))) {
        MLNX_SAI_LOG_ERR("Failed set PSPA for local port: [%u], device: [%u], swid [%u]\n",
                         local_port, g_device_id, g_swid_id);
    }

    return status;
}

static sai_status_t mlnx_dvs_mng_stage(mlnx_sai_boot_type_t boot_type, sai_object_id_t switch_id)
{
    sai_status_t          status;
    sx_status_t           sx_status;
    sx_port_attributes_t *port_attributes_p = NULL;
    uint32_t              ii;
    sx_topolib_dev_info_t dev_info;
    mlnx_port_config_t   *port;
    uint32_t              ports_to_map;
    uint32_t              swid_num = 0;
    uint32_t              local_port;
    sx_port_mapping_t    *port_mapping = NULL;
    sx_port_log_id_t     *log_ports = NULL;

    memset(&dev_info, 0, sizeof(dev_info));

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    for (swid_num = 0; swid_num < g_sai_db_ptr->num_of_swids; swid_num++) {
        if (SX_STATUS_SUCCESS != (status = sx_api_port_swid_set(gh_sdk, SX_ACCESS_CMD_ADD, swid_num))) {
            SX_LOG_ERR("Port swid set failed - %s.\n", SX_STATUS_MSG(status));
            status = sdk_to_sai(status);
            goto out;
        }
    }

    port_attributes_p =
        (sx_port_attributes_t*)calloc((g_sai_db_ptr->num_of_swids + MAX_PORTS), sizeof(*port_attributes_p));
    if (NULL == port_attributes_p) {
        SX_LOG_ERR("Can't allocate port attributes\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    port_mapping = calloc(MAX_PORTS, sizeof(*port_mapping));
    if (!port_mapping) {
        SX_LOG_ERR("Failed to allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    log_ports = calloc(MAX_PORTS, sizeof(*log_ports));
    if (!log_ports) {
        SX_LOG_ERR("Failed to allocate memory\n");
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }

    for (ports_to_map = 0; ports_to_map < MAX_PORTS; ports_to_map++) {
        port = mlnx_port_by_idx(ports_to_map + 1); /* we don't want to map local port 0!! */
        if (port == NULL) {
            SX_LOG_ERR("Can't Get port.\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        port_attributes_p[ports_to_map].port_mode = SX_PORT_MODE_EXTERNAL;
        memcpy(&port_attributes_p[ports_to_map].port_mapping, &port->port_map, sizeof(port->port_map));
    }

    status = sx_api_port_device_set(gh_sdk, SX_ACCESS_CMD_ADD, g_device_id, &g_sai_db_ptr->base_mac_addr,
                                    port_attributes_p, ports_to_map);

    for (ii = 0; ii < MAX_PORTS; ii++) {
        port = mlnx_port_by_local_id(port_attributes_p[ii].port_mapping.local_port);
        port->logical = port_attributes_p[ii].log_port;
        status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, port->logical, NULL, &port->saiport);
        if (SAI_ERR(status)) {
            goto out;
        }
    }

    dev_info.dev_id = g_device_id;
    dev_info.node_type = SX_DEV_NODE_TYPE_LEAF_LOCAL;
    dev_info.unicast_arr_len = 0;
    dev_info.unicast_tree_hndl_arr[0] = 0;

    if (SX_STATUS_SUCCESS != (status = sx_api_topo_device_set(gh_sdk, SX_ACCESS_CMD_ADD, &dev_info))) {
        SX_LOG_ERR("topo device add failed - %s.\n", SX_STATUS_MSG(status));
        status = sdk_to_sai(status);
        goto out;
    }

    if (g_notification_callbacks.on_switch_state_change) {
        g_notification_callbacks.on_switch_state_change(switch_id, SAI_SWITCH_OPER_STATUS_UP);
    }

    ports_to_map = 0;
    for (ii = 0; ii < MAX_PORTS; ii++) {
        if (!g_sai_db_ptr->ports_db[ii].is_present) {
            continue;
        }
        local_port = g_sai_db_ptr->ports_db[ii].port_map.local_port;
        port_mapping[ports_to_map].mapping_mode = SX_PORT_MAPPING_MODE_DISABLE;
        port_mapping[ports_to_map].local_port = local_port;
        log_ports[ports_to_map] = g_sai_db_ptr->ports_db[ii].logical;
        ports_to_map++;
        if (g_is_chipsim) {
            mlnx_set_swid_per_port(local_port, INVALID_SWID);
        }
    }

    sx_status = sx_api_port_mapping_set(gh_sdk, log_ports, port_mapping, ports_to_map);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to unmap ports - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    ports_to_map = 0;
    for (ii = 0; ii < MAX_PORTS; ii++) {
        if (!g_sai_db_ptr->ports_db[ii].is_present) {
            continue;
        }

        port_mapping[ports_to_map] = g_sai_db_ptr->ports_db[ii].port_map;
        ports_to_map++;
    }

    sx_status = sx_api_port_mapping_set(gh_sdk, log_ports, port_mapping, ports_to_map);
    if (SX_ERR(sx_status)) {
        SX_LOG_ERR("Failed to map ports - %s\n", SX_STATUS_MSG(sx_status));
        status = sdk_to_sai(sx_status);
        goto out;
    }

    for (ii = 0; ii < MAX_PORTS; ii++) {
        port = &mlnx_ports_db[ii];
        if (port->logical && port->is_present) {
            status = mlnx_port_config_init_mandatory(port);
            if (SAI_ERR(status)) {
                SX_LOG_ERR("Failed initialize port oid %" PRIx64 " config\n", port->saiport);
                goto out;
            }
        }
    }

out:
    sai_db_unlock();

    if (NULL != port_attributes_p) {
        free(port_attributes_p);
    }
    if (NULL != port_mapping) {
        free(port_mapping);
    }
    if (NULL != log_ports) {
        free(log_ports);
    }

    return status;
}


/**
 * Rename IPoIB devices
 *
 * IPoIB devices are automatically created for each IB device (in the kernel)
 * Its name is ibX where X is a sequential number 0..N
 * in our system when IB multi-swid is created, then IPoIB interfaces will be created
 * for each SWID, ib0..ibN where N is num_of_swids -1
 * if IB router is enabled, then an interface will also be created for all RPA devices,
 * and the current sequence is that all RPA ports are created after swid 0 is up.
 * So, when IB router is present ib0 will still be IPoIB for swid 0, but next ib1..ibN are
 * related to the RPA ports, and the IPoIB interface related to swid 1 is ib(N+1) when N is
 * the number of swids
 *
 * Example : 3 swids, no ib router -> ib0, ib1, ib2 related to swids 0,1,2
 *           3 swids, ib router -> ib0 to swid 0, ib4 to swid 1, ib5 to swid 2
 *
 * We shall rename per swid != IPoIB interface name to ibX when X is the SWID number.
 * @return
 */
static sai_status_t mlnx_rename_ipoib_devices()
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     j = 0;
    uint32_t     swid = 0;
    char         cmd[50];
    uint8_t      system_err = 0;

    if (g_sai_db_ptr->ib_routing_en) {
        j = 1;
        while (swid < g_sai_db_ptr->num_of_swids) {
            snprintf(cmd,
                     sizeof(cmd),
                     "ip link set " IB_IPOIB_IF_DEFAULT_NAME " name " IB_IPOIB_SMA_IF_NAME_FORMAT,
                     j,
                     j);
            j++;
            swid++;
            system_err = system(cmd);
            if (0 != system_err) {
                SX_LOG_ERR("Failed running \"%s\".\n", cmd);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }

        j = (g_sai_db_ptr->num_of_swids * g_sai_db_ptr->ib_routing_en) + 1;
        swid = 1;
        while (swid < g_sai_db_ptr->num_of_swids) {
            snprintf(cmd,
                     sizeof(cmd),
                     "ip link set " IB_IPOIB_IF_DEFAULT_NAME " name " IB_IPOIB_IF_NAME_FORMAT,
                     j++,
                     swid++);
            system_err = system(cmd);
            if (0 != system_err) {
                SX_LOG_ERR("Failed running \"%s\".\n", cmd);
                status = SAI_STATUS_FAILURE;
                goto out;
            }
        }
    }

out:
    return status;
}


static uint8_t mlnx_get_ib_port(uint32_t local)
{
    struct ku_plib_reg plib_reg;

    memset(&plib_reg, 0, sizeof(plib_reg));
    plib_reg.local_port = local;
    if (SAI_STATUS_SUCCESS != mlnx_set_get_plib_register(SXD_ACCESS_CMD_GET,
                                                         g_swid_id,
                                                         g_device_id,
                                                         NULL,
                                                         NULL,
                                                         &plib_reg)) {
        MLNX_SAI_LOG_ERR("Failed get PLIB for local port: [%u], device: [%u], swid [%u]\n",
                         local, g_device_id, g_swid_id);
        return INVALID_IB_PORT;
    }
    return plib_reg.ib_port;
}


static uint8_t mlnx_get_split_ib_port(uint32_t local)
{
    struct ku_plibdb_reg plibdb_reg;

    memset(&plibdb_reg, 0, sizeof(plibdb_reg));
    plibdb_reg.local_port = local;
    if (SAI_STATUS_SUCCESS != mlnx_set_get_plibdb_register(SXD_ACCESS_CMD_GET,
                                                           g_swid_id,
                                                           g_device_id,
                                                           NULL,
                                                           NULL,
                                                           &plibdb_reg)) {
        MLNX_SAI_LOG_ERR("Failed get PLIBDB for local port: [%u], device: [%u], swid [%u]\n",
                         local, g_device_id, g_swid_id);
        return INVALID_IB_PORT;
    }

    /*Gorilla in breakout-mode index port by 2x */
    return plibdb_reg.ib_port_2x;
}


static sai_status_t mlnx_get_default_module_lane_map(uint32_t local_port, sx_port_mapping_t* port_mapping)
{
    sai_status_t       status = SAI_STATUS_SUCCESS;
    struct ku_pmlp_reg pmlp_reg;
    uint32_t           ii;

    if ((local_port == 0) || (local_port > MAX_PORTS)) {
        port_mapping->module_port = 0;
        port_mapping->width = 0;
        port_mapping->lane_bmap = 0x0;
        port_mapping->local_port = local_port;
    } else {
        memset(&pmlp_reg, 0, sizeof(struct ku_pmlp_reg));
        pmlp_reg.local_port = local_port;
        if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pmlp_register(SXD_ACCESS_CMD_GET,
                                                                       g_swid_id,
                                                                       g_device_id,
                                                                       NULL,
                                                                       NULL,
                                                                       &pmlp_reg))) {
            MLNX_SAI_LOG_ERR("Failed get PMLP for local port: [%u], device: [%u], swid [%u]\n",
                             local_port, g_device_id, g_swid_id);
            goto out;
        }
        port_mapping->module_port = pmlp_reg.module[0];
        port_mapping->width = pmlp_reg.width;
        port_mapping->lane_bmap = 0x0;
        port_mapping->local_port = local_port;

        for (ii = 0; ii < pmlp_reg.width; ++ii) {
            port_mapping->lane_bmap |= (1 << (ii + pmlp_reg.lane[0]));
        }
    }

out:
    return status;
}

sai_status_t mlnx_get_default_label_port_from_local_port(mlnx_port_config_t* port)
{
    sai_status_t       status;
    struct ku_pllp_reg pllp_reg;

    if (NULL == port) {
        MLNX_SAI_LOG_ERR("Got Null pointer to port\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memset(&pllp_reg, 0, sizeof(pllp_reg));
    pllp_reg.local_port = port->port_map.local_port;

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_pllp_register(SXD_ACCESS_CMD_GET,
                                                                   g_swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &pllp_reg))) {
        MLNX_SAI_LOG_ERR("Failed get PLLP for local port: [%u], device: [%u], swid [%u]\n",
                         port->port_map.local_port, g_device_id, g_swid_id);
        goto out;
    }
    /* MOCK */
    port->label_port = pllp_reg.label_port;
    port->label_index = pllp_reg.ipil_num;
    port->protocol = SAI_PORT_PROTOCOL_IB;
    port->is_fnm = false;
    port->is_maf = false;
    port->conn_type = CONN_TYPE_FRONT_PANEL;
    port->remote_id = 0;

    /* TODO: comment out when supported by FW and SDK */
    /*port->protocol = pllp_reg.protocol;
     *  port->is_fnm = (bool)pllp_reg.is_fnm;
     *  port->is_maf = (bool)pllp_reg.is_fam;
     *  port->conn_type = pllp_reg.conn_type;
     *  port->remote_id = pllp_reg.rmt_id;*/

out:
    return status;
}

static sai_status_t mlnx_set_ib_node_description(uint8_t swid_id, const char* node_desc)
{
    sai_status_t       status;
    struct ku_spzr_reg spzr_reg;

    if (NULL == node_desc) {
        MLNX_SAI_LOG_ERR("Got Null pointer to node description\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    memset(&spzr_reg, 0, sizeof(spzr_reg));
    spzr_reg.swid = swid_id;
    spzr_reg.ndm = 1;
    memcpy(spzr_reg.node_description, node_desc, sizeof(spzr_reg.node_description));

    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_spzr_register(SXD_ACCESS_CMD_SET,
                                                                   swid_id,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &spzr_reg))) {
        MLNX_SAI_LOG_ERR("Failed set SPZR for node description: [%s], device: [%u], swid [%u]\n",
                         node_desc, g_device_id, swid_id);
    }
    /*use CTRL_CMD_SET_SW_IB_NODE_DESC to set the ib device description in the SDK
     * in case an ND MAD is routed to the CPU by the FW (MAD_DEMUX) the SDK will answer with this name
     * the SDK will only "enforce" this change for "default" device (I.E: PCI or OOB default as set to it)
     * so we can call for all devices the same. */
    status = sa_set_sdk_node_desc(g_sxd_handle,
                                  g_device_id,
                                  swid_id,
                                  node_desc);
    if (status != SAI_STATUS_SUCCESS) {
        SX_LOG_ERR("MLX_SAI - Failed to set IB NodeDescription in SDK to %s\n", node_desc);
        goto out;
    }
out:
    return status;
}

/**
 * This function returns the break modes available by chip (supported number of HW lanes)
 *
 * @return
 * SIB2 - NONE
 * QTM, QTM2 - 2x, 4x
 **/
static mlnx_port_breakout_capability_t get_breakout_modes_by_chip()
{
    sx_chip_types_t chip_type = g_sai_db_ptr->sx_chip_type;

    assert(chip_type != SX_CHIP_TYPE_UNKNOWN);

    switch (chip_type) {
    case SX_CHIP_TYPE_QUANTUM2:
    case SX_CHIP_TYPE_QUANTUM3:
        return MLNX_PORT_BREAKOUT_CAPABILITY_TWO_FOUR;

    default:
        return MLNX_PORT_BREAKOUT_CAPABILITY_NONE;
    }
}

static sai_status_t parse_ib_port_info()
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    mlnx_port_config_t *tmp_port;
    mlnx_port_config_t *port;
    uint32_t            local = 0;

    for (local = 0; local < MAX_LOGICAL_PORTS; local++) {
        port = mlnx_port_by_idx(local);
        if (port == NULL) {
            MLNX_SAI_LOG_ERR("Can't Get port.\n");
            status = SAI_STATUS_FAILURE;
            break;
        }

        port->breakout_modes = get_breakout_modes_by_chip();
        port->auto_neg = AUTO_NEG_DEFAULT;

        if (SAI_STATUS_SUCCESS != (status = mlnx_get_default_module_lane_map(local, &port->port_map))) {
            MLNX_SAI_LOG_ERR("%s: Failed to get default module lane map", __func__);
            break;
        }
        port->module = port->port_map.module_port;
        port->width = port->port_map.width;

        if ((local == 0) || (port->width == 0)) {
            port->label_port = 0;
        } else {
            /*MOCK */
            if (mlnx_chip_is_qtm3() && (local % 4 != 1)) {
                continue;
            }
            if (SAI_STATUS_SUCCESS != (status = mlnx_set_swid_per_port(local, g_swid_id))) {
                MLNX_SAI_LOG_ERR("%s: Failed to set default swid to local port %u", __func__, local);
                return status;
            }

            if (SAI_STATUS_SUCCESS !=
                (status =
                     mlnx_get_default_label_port_from_local_port(port))) {
                MLNX_SAI_LOG_ERR("%s: Failed to get default label port", __func__);
                return status;
            }

            port->is_present = true;
            g_sai_db_ptr->ports_number++;
            port->speed = g_sai_db_ptr->sx_chip_type == SX_CHIP_TYPE_QUANTUM2 ? PORT_SPEED_400 : PORT_SPEED_200;
            port->swid_id = (uint8_t)DEFAULT_IB_SWID;
            port->port_map.mapping_mode = SX_PORT_MAPPING_MODE_ENABLE;
        }

        if (local == 0) {
            MLNX_SAI_LOG_NTC("Label Port %u Ib port %u local=%u \n",
                             port->label_port,
                             port->ib_port,
                             port->port_map.local_port);
            continue;
        }

        /* TODO: remove after split_ready profile flow is fixed */
        if (g_sai_db_ptr->breakout_mode_en) {
            if (port->label_port) {
                port->split_index = 1;
            } else {
                tmp_port = mlnx_port_by_idx(local - 1);
                assert(tmp_port);
                port->label_port = tmp_port->label_port;
                port->label_index = tmp_port->label_index;
                port->split_index = 2;
            }
            port->ib_port = mlnx_get_split_ib_port(local);
        } else {
            port->ib_port = (port->is_present) ? mlnx_get_ib_port(local) : INVALID_IB_PORT;
        }

        MLNX_SAI_LOG_NTC(
            "Label Port %u Ib port %u{local=%u module=%u width=%u lanes=0x%x breakout-modes=%u split=%u, port-speed=%u}\n",
            port->label_port,
            port->ib_port,
            port->port_map.local_port,
            port->port_map.module_port,
            port->port_map.width,
            port->port_map.lane_bmap,
            port->breakout_modes,
            port->split_count,
            port->speed);
    }

    return status;
}

static void event_thread_func(void *context)
{
#define MAX_PACKET_SIZE MAX(g_resource_limits.port_mtu_max, SX_HOST_EVENT_BUFFER_SIZE_MAX)

    sx_status_t                          status;
    sx_api_handle_t                      api_handle;
    sx_user_channel_t                    port_channel, callback_channel;
    fd_set                               descr_set;
    int                                  ret_val;
    sai_object_id_t                      switch_id = (sai_object_id_t)context;
    uint8_t                             *p_packet = NULL;
    uint32_t                             packet_size;
    uint32_t                             ii;
    mlnx_port_config_t                  *port;
    sx_receive_info_t                   *receive_info = NULL;
    sai_port_oper_status_notification_t  port_data;
    sai_port_module_event_notification_t module_data;
    struct timeval                       timeout;
    sx_trap_group_t                      group = HWD_TRAP_GROUP;
    sx_host_ifc_trap_key_t               trap_key;
    sx_trap_group_attributes_t           group_attributes;
    sx_host_ifc_trap_attr_t              trap_attr;

    memset(&port_channel, 0, sizeof(port_channel));
    memset(&callback_channel, 0, sizeof(callback_channel));
    memset(&trap_attr, 0, sizeof(trap_attr));
    memset(&trap_key, 0, sizeof(trap_key));
    memset(&group_attributes, 0, sizeof(group_attributes));

    if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &api_handle))) {
        MLNX_SAI_LOG_ERR("Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        if (g_notification_callbacks.on_switch_shutdown_request) {
            g_notification_callbacks.on_switch_shutdown_request(switch_id);
        }
        return;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(api_handle, &port_channel.channel.fd))) {
        SX_LOG_ERR("host ifc open port fd failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    receive_info = (sx_receive_info_t*)calloc(1, sizeof(*receive_info));

    if (NULL == receive_info) {
        SX_LOG_ERR("Can't allocate receive_info memory\n");
        status = SX_STATUS_NO_MEMORY;
        goto out;
    }

    p_packet = (uint8_t*)malloc(sizeof(*p_packet) * MAX_PACKET_SIZE);
    if (NULL == p_packet) {
        SX_LOG_ERR("Can't allocate packet memory\n");
        status = SX_STATUS_ERROR;
        goto out;
    }
    SX_LOG_NTC("Event packet buffer size %u\n", MAX_PACKET_SIZE);

    port_channel.type = SX_USER_CHANNEL_TYPE_FD;

    /**
     * Signal degrade event requires special registration to SDK events,
     * unlike PUDE event.
     * first we bind group to swid, then we register the group to sdk and last, the trap itself to the group
     */
    if (g_notification_callbacks.on_signal_degrade != NULL) {
        group_attributes.prio = SX_TRAP_PRIORITY_HIGH;
        group_attributes.truncate_mode = SX_TRUNCATE_MODE_DISABLE;
        group_attributes.truncate_size = 0;
        group_attributes.control_type = SX_CONTROL_TYPE_DEFAULT;
        group_attributes.add_timestamp = false;

        if (SX_STATUS_SUCCESS !=
            (status = sx_api_host_ifc_trap_group_set(api_handle, g_swid_id, group, &group_attributes))) {
            SX_LOG_ERR("Failed mapping trap to group\n");
            goto out;
        }

        trap_key.type = HOST_IFC_TRAP_KEY_TRAP_ID_E;
        trap_key.trap_key_attr.trap_id = SX_TRAP_ID_BER_MONITOR;
        trap_attr.attr.trap_id_attr.trap_group = group;
        trap_attr.attr.trap_id_attr.trap_action = SX_TRAP_ACTION_TRAP_2_CPU;

        if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_ext_set(api_handle,
                                                                           SX_ACCESS_CMD_SET,
                                                                           &trap_key,
                                                                           &trap_attr))) {
            SX_LOG_ERR("sx_api_host_ifc_trap_id_ext_set BER MONITOR TRAP failed\n");
            goto out;
        }


        if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(api_handle, SX_ACCESS_CMD_REGISTER,
                                                                                g_swid_id, SX_TRAP_ID_BER_MONITOR,
                                                                                &port_channel))) {
            SX_LOG_ERR("host ifc trap register BER MONITOR TRAP failed - %s.\n", SX_STATUS_MSG(status));
            goto out;
        }
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(api_handle, SX_ACCESS_CMD_REGISTER,
                                                                            g_swid_id, SX_TRAP_ID_PMPE,
                                                                            &port_channel))) {
        SX_LOG_ERR("host ifc trap register PMPE failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    /*Register to PUDE event */
    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(api_handle, SX_ACCESS_CMD_REGISTER,
                                                                            g_swid_id, SX_TRAP_ID_PUDE,
                                                                            &port_channel))) {
        SX_LOG_ERR("host ifc trap register PUDE failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    memcpy(&callback_channel, &g_sai_db_ptr->callback_channel, sizeof(callback_channel));
    cl_plock_release(&g_sai_db_ptr->p_lock);

    while (!event_thread_asked_to_stop) {
        FD_ZERO(&descr_set);
        FD_SET(port_channel.channel.fd.fd, &descr_set);
        FD_SET(callback_channel.channel.fd.fd, &descr_set);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        ret_val = select(FD_SETSIZE, &descr_set, NULL, NULL, &timeout);

        if (-1 == ret_val) {
            SX_LOG_ERR("select ended with error/interrupt %s\n", strerror(errno));
            status = SX_STATUS_ERROR;
            goto out;
        }

        if (ret_val > 0) {
            if (FD_ISSET(port_channel.channel.fd.fd, &descr_set)) {
                packet_size = MAX_PACKET_SIZE;
                if (SX_STATUS_SUCCESS !=
                    (status = sx_lib_host_ifc_recv(&port_channel.channel.fd, p_packet, &packet_size, receive_info))) {
                    SX_LOG_ERR("sx_api_host_ifc_recv on port fd failed with error %s out size %u\n",
                               SX_STATUS_MSG(status), packet_size);
                    goto out;
                }

                if ((SX_INVALID_PORT == receive_info->source_log_port) && (receive_info->trap_id != SX_TRAP_ID_PMPE)) {
                    SX_LOG_WRN("sx_api_host_ifc_recv on port fd returned unknown port, waiting for next packet\n");
                    continue;
                }

                if (receive_info->trap_id == SX_TRAP_ID_PUDE) {
                    if (SAI_STATUS_SUCCESS !=
                        (status =
                             mlnx_create_object(SAI_OBJECT_TYPE_PORT, receive_info->event_info.pude.log_port, NULL,
                                                &port_data.port_id))) {
                        goto out;
                    }

                    if (SX_PORT_OPER_STATUS_UP == receive_info->event_info.pude.oper_state) {
                        port_data.port_state = SAI_PORT_OPER_STATUS_UP;
                    } else {
                        port_data.port_state = SAI_PORT_OPER_STATUS_DOWN;
                    }
                    SX_LOG_NTC("Port %x changed state to %s\n", receive_info->event_info.pude.log_port,
                               (SX_PORT_OPER_STATUS_UP == receive_info->event_info.pude.oper_state) ? "up" : "down");

                    if (g_notification_callbacks.on_port_state_change) {
                        g_notification_callbacks.on_port_state_change(1, &port_data);
                    }
                } else if (receive_info->trap_id == SX_TRAP_ID_BER_MONITOR) {
                    SX_LOG_NTC("Log port %x alarm state changed to Alarm\n", receive_info->source_log_port);
                    sai_db_read_lock();
                    if (SAI_STATUS_SUCCESS !=
                        (status = mlnx_port_by_log_id(receive_info->event_info.ber_monitor.log_port, &port))) {
                        MLNX_SAI_LOG_ERR("Failed get port by log id from BER monitor trap %x\n",
                                         receive_info->source_log_port);
                        sai_db_unlock();
                        goto out;
                    }
                    sai_db_unlock();
                    g_notification_callbacks.on_signal_degrade(1, &port->saiport);
                } else if (receive_info->trap_id == SX_TRAP_ID_PMPE) {
                    module_data.module_state = (sai_port_module_status_t)receive_info->event_info.pmpe.module_state;
                    SX_LOG_NTC("Module %u status changed to %d \n", receive_info->event_info.pmpe.module_id,
                               receive_info->event_info.pmpe.module_state);
                    if (g_notification_callbacks.on_module_event != NULL) {
                        sai_db_read_lock();
                        for (ii = 0; ii < receive_info->event_info.pmpe.list_size; ii++) {
                            if (SAI_STATUS_SUCCESS !=
                                (status =
                                     mlnx_port_by_log_id(receive_info->event_info.pmpe.log_port_list[ii], &port))) {
                                MLNX_SAI_LOG_ERR("Failed get port by log id from PMPE trap %x\n",
                                                 receive_info->event_info.pmpe.log_port_list[ii]);
                                sai_db_unlock();
                                goto out;
                            }
                            if (port->module != receive_info->event_info.pmpe.module_id) {
                                MLNX_SAI_LOG_ERR("Invalid data received from PMPE trap. module expected: %x\n",
                                                 port->module);
                                continue;
                            }
                            module_data.port_id = port->saiport;
                            g_notification_callbacks.on_module_event(1, &module_data);
                        }
                        sai_db_unlock();
                    }
                }
            }
        }
    }

out:
    SX_LOG_NTC("Closing event thread - %s.\n", SX_STATUS_MSG(status));

    if (SX_STATUS_SUCCESS != status) {
        if (g_notification_callbacks.on_switch_shutdown_request) {
            g_notification_callbacks.on_switch_shutdown_request(switch_id);
        }
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_close(api_handle, &port_channel.channel.fd))) {
        SX_LOG_ERR("host ifc close port fd failed - %s.\n", SX_STATUS_MSG(status));
    }

    cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    memset(&g_sai_db_ptr->callback_channel, 0, sizeof(g_sai_db_ptr->callback_channel));
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    cl_plock_release(&g_sai_db_ptr->p_lock);

    if (NULL != p_packet) {
        free(p_packet);
    }

    free(receive_info);

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&api_handle))) {
        SX_LOG_ERR("API close failed.\n");
    }
}

sai_status_t mlnx_cb_table_init(void)
{
    sai_status_t status;

    status = mlnx_port_cb_table_init();
    if (SAI_ERR(status)) {
        return status;
    }

    return status;
}

static sai_status_t mlnx_change_dpt_to_emad()
{
    sai_status_t      status = SAI_STATUS_SUCCESS;
    sxd_status_t      sxd_status = SXD_STATUS_SUCCESS;
    dpt_path_params_t path_params;

    memset(&path_params, 0, sizeof(path_params));

    sxd_status = sxd_dpt_path_add(g_device_id, 0, OOB_PATH, path_params);
    if (SXD_CHECK_FAIL(sxd_status)) {
        MLNX_SAI_LOG_ERR("Failed: sxd_dpt_path_add for device: [%u]. Return value: [%d, %s]",
                         g_device_id, sxd_status, SXD_STATUS_MSG(sxd_status));
        MLNX_SAI_LOG_ERR("Failed changing dpt path to EMAD: %s", SXD_STATUS_MSG(sxd_status));
        status = SAI_STATUS_FAILURE;
    }
    return status;
}

static sai_status_t mlnx_add_device_to_dpt()
{
    sai_status_t        status = SAI_STATUS_SUCCESS;
    sxd_status_t        sxd_status = SXD_STATUS_SUCCESS;
    local_to_ib_map_t   map[MAX_PORTS];
    uint32_t            port_number;
    mlnx_port_config_t *port;

    memset(map, 0, sizeof(local_to_ib_map_t) * MAX_PORTS);

    for (port_number = 0; port_number < MAX_PORTS; ++port_number) {
        port = mlnx_port_by_idx(port_number);
        if (port == NULL) {
            MLNX_SAI_LOG_ERR("Can't Get port.\n");
            status = SAI_STATUS_FAILURE;
            return status;
        }
        map[port_number].local_port = port->port_map.local_port;
        map[port_number].ib_port = port->ib_port;
        map[port_number].port_module = port->module;
    }

    sxd_status = sxd_dpt_add_ports_map(g_device_id, map, MAX_PORTS);
    if (SXD_CHECK_FAIL(sxd_status)) {
        MLNX_SAI_LOG_ERR("Failed: sxd_dpt_add_ports_map for device: [%u]. Return value: [%d, %s]",
                         g_device_id, sxd_status, SXD_STATUS_MSG(sxd_status));
        MLNX_SAI_LOG_ERR("Failed adding ports map for device: %s", SXD_STATUS_MSG(sxd_status));
        status = SAI_STATUS_FAILURE;
    }
    return status;
}


static sai_status_t mlnx_initialize_switch(sai_object_id_t switch_id)
{
    int                  system_err;
    const char          *config_file, *boot_type_char, *dump_path, *max_dumps;
    mlnx_sai_boot_type_t boot_type = 0;
    sai_status_t         sai_status;
    sx_api_profile_t    *ku_profile;
    const bool           warm_recover = false;
    cl_status_t          cl_err;
    int                  val;
    uint8_t              swid;

    config_file = g_mlnx_services.profile_get_value(g_profile_id, SAI_KEY_INIT_CONFIG_FILE);

    if (NULL == config_file) {
        MLNX_SAI_LOG_ERR("NULL config file for profile %u\n", g_profile_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    system_err = system("pidof sx_sdk");
    if (0 == system_err) {
        MLNX_SAI_LOG_ERR("SDK already running. Please terminate it before running SAI init.\n");
        return SAI_STATUS_FAILURE;
    }

    boot_type_char = g_mlnx_services.profile_get_value(g_profile_id, SAI_KEY_BOOT_TYPE);
    if (NULL != boot_type_char) {
        boot_type = (uint8_t)atoi(boot_type_char);
    } else {
        boot_type = 0;
    }

    switch (boot_type) {
    case BOOT_TYPE_REGULAR:
#if (!defined ACS_OS) || (defined ACS_OS_NO_DOCKERS)
        system_err = system("/etc/init.d/openibd start");
        if (0 != system_err) {
            MLNX_SAI_LOG_ERR("Failed running openibd start.\n");
            return SAI_STATUS_FAILURE;
        }
        system_err = system("/etc/init.d/sxdkernel start");
        if (0 != system_err) {
            MLNX_SAI_LOG_ERR("Failed running sxdkernel start.\n");
            return SAI_STATUS_FAILURE;
        }
#endif
        break;

    case BOOT_TYPE_WARM:
    case BOOT_TYPE_FAST:
#if (!defined ACS_OS) || (defined ACS_OS_NO_DOCKERS)
        system_err = system("/etc/init.d/openibd start");
        if (0 != system_err) {
            MLNX_SAI_LOG_ERR("Failed running openibd start.\n");
            return SAI_STATUS_FAILURE;
        }
        system_err = system("env FAST_BOOT=1 /etc/init.d/sxdkernel start");
        if (0 != system_err) {
            MLNX_SAI_LOG_ERR("Failed running sxdkernel start.\n");
            return SAI_STATUS_FAILURE;
        }
#endif
        break;

    /* default */
    default:
        MLNX_SAI_LOG_ERR("Boot type %d not recognized, must be 0 (cold) or 1 (warm) or 2 (fast)\n", boot_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = mlnx_sai_rm_initialize(config_file);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    sai_status = mlnx_sdk_start(boot_type);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_resource_mng_stage(warm_recover, boot_type))) {
        return sai_status;
    }


    sai_db_write_lock();
    g_sai_db_ptr->boot_type = boot_type;
    sai_db_unlock();

    ku_profile = mlnx_sai_get_ku_profile();
    if (!ku_profile) {
        return SAI_STATUS_FAILURE;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_ku_profile_prepare(ku_profile))) {
        return sai_status;
    }

    dump_path = g_mlnx_services.profile_get_value(g_profile_id, SAI_KEY_DUMP_STORE_PATH);
    if (NULL != dump_path) {
        strncpy(g_sai_db_ptr->dump_configuration.path, dump_path, sizeof(g_sai_db_ptr->dump_configuration.path));
        g_sai_db_ptr->dump_configuration.path[SX_API_DUMP_PATH_LEN_LIMIT - 1] = 0;
    }

    max_dumps = g_mlnx_services.profile_get_value(g_profile_id, SAI_KEY_DUMP_STORE_AMOUNT);
    if (NULL != max_dumps) {
        val = strtol(max_dumps, NULL, 0);
        if (!((val <= 0) || (ERANGE == errno))) {
            g_sai_db_ptr->dump_configuration.max_events_to_store = val;
        } else {
            SX_LOG_WRN("\"%s\" is not valid value to enable DFW - feature is off.\n", max_dumps);
        }
    }
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_chassis_mng_stage(boot_type,
                                                                   ku_profile))) {
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS != (sai_status = parse_ib_port_info())) {
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_dvs_mng_stage(boot_type, switch_id))) {
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_rename_ipoib_devices())) {
        return sai_status;
    }

    /* update dpt regarding mapping between localport to ibport for each devid */
    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_add_device_to_dpt())) {
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_change_dpt_to_emad())) {
        return sai_status;
    }

    for (swid = 0; swid < g_sai_db_ptr->num_of_swids; swid++) {
        if (SAI_STATUS_SUCCESS != (sai_status = sa_init(&g_sai_db_ptr->swidapi_handles[swid], swid, 0))) {
            SX_LOG_ERR("Failed to open MAD RPC port for swid %u\n", swid);
            SX_LOG_ERR("Getting stats wont be supported \n");
        }
    }

    cl_err = cl_thread_init(&event_thread, event_thread_func, (const void*const)switch_id, NULL);
    if (cl_err) {
        SX_LOG_ERR("Failed to create event thread\n");
        return SAI_STATUS_FAILURE;
    }


#ifndef _WIN32
    if (0 != sem_init(&g_sai_db_ptr->dfw_sem, 1, 0)) {
        SX_LOG_ERR("Error creating DFW thread semaphore\n");
        return SAI_STATUS_FAILURE;
    }
#endif /* ifndef _WIN32 */
    cl_err = cl_thread_init(&dfw_thread, mlnx_switch_dfw_thread_func, NULL, NULL);
    if (cl_err) {
        SX_LOG_ERR("Failed to create DFW thread\n");
        return SAI_STATUS_FAILURE;
    }


    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_connect_switch(sai_object_id_t switch_id)
{
    int                            err, shmid;
    sxd_chip_types_t               chip_type;
    sx_chip_types_t                sx_chip_type;
    sx_status_t                    status;
    sxd_status_t                   sxd_status;
    sx_log_verbosity_target_attr_t log_verbosity_target_attr = { 0 };

    /* Open an handle if not done already on init for init agent */
    if (0 == gh_sdk) {
        if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &gh_sdk))) {
            MLNX_SAI_LOG_ERR("Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        if (SX_STATUS_SUCCESS != (status = sx_api_system_log_verbosity_level_set(gh_sdk,
                                                                                 SX_LOG_VERBOSITY_TARGET_API,
                                                                                 LOG_VAR_NAME(__MODULE__),
                                                                                 LOG_VAR_NAME(__MODULE__)))) {
            SX_LOG_ERR("Set system log verbosity failed - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        log_verbosity_target_attr.verbosity_target = SX_LOG_VERBOSITY_TARGET_API;
        log_verbosity_target_attr.enable = 1;
        if (SX_STATUS_SUCCESS !=
            (status = sx_api_system_log_enter_func_severity_set(gh_sdk, &log_verbosity_target_attr))) {
            SX_LOG_ERR("Set system log func severity failed - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }
        sx_log_funcs_severity_set(true);

        status = get_chip_type(&chip_type);
        if (SX_ERR(status)) {
            SX_LOG_ERR("get_chip_type failed\n");
            return SAI_STATUS_FAILURE;
        }

        sx_chip_type = convert_chip_sxd_to_sx(chip_type);

        status = rm_chip_limits_get(sx_chip_type, &g_resource_limits);
        if (SX_ERR(status)) {
            SX_LOG_ERR("Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
            return sdk_to_sai(status);
        }

        g_mlnx_shm_rm_size = (uint32_t)mlnx_sai_rm_db_size_get();

        err = cl_shm_open(SAI_PATH, &shmid);
        if (err) {
            SX_LOG_ERR("Failed to open shared memory of SAI DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }

        g_sai_db_ptr = mmap(NULL,
                            sizeof(*g_sai_db_ptr) + g_mlnx_shm_rm_size,
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            shmid,
                            0);
        if (g_sai_db_ptr == MAP_FAILED) {
            SX_LOG_ERR("Failed to map the shared memory of the SAI DB\n");
            g_sai_db_ptr = NULL;
            return SAI_STATUS_NO_MEMORY;
        }

        status = mlnx_cb_table_init();
        if (SAI_ERR(status)) {
            return status;
        }

        sxd_status = sxd_access_reg_init(0, sai_log_cb, LOG_VAR_NAME(__MODULE__));
        if (SXD_CHECK_FAIL(sxd_status)) {
            SX_LOG_ERR("Failed to init access reg - %s.\n", SXD_STATUS_MSG(sxd_status));
            return SAI_STATUS_FAILURE;
        }
    }

    SX_LOG_NTC("Connect switch\n");

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Create switch
 *
 *   SDK initialization/connect to SDK. After the call the capability attributes should be
 *   ready for retrieval via sai_get_switch_attribute(). Same Switch Object id should be
 *   given for create/connect for each NPU.
 *
 * @param[out] switch_id The Switch Object ID
 * @param[in] attr_count number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_create_switch(_Out_ sai_object_id_t     * switch_id,
                                       _In_ uint32_t               attr_count,
                                       _In_ const sai_attribute_t *attr_list)
{
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         key_str[MAX_KEY_STR_LEN];
    const sai_attribute_value_t *attr_val = NULL;
    mlnx_object_id_t             mlnx_switch_id = {0};
    sai_status_t                 sai_status;
    uint32_t                     attr_idx;

    if (NULL == switch_id) {
        MLNX_SAI_LOG_ERR("NULL switch_id id param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = check_attribs_metadata(attr_count, attr_list, SAI_OBJECT_TYPE_SWITCH, switch_vendor_attribs,
                                        SAI_COMMON_API_CREATE);
    if (SAI_ERR(sai_status)) {
        MLNX_SAI_LOG_ERR("Failed attribs check\n");
        return sai_status;
    }

    sai_attr_list_to_str(attr_count, attr_list, SAI_OBJECT_TYPE_SWITCH, MAX_LIST_VALUE_STR_LEN, list_str);
    MLNX_SAI_LOG_NTC("Create switch, %s\n", list_str);

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_INIT_SWITCH, &attr_val, &attr_idx);
    assert(!SAI_ERR(sai_status));
    mlnx_switch_id.id.is_created = attr_val->booldata;

    sai_status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_SWITCH, &mlnx_switch_id, switch_id);
    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    sai_status =
        find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_SWITCH_PROFILE_ID, &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_profile_id = attr_val->u32;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_switch_state_change = (sai_switch_state_change_notification_fn)attr_val->ptr;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_switch_shutdown_request =
            (sai_switch_shutdown_request_notification_fn)attr_val->ptr;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_port_state_change = (sai_port_state_change_notification_fn)attr_val->ptr;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_packet_event = (sai_packet_event_notification_fn)attr_val->ptr;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_signal_degrade = (sai_port_signal_degrade_notification_fn)attr_val->ptr;
    }

    sai_status = find_attrib_in_list(attr_count,
                                     attr_list,
                                     SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY,
                                     &attr_val,
                                     &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_notification_callbacks.on_module_event = (sai_port_module_plug_event_notification_fn)attr_val->ptr;
    }
    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_NUM_OF_SWIDS,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_num_of_swids = attr_val->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_ADAPTIVE_ROUTING,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_adaptive_routing_en = attr_val->booldata;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_AR_GROUPS,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_adaptive_routing_group_cap = attr_val->u32;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_IB_ROUTING,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_ib_routing_en = attr_val->booldata;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_BREAKOUT_MODE,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_breakout_mode_en = attr_val->booldata;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_OPERATION_MODE_IB, &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_ib_operation_mode = attr_val->booldata;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_uninit_data_plane_on_removal = attr_val->booldata;
    }

    if (mlnx_switch_id.id.is_created) {
        sai_status = mlnx_initialize_switch(*switch_id);
    } else {
        sai_status = mlnx_connect_switch(*switch_id);
    }

    if (SAI_ERR(sai_status)) {
        return sai_status;
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_TYPE, &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        if (attr_val->s32 != SAI_SWITCH_TYPE_IBV0) {
            SX_LOG_ERR("Supported switch type is: SAI_SWITCH_TYPE_IBV0");
            return SAI_STATUS_INVALID_PARAMETER;
        } else {
            g_switch_type = attr_val->s32;
        }
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_NODE_DESCRIPTION,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        memset(g_sai_db_ptr->ib_node_description, 0, SX_IB_NODE_DESCRIPTION_LEN);
        memcpy(g_sai_db_ptr->ib_node_description,
               attr_val->s8list.list,
               attr_val->s8list.count);
        sai_status = mlnx_set_node_description_on_all_swids();
        if (SAI_ERR(sai_status)) {
            return sai_status;
        }
    }

    sai_status = find_attrib_in_list(attr_count, attr_list, SAI_SWITCH_ATTR_CUSTOM_INFINIBAND_SYSTEM_IMAGE_GUID,
                                     &attr_val, &attr_idx);
    if (!SAI_ERR(sai_status)) {
        g_sai_db_ptr->ib_system_image_guid = attr_val->u64;
        sai_status = mlnx_set_system_image_guid_on_all_swids();
        if (SAI_ERR(sai_status)) {
            return sai_status;
        }
    }
    sai_status = mlnx_object_id_to_sai(SAI_OBJECT_TYPE_SWITCH, &mlnx_switch_id, switch_id);
    switch_key_to_str(*switch_id, key_str);
    SX_LOG_NTC("Created switch %s\n", key_str);
    return sai_status;
}

static sai_status_t mlnx_shutdown_switch(void)
{
    sx_status_t  status;
    sxd_status_t sxd_status;
    int          system_err;
    uint8_t      swid;

    SX_LOG_ENTER();

    SX_LOG_NTC("Shutdown switch\n");

    event_thread_asked_to_stop = true;
    dfw_thread_asked_to_stop = true;

#ifndef _WIN32
    pthread_join(dfw_thread.osd.id, NULL);
    pthread_join(event_thread.osd.id, NULL);

    if (0 != sem_destroy(&g_sai_db_ptr->dfw_sem)) {
        SX_LOG_ERR("Error destroying DFW thread semaphore\n");
    }
#endif

    /* reset value for next run if process isn't closed */
    event_thread_asked_to_stop = false;
    dfw_thread_asked_to_stop = false;
    for (swid = 0; swid < g_sai_db_ptr->num_of_swids; swid++) {
        sa_destroy(&g_sai_db_ptr->swidapi_handles[swid]);
    }

    sai_db_unload(true);

    if (SXD_STATUS_SUCCESS != (sxd_status = sxd_close_device(g_sxd_handle))) {
        SX_LOG_ERR("sxd_close_device error: %s\n", strerror(errno));
    }

    if (SXD_STATUS_SUCCESS != (sxd_status = sxd_access_reg_deinit())) {
        SX_LOG_ERR("Access reg deinit failed.\n");
    }

    if (SXD_STATUS_SUCCESS != (sxd_status = sxd_dpt_deinit())) {
        SX_LOG_ERR("DPT deinit failed.\n");
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));
#ifdef SDK_VALGRIND
    system_err = system("killall -w memcheck-amd64-");
#else
    system_err = system("killall -w sx_sdk");
#endif

    if (0 != system_err) {
#ifdef SDK_VALGRIND
        MLNX_SAI_LOG_ERR("killall -w memcheck-amd64- failed.\n");
#else
        MLNX_SAI_LOG_ERR("killall -w sx_sdk failed.\n");
#endif
    }

#if (!defined ACS_OS) || (defined ACS_OS_NO_DOCKERS)
    system_err = system("/etc/init.d/sxdkernel stop");
    if (0 != system_err) {
        MLNX_SAI_LOG_ERR("Failed running sxdkernel stop.\n");
    }
    system_err = system("/etc/init.d/openibd stop");
    if (0 != system_err) {
        MLNX_SAI_LOG_ERR("Failed running openibd stop.\n");
    }
#endif

    SX_LOG_EXIT();

    return sdk_to_sai(status);
}

static sai_status_t mlnx_disconnect_switch(void)
{
    sx_status_t status;

    SX_LOG_NTC("Disconnect switch\n");

    if (SXD_STATUS_SUCCESS != sxd_access_reg_deinit()) {
        SX_LOG_ERR("Access reg deinit failed.\n");
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_close(&gh_sdk))) {
        SX_LOG_ERR("API close failed.\n");
    }

    memset(&g_notification_callbacks, 0, sizeof(g_notification_callbacks));


    return sdk_to_sai(status);
}

static sai_status_t mlnx_switch_node_description_get(_In_ const sai_object_key_t   *key,
                                                     _Inout_ sai_attribute_value_t *value,
                                                     _In_ uint32_t                  attr_index,
                                                     _Inout_ vendor_cache_t        *cache,
                                                     void                          *arg)
{
    SX_LOG_ENTER();
    memcpy(g_sai_db_ptr->ib_node_description, value->u8list.list, SX_IB_NODE_DESCRIPTION_LEN);
    value->u8list.count = SX_IB_NODE_DESCRIPTION_LEN;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_node_description_set(_In_ const sai_object_key_t      *key,
                                                     _In_ const sai_attribute_value_t *value,
                                                     void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();
    /* update the DB */
    memcpy(g_sai_db_ptr->ib_node_description, (char*)value->u8list.list, value->u8list.count);
    /* update the FW */
    status = mlnx_set_node_description_on_all_swids();

    SX_LOG_EXIT();

    return status;
}

static sai_status_t mlnx_set_node_description_on_all_swids(void)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    SX_LOG_ENTER();
    SX_LOG_DBG("MLX_SAI - Set IB NodeDescription to %s\n", g_sai_db_ptr->ib_node_description);
    /* set the node description for each swid */
    for (ii = 0; ii < g_sai_db_ptr->num_of_swids; ++ii) {
        /* set IB Node Description in FW */
        status = mlnx_set_ib_node_description((uint8_t)ii,
                                              g_sai_db_ptr->ib_node_description);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("MLX_SAI - Failed to set IB NodeDescription in FW to %s\n",
                       g_sai_db_ptr->ib_node_description);
            goto out;
        }
    }
out:
    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_set_system_image_guid_on_all_swids(void)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    SX_LOG_ENTER();
    SX_LOG_DBG("MLX_SAI - Set IB System Image GUID to %lu\n", g_sai_db_ptr->ib_system_image_guid);
    /* set the node description for each swid */
    for (ii = 0; ii < g_sai_db_ptr->num_of_swids; ++ii) {
        /* set IB Node Description in FW */
        status = mlnx_set_system_image_guid((uint8_t)ii,
                                            g_sai_db_ptr->ib_system_image_guid);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("MLX_SAI - Failed to set IB System Image GUID in FW to %lu\n",
                       g_sai_db_ptr->ib_system_image_guid);
            goto out;
        }
    }
out:
    SX_LOG_EXIT();
    return status;
}

/**
 * @brief Set switch attribute value
 *
 * @param[in] switch_id Switch id
 * @param[in] attr Switch attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_set_switch_attribute(_In_ sai_object_id_t switch_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .key.object_id = switch_id };
    char                   key_str[MAX_KEY_STR_LEN];
    sai_status_t           sai_status;

    SX_LOG_ENTER();
    switch_key_to_str(switch_id, key_str);
    sai_status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_SWITCH, switch_vendor_attribs, attr);
    SX_LOG_EXIT();
    return sai_status;
}


/**
 * @brief Get switch attribute value
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of switch attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_get_switch_attribute(_In_ sai_object_id_t     switch_id,
                                              _In_ sai_uint32_t        attr_count,
                                              _Inout_ sai_attribute_t *attr_list)
{
    sai_status_t           status;
    const sai_object_key_t key = { .key.object_id = switch_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();
    switch_key_to_str(switch_id, key_str);
    status =
        sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_SWITCH, switch_vendor_attribs, attr_count, attr_list);
    SX_LOG_EXIT();
    return status;
}

sai_status_t mlnx_switch_get_mac(sx_mac_addr_t *mac)
{
    memcpy(mac, &g_sai_db_ptr->base_mac_addr, sizeof(*mac));
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_attr_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    assert((long)arg == SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL);

    SX_LOG_ENTER();

    value->booldata = g_uninit_data_plane_on_removal;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_attr_set(_In_ const sai_object_key_t      *key,
                                         _In_ const sai_attribute_value_t *value,
                                         void                             *arg)
{
    assert((long)arg == SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL);

    SX_LOG_ENTER();

    g_uninit_data_plane_on_removal = value->booldata;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_switch_log_set(sx_verbosity_level_t level)
{
    sx_status_t status;

    LOG_VAR_NAME(__MODULE__) = level;

    if (gh_sdk) {
        status = sdk_to_sai(sx_api_topo_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        status = SAI_STATUS_SUCCESS;
    }
    return status;
}

static sai_status_t mlnx_switch_type_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = g_sai_db_ptr->switch_type;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_infiniband_num_of_swids_get(_In_ const sai_object_key_t   *key,
                                                            _Inout_ sai_attribute_value_t *value,
                                                            _In_ uint32_t                  attr_index,
                                                            _Inout_ vendor_cache_t        *cache,
                                                            void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = g_sai_db_ptr->num_of_swids;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_infiniband_adaptive_routing_get(_In_ const sai_object_key_t   *key,
                                                                _Inout_ sai_attribute_value_t *value,
                                                                _In_ uint32_t                  attr_index,
                                                                _Inout_ vendor_cache_t        *cache,
                                                                void                          *arg)
{
    SX_LOG_ENTER();

    value->booldata = g_sai_db_ptr->adaptive_routing_en;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_infiniband_ar_groups_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    SX_LOG_ENTER();

    value->s32 = g_sai_db_ptr->adaptive_routing_group_cap;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_infiniband_ib_routing_get(_In_ const sai_object_key_t   *key,
                                                          _Inout_ sai_attribute_value_t *value,
                                                          _In_ uint32_t                  attr_index,
                                                          _Inout_ vendor_cache_t        *cache,
                                                          void                          *arg)
{
    SX_LOG_ENTER();

    value->booldata = g_sai_db_ptr->ib_routing_en;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_infiniband_breakout_mode_get(_In_ const sai_object_key_t   *key,
                                                             _Inout_ sai_attribute_value_t *value,
                                                             _In_ uint32_t                  attr_index,
                                                             _Inout_ vendor_cache_t        *cache,
                                                             void                          *arg)
{
    SX_LOG_ENTER();

    value->booldata = g_sai_db_ptr->breakout_mode_en;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_image_guid_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t     ii;

    SX_LOG_ENTER();
    SX_LOG_DBG("MLX_SAI - Set IB system image GUID to %u\n", value->u64);

    for (ii = 0; ii < g_sai_db_ptr->num_of_swids; ++ii) {
        status = mlnx_set_system_image_guid((uint8_t)ii, value->u64);
        if (status != SAI_STATUS_SUCCESS) {
            SX_LOG_ERR("MLX_SAI - Failed to set system image guid in FW to %lu\n",
                       g_sai_db_ptr->ib_system_image_guid);
            goto out;
        }
    }
out:
    SX_LOG_EXIT();
    return status;
}


static sai_status_t mlnx_set_system_image_guid(uint8_t swid, uint64_t guid_value)
{
    sai_status_t       status;
    uint32_t           mask = 0xFFFFFFFF;
    struct ku_spzr_reg spzr_reg;

    if (0 == guid_value) {
        MLNX_SAI_LOG_ERR("Got 0 as system image guid\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    SX_LOG_DBG("MLX_SAI - Set IB system image GUID to %lu\n", guid_value);
    memset(&spzr_reg, 0, sizeof(spzr_reg));
    spzr_reg.swid = swid;
    spzr_reg.sig = 1;
    spzr_reg.system_image_guid_l = guid_value & mask;
    spzr_reg.system_image_guid_h = guid_value >> 32;
    if (SAI_STATUS_SUCCESS != (status = mlnx_set_get_spzr_register(SXD_ACCESS_CMD_SET,
                                                                   swid,
                                                                   g_device_id,
                                                                   NULL,
                                                                   NULL,
                                                                   &spzr_reg))) {
        MLNX_SAI_LOG_ERR("Failed set SPZR for system image guid: [%lu], device: [%u], swid [%u]\n",
                         guid_value, g_device_id, swid);
    }

out:
    return status;
}


static sai_status_t mlnx_switch_image_guid_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    SX_LOG_ENTER();
    value->u64 = g_sai_db_ptr->ib_system_image_guid;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_event_func_get(_In_ const sai_object_key_t   *key,
                                               _Inout_ sai_attribute_value_t *value,
                                               _In_ uint32_t                  attr_index,
                                               _Inout_ vendor_cache_t        *cache,
                                               void                          *arg)
{
    long attr_id = (long)arg;

    SX_LOG_ENTER();

    switch (attr_id) {
    case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
        value->ptr = g_notification_callbacks.on_switch_state_change;
        break;

    case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
        value->ptr = g_notification_callbacks.on_switch_shutdown_request;
        break;

    case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
        value->ptr = g_notification_callbacks.on_port_state_change;
        break;

    case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
        value->ptr = g_notification_callbacks.on_packet_event;
        break;

    case SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY:
        value->ptr = g_notification_callbacks.on_signal_degrade;
        break;

    case SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY:
        value->ptr = g_notification_callbacks.on_module_event;
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_event_func_set(_In_ const sai_object_key_t      *key,
                                               _In_ const sai_attribute_value_t *value,
                                               void                             *arg)
{
    long attr_id = (long)arg;

    SX_LOG_ENTER();

    switch (attr_id) {
    case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
        g_notification_callbacks.on_switch_state_change = (sai_switch_state_change_notification_fn)value->ptr;
        break;

    case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
        g_notification_callbacks.on_switch_shutdown_request =
            (sai_switch_shutdown_request_notification_fn)value->ptr;
        break;

    case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
        g_notification_callbacks.on_port_state_change = (sai_port_state_change_notification_fn)value->ptr;
        break;

    case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
        g_notification_callbacks.on_packet_event = (sai_packet_event_notification_fn)value->ptr;
        break;

    case SAI_SWITCH_ATTR_PORT_SIGNAL_DEGRADE_NOTIFY:
        g_notification_callbacks.on_signal_degrade = (sai_port_signal_degrade_notification_fn)value->ptr;
        break;

    case SAI_SWITCH_ATTR_PORT_MODULE_PLUG_EVENT_NOTIFY:
        g_notification_callbacks.on_module_event = (sai_port_module_plug_event_notification_fn)value->ptr;
        break;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_operation_mode_get(_In_ const sai_object_key_t   *key,
                                                   _Inout_ sai_attribute_value_t *value,
                                                   _In_ uint32_t                  attr_index,
                                                   _Inout_ vendor_cache_t        *cache,
                                                   void                          *arg)
{
    /* TODO: implement when SDK is ready - MOCK*/
    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove/disconnect Switch
 *   Release all resources associated with currently opened switch
 *
 * @param[in] switch_id The Switch id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t mlnx_remove_switch(_In_ sai_object_id_t switch_id)
{
    mlnx_object_id_t mlnx_switch_id = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_SWITCH, switch_id, &mlnx_switch_id);
    if (SAI_ERR(status)) {
        return status;
        SX_LOG_EXIT();
    }

    if (g_uninit_data_plane_on_removal) {
        status = mlnx_shutdown_switch();
    } else {
        status = mlnx_disconnect_switch();
    }

    SX_LOG_EXIT();
    return status;
}


const sai_switch_api_t mlnx_switch_api = {
    mlnx_create_switch,
    mlnx_remove_switch,
    mlnx_set_switch_attribute,
    mlnx_get_switch_attribute,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
