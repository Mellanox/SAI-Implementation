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

/*
 *  NOTES:
 *   SAI policer is capable of binding to ACL, trap group, port.
 *   For each type of these objects SDK defines different policer types.
 *   SAI policer internally uses different SDK policers for bidning to menitoned object types.
 *
 *   The mlnx_policer_db_entry_t structure contains ACL and trap group related SDK resource handles.
 *   mlnx_port_policer_info_t structure contains information about SDK storm control policers used internally by a SAI policer.
 *
 *   ----------------
 *   ACL & trap group
 *   ----------------
 *   For ACL and trap group we create policer using sx_api_policer_set API.
 *       for ACL we set sx_policer_attributes_t::is_host_ifc_policer = false
 *       for trap group we set sx_policer_attributes_t::is_host_ifc_policer = true
 *
 *   ----------------
 *   Port policer
 *   ----------------
 *   For port sx_api_port_storm_control_set API is used. SAI policer uses up to 4 storm policers: for 'all traffic', flood, broadcast and multicast policers defined by following attributes:
 *       SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID,
 *       SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID,
 *       SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID,
 *       SAI_PORT_ATTR_POLICER_ID
 */
#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "assert.h"
#include <limits.h>
#include <math.h>


#undef  __MODULE__
#define __MODULE__ SAI_POLICER

#define policer_db_cl_plock_excl_acquire(lock) \
    {SX_LOG_DBG("policer_db_cl_plock_excl_acquire\n"); \
     cl_plock_excl_acquire(lock); }
#define policer_db_cl_plock_release(lock) {SX_LOG_DBG("policer_db_cl_plock_release\n"); cl_plock_release(lock); }
#define IR_UNITS 1000

sai_status_t mlnx_sai_unbind_policer_from_trap_group(_In_ sai_object_id_t sai_object_id);


static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

typedef sx_status_t (*pfn_sx_api_port_storm_control_set)(const sx_api_handle_t handle, const sx_access_cmd_t cmd,
                                                         const sx_port_log_id_t log_port,
                                                         const sx_port_storm_control_id_t storm_control_id,
                                                         const sx_port_storm_control_params_t *storm_control_params_p);
typedef sx_status_t (*pfn_sx_api_port_storm_control_get)(const sx_api_handle_t handle, const sx_port_log_id_t log_port,
                                                         const sx_port_storm_control_id_t storm_control_id,
                                                         sx_port_storm_control_params_t  *storm_control_params_p);
typedef struct _mlnx_sai_policer_test_storm_data_t {
    pfn_sx_api_port_storm_control_set sx_api_port_storm_control_set_p;
    pfn_sx_api_port_storm_control_get sx_api_port_storm_control_get_p;
} mlnx_sai_policer_test_storm_data_t;


static mlnx_sai_policer_test_storm_data_t storm_policer_functions =
{sx_api_port_storm_control_set, sx_api_port_storm_control_get};


void mlnx_sai_policer_set_storm_endpoints(void* f1, void* f2)
{
    storm_policer_functions.sx_api_port_storm_control_set_p = (pfn_sx_api_port_storm_control_set)f1;
    storm_policer_functions.sx_api_port_storm_control_get_p = (pfn_sx_api_port_storm_control_get)f2;
}

void mlnx_sai_policer_get_storm_endpoints(pfn_sx_api_port_storm_control_set* f1, pfn_sx_api_port_storm_control_get* f2)
{
    *f1 = storm_policer_functions.sx_api_port_storm_control_set_p;
    *f2 = storm_policer_functions.sx_api_port_storm_control_get_p;
}

typedef enum _mlnx_sai_policer_color_indicator {
    MLNX_POLICER_COLOR_GREEN,
    MLNX_POLICER_COLOR_YELLOW,
    MLNX_POLICER_COLOR_RED
} mlnx_sai_policer_color_indicator_t;

static sai_status_t fill_policer_data(_In_ bool                   set_defaults,
                                      _In_ uint32_t               attr_count,
                                      _In_ const sai_attribute_t *attr_list,
                                      sx_policer_attributes_t    *sx_policer_attribs);
static sai_status_t sx_meter_type_to_sai(_In_ sx_policer_meter_t sx_val, _Out_ int32_t* sai_val);
static sai_status_t sx_mode_type_to_sai(_In_ sx_policer_rate_type_e sx_val, _Out_ int32_t* sai_val);
static sai_status_t sx_policer_action_to_sai(_In_ sx_policer_action_t sx_val, _Out_ int32_t* sai_val);
static sai_status_t sai_policer_get_sx_attribs(_In_ const sai_object_key_t *key,
                                               sx_policer_attributes_t     *sx_policer_attribs);
static sai_status_t sai_policer_meter_type_attr_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg);
static sai_status_t sai_policer_mode_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
static sai_status_t sai_policer_color_source_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg);
static sai_status_t sai_policer_cbs_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t sai_policer_cir_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t sai_policer_pbs_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t sai_policer_pir_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg);
static sai_status_t sai_policer_packet_action_get_internal(_In_ const sai_object_key_t            *key,
                                                           _In_ mlnx_sai_policer_color_indicator_t color,
                                                           _Out_ sai_attribute_value_t            *value);
static sai_status_t sai_policer_green_packet_action_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg);
static sai_status_t sai_policer_yellow_packet_action_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg);
static sai_status_t sai_policer_red_packet_action_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg);
static sai_status_t sai_policer_attr_set(_In_ const sai_object_key_t* key,
                                         _In_ sai_attribute_t         sai_attr,
                                         _In_ char                  * attr_name);
static sai_status_t sai_policer_color_source_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg);
static sai_status_t sai_policer_cbs_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t sai_policer_cir_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t sai_policer_pbs_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t sai_policer_pir_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg);
static sai_status_t sai_policer_green_packet_action_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg);
static sai_status_t sai_policer_yellow_packet_action_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg);
static sai_status_t sai_policer_red_packet_action_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg);

void db_reset_policer_entry(_In_ uint32_t db_policers_entry_index);
sai_status_t db_init_sai_policer_data(_In_ sx_policer_attributes_t* policer_attr,
                                      _Out_ uint32_t              * db_policers_entry_index_p);
static sai_status_t db_remove_sai_policer_data(_In_ uint32_t db_policers_entry_index);
static sai_status_t db_write_sai_policer_attribs(_In_ sai_object_id_t          sai_policer_id,
                                                 _In_ sx_policer_attributes_t* sx_policer_attribs);
static const sai_vendor_attribute_entry_t policer_vendor_attribs[] = {
    {
        SAI_POLICER_ATTR_METER_TYPE,
        { true, false, false, true },
        { true, false, true, true },
        sai_policer_meter_type_attr_get, NULL,
        NULL, NULL
    },
    {
        SAI_POLICER_ATTR_MODE,
        { true, false, false, true },
        { true, false, false, true },
        sai_policer_mode_get, NULL,
        NULL, NULL
    },
    {
        SAI_POLICER_ATTR_COLOR_SOURCE,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_color_source_get, NULL,
        sai_policer_color_source_set, NULL
    },
    {
        SAI_POLICER_ATTR_CBS,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_cbs_get, NULL,
        sai_policer_cbs_set, NULL
    },
    {
        SAI_POLICER_ATTR_CIR,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_cir_get, NULL,
        sai_policer_cir_set, NULL
    },
    {
        SAI_POLICER_ATTR_PBS,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_pbs_get, NULL,
        sai_policer_pbs_set, NULL
    },
    {
        SAI_POLICER_ATTR_PIR,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_pir_get, NULL,
        sai_policer_pir_set, NULL
    },
    {
        SAI_POLICER_ATTR_GREEN_PACKET_ACTION,
        { true, false, true, true},
        { true, false, true, true },
        sai_policer_green_packet_action_get, NULL,
        sai_policer_green_packet_action_set, NULL
    },
    {
        SAI_POLICER_ATTR_YELLOW_PACKET_ACTION,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_yellow_packet_action_get, NULL,
        sai_policer_yellow_packet_action_set, NULL
    },
    {
        SAI_POLICER_ATTR_RED_PACKET_ACTION,
        { true, false, true, true },
        { true, false, true, true },
        sai_policer_red_packet_action_get, NULL,
        sai_policer_red_packet_action_set, NULL
    },
    {
        SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST,
        { false, false, false, false },
        { false, false, false, false},
        NULL, NULL,
        NULL, NULL
    },
    {
        END_FUNCTIONALITY_ATTRIBS_ID,
        { false, false, false, false },
        { false, false, false, false },
        NULL, NULL,
        NULL, NULL
    }
};
static void log_sx_policer_attrib_color_action(_In_ sx_policer_action_t sx_policer_action, _In_ char* action_name)
{
    char* val = NULL;

    switch (sx_policer_action) {
    case SX_POLICER_ACTION_FORWARD:
        val = "SX_POLICER_ACTION_FORWARD";
        break;

    case SX_POLICER_ACTION_DISCARD:
        val = "SX_POLICER_ACTION_DISCARD";
        break;

    case SX_POLICER_ACTION_FORWARD_SET_RED_COLOR:
        val = "SX_POLICER_ACTION_FORWARD_SET_RED_COLOR or SX_POLICER_ACTION_FORWARD_SET_YELLOW_COLOR";
        break;

    default:
        val = "unknown packet action";
    }
    SX_LOG_INF("%s:%s, %d\n", action_name, val, sx_policer_action);
}

void log_sx_policer_attributes(_In_ sx_policer_id_t sx_policer, _In_ sx_policer_attributes_t* sx_attribs)
{
    char* val = NULL;

    SX_LOG_ENTER();
    SX_LOG_INF("[start]:log sx_policer_attributes_t\n");
    SX_LOG_INF("sx_policer:0x%" PRIx64 "\n", sx_policer);

    switch (sx_attribs->meter_type) {
    case SX_POLICER_METER_PACKETS:
        val = "SX_POLICER_METER_PACKETS";
        break;

    case SX_POLICER_METER_TRAFFIC:
        val = "SX_POLICER_METER_TRAFFIC";
        break;

    default:
        val = "unknown meter type";
    }
    SX_LOG_INF("meter_type:%s, %d\n", val, sx_attribs->meter_type);


    SX_LOG_INF("cbs:%d\n", sx_attribs->cbs);
    SX_LOG_INF("ebs:%d\n", sx_attribs->ebs);

    SX_LOG_INF("cir:%d\n", sx_attribs->cir);

    log_sx_policer_attrib_color_action(sx_attribs->yellow_action, "yellow_action");
    log_sx_policer_attrib_color_action(sx_attribs->red_action, "red_action");
    /* log_sx_policer_attrib_color_action(sx_attribs->green_action, "green_action"); */

    SX_LOG_INF("eir:%d\n", sx_attribs->eir);

    switch (sx_attribs->rate_type) {
    case SX_POLICER_RATE_TYPE_SX_E:
        val = "SX_POLICER_RATE_TYPE_SX_E [Single rate three color marker]";
        break;

    case SX_POLICER_RATE_TYPE_SINGLE_RATE_E:
        val = "SX_POLICER_RATE_TYPE_SINGLE_RATE_E";
        break;

    case SX_POLICER_RATE_TYPE_DUAL_RATE_E:
        val = "SX_POLICER_RATE_TYPE_DUAL_RATE_E";
        break;

    default:
        val = "unknown rate type";
    }
    SX_LOG_INF("rate_type:%s, %d\n", val, sx_attribs->rate_type);
    SX_LOG_INF("color_aware:%d\n", sx_attribs->color_aware);
    SX_LOG_INF("is_host_ifc_policer:%d\n", sx_attribs->is_host_ifc_policer);
    SX_LOG_INF("[end]:log sx_policer_attributes_t\n");
    SX_LOG_EXIT();
}

/*
 *  Calls into sx API to obtain sx policer attributes
 */
static sai_status_t sai_policer_get_sx_attribs_internal(_In_ const sai_object_key_t *key,
                                                        sx_policer_attributes_t     *sx_policer_attribs,
                                                        _In_ bool                    lock_db_access)
{
    sai_status_t             sai_status;
    mlnx_policer_db_entry_t* policer_db_entry = NULL;
    sai_object_type_t        obj_type;

    SX_LOG_ENTER();

    obj_type = sai_object_type_query(key->key.object_id);
    if (SAI_OBJECT_TYPE_POLICER != obj_type) {
        SX_LOG_ERR("Unexpected obect type:%s was expected policer.\n", SAI_TYPE_STR(obj_type));
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == sx_policer_attribs) {
        SX_LOG_ERR("NULL sx policer attributes\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (lock_db_access) {
        policer_db_cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = db_get_sai_policer_data(key->key.object_id, &policer_db_entry))) {
        SX_LOG_ERR("Failed to obtain sx policer db entry. object_id:0x%" PRIx64 "\n", key->key.object_id);
    } else {
        *sx_policer_attribs = policer_db_entry->sx_policer_attr;
        log_sx_policer_attributes(policer_db_entry->sx_policer_id_trap, sx_policer_attribs);
    }

    if (lock_db_access) {
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
    }

    SX_LOG_EXIT();
    return sai_status;
}


static sai_status_t sai_policer_get_sx_attribs(_In_ const sai_object_key_t *key,
                                               sx_policer_attributes_t     *sx_policer_attribs)
{
    return sai_policer_get_sx_attribs_internal(key, sx_policer_attribs, true);
}


static sai_status_t sai_policer_meter_type_attr_get(_In_ const sai_object_key_t   *key,
                                                    _Inout_ sai_attribute_value_t *value,
                                                    _In_ uint32_t                  attr_index,
                                                    _Inout_ vendor_cache_t        *cache,
                                                    void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;
    int32_t                 meter_val = 0;

    SX_LOG_ENTER();
    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = sx_meter_type_to_sai(sx_policer_attrs.meter_type, &meter_val))) {
        SX_LOG_EXIT();
        return sai_status + attr_index;
    }

    value->s32 = meter_val;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_mode_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;
    int32_t                 val = 0;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = sx_mode_type_to_sai(sx_policer_attrs.rate_type, &val))) {
        SX_LOG_EXIT();
        return sai_status + attr_index;
    }

    value->s32 = val;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_color_source_get(_In_ const sai_object_key_t   *key,
                                                 _Inout_ sai_attribute_value_t *value,
                                                 _In_ uint32_t                  attr_index,
                                                 _Inout_ vendor_cache_t        *cache,
                                                 void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(attr_index);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = (sx_policer_attrs.color_aware) ? SAI_POLICER_COLOR_SOURCE_AWARE : SAI_POLICER_COLOR_SOURCE_BLIND;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_cbs_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(attr_index);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_POLICER_METER_PACKETS == sx_policer_attrs.meter_type) {
        /* sai_cbs = (2^sx_cbs) packets */
        value->u64 = (sai_uint64_t)pow(2, sx_policer_attrs.cbs);
    } else {
        /* sai_cbs_bytes = (2^sx_CBS)*512 [bits]/ 8 */
        value->u64 = (sai_uint64_t)pow(2, sx_policer_attrs.cbs) * 512 / 8;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_cir_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(attr_index);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_POLICER_METER_PACKETS == sx_policer_attrs.meter_type) {
        value->u64 = sx_policer_attrs.cir;
    } else {
        /* sai_value = (sx_value * 10^3) / 8 [bytes/sec] */
        value->u64 = (((uint64_t)sx_policer_attrs.cir) * IR_UNITS) / 8;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_pbs_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(attr_index);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_POLICER_METER_PACKETS == sx_policer_attrs.meter_type) {
        /* sai_cbs = (2^sx_cbs) packets */
        value->u64 = (sai_uint64_t)pow(2, sx_policer_attrs.ebs);
    } else {
        /* sai_cbs_bytes = (2^sx_CBS)*512 [bits]/ 8 */
        value->u64 = (sai_uint64_t)pow(2, sx_policer_attrs.ebs) * 512 / 8;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_pir_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;

    SX_LOG_ENTER();


    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(attr_index);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_POLICER_METER_PACKETS == sx_policer_attrs.meter_type) {
        value->u64 = sx_policer_attrs.eir;
    } else {
        /* sai_value = (sx_value * 10^3) / 8 [bytes/sec] */
        value->u64 = ((((uint64_t)sx_policer_attrs.eir)) * IR_UNITS) / 8;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_packet_action_get_internal(_In_ const sai_object_key_t            *key,
                                                           _In_ mlnx_sai_policer_color_indicator_t color,
                                                           _Out_ sai_attribute_value_t            *value)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attrs;
    sx_policer_action_t     sx_action;
    int32_t                 val = 0;

    SX_LOG_ENTER();

    memset(&sx_policer_attrs, 0, sizeof(sx_policer_attrs));

    if (MLNX_POLICER_COLOR_GREEN == color) {
        value->s32 = SAI_PACKET_ACTION_FORWARD;
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs(key, &sx_policer_attrs))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    switch (color) {
    case MLNX_POLICER_COLOR_YELLOW:
        sx_action = sx_policer_attrs.yellow_action;
        break;

    case MLNX_POLICER_COLOR_RED:
        sx_action = sx_policer_attrs.red_action;
        break;

    default:
        SX_LOG_ERR("Invalid color action indicator specified:%d.\n", color);
        return SAI_STATUS_INVALID_PARAMETER;
    }


    if (SAI_STATUS_SUCCESS != (sai_status = sx_policer_action_to_sai(sx_action, &val))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    value->s32 = val;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_green_packet_action_get(_In_ const sai_object_key_t   *key,
                                                        _Inout_ sai_attribute_value_t *value,
                                                        _In_ uint32_t                  attr_index,
                                                        _Inout_ vendor_cache_t        *cache,
                                                        void                          *arg)
{
    UNREFERENCED_PARAMETER(attr_index);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(arg);

    sai_status_t status;
    SX_LOG_ENTER();
    status = sai_policer_packet_action_get_internal(key, MLNX_POLICER_COLOR_GREEN, value);
    SX_LOG_EXIT();
    return status;
}


static sai_status_t sai_policer_yellow_packet_action_get(_In_ const sai_object_key_t   *key,
                                                         _Inout_ sai_attribute_value_t *value,
                                                         _In_ uint32_t                  attr_index,
                                                         _Inout_ vendor_cache_t        *cache,
                                                         void                          *arg)
{
    sai_status_t status;

    UNREFERENCED_PARAMETER(attr_index);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(arg);

    SX_LOG_ENTER();
    status = sai_policer_packet_action_get_internal(key, MLNX_POLICER_COLOR_YELLOW, value);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sai_policer_red_packet_action_get(_In_ const sai_object_key_t   *key,
                                                      _Inout_ sai_attribute_value_t *value,
                                                      _In_ uint32_t                  attr_index,
                                                      _Inout_ vendor_cache_t        *cache,
                                                      void                          *arg)
{
    sai_status_t status;

    UNREFERENCED_PARAMETER(attr_index);
    UNREFERENCED_PARAMETER(cache);
    UNREFERENCED_PARAMETER(arg);

    SX_LOG_ENTER();
    status = sai_policer_packet_action_get_internal(key, MLNX_POLICER_COLOR_RED, value);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sai_policer_get_packet_flags_for_policer_type(_In_ mlnx_port_policer_type    port_policer_type,
                                                                  _In_ const mlnx_port_config_t *port_config,
                                                                  _Out_ sx_port_packet_types_t  *packet_types_out)
{
    sx_port_packet_types_t packet_types;

    SX_LOG_ENTER();
    memset(&packet_types, 0, sizeof(packet_types));

    switch (port_policer_type) {
    case MLNX_PORT_POLICER_TYPE_REGULAR_INDEX:
        packet_types.uc                  =
            packet_types.mc              =
                packet_types.bc          =
                    packet_types.uuc     =
                        packet_types.umc = true;

        if (SAI_NULL_OBJECT_ID != port_config->port_policers[MLNX_PORT_POLICER_TYPE_FLOOD_INDEX]) {
            SX_LOG_DBG("removing flood traffic flags from regular storm policer\n");
            packet_types.uc      =
                packet_types.umc = false;
        }
        if (SAI_NULL_OBJECT_ID != port_config->port_policers[MLNX_PORT_POLICER_TYPE_BROADCAST_INDEX]) {
            SX_LOG_DBG("removing broadcast traffic flags from regular storm policer\n");
            packet_types.bc = false;
        }
        if (SAI_NULL_OBJECT_ID != port_config->port_policers[MLNX_PORT_POLICER_TYPE_MULTICAST_INDEX]) {
            SX_LOG_DBG("removing multicast traffic flags from regular storm policer\n");
            packet_types.mc = false;
        }
        break;

    case MLNX_PORT_POLICER_TYPE_FLOOD_INDEX:
        packet_types.uc      =
            packet_types.umc = true;
        break;

    case MLNX_PORT_POLICER_TYPE_BROADCAST_INDEX:
        packet_types.bc = true;
        break;

    case MLNX_PORT_POLICER_TYPE_MULTICAST_INDEX:
        packet_types.mc = true;
        break;

    default:
        SX_LOG_ERR("Invalid policer storm type:%d\n", port_policer_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    *packet_types_out = packet_types;
    SX_LOG_DBG("state of policer type%d: uc:%d, mc:%d, bc:%d, uuc:%d, umc:%d\n",
               port_policer_type, packet_types_out->uc, packet_types_out->mc,
               packet_types_out->bc, packet_types_out->uuc, packet_types_out->umc);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_commit_changes_to_port_bindings(sai_object_id_t sai_policer)
{
    sai_status_t                   sai_status;
    sx_status_t                    sx_status;
    mlnx_port_config_t            *port_config;
    mlnx_policer_db_entry_t      * policer_entry     = NULL;
    uint32_t                       storm_control_ind = 0;
    sx_port_storm_control_params_t storm_ctrl_params;
    uint32_t                       port_ind;
    uint32_t                       ii;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_entry))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    mlnx_port_foreach(port_config, port_ind) {
        for (ii = 0; ii < MLNX_PORT_POLICER_TYPE_MAX; ii++) {
            memset(&storm_ctrl_params, 0, sizeof(storm_ctrl_params));
            if (sai_policer == port_config->port_policers[ii]) {
                if (SAI_STATUS_SUCCESS !=
                    (sai_status =
                         sai_policer_get_packet_flags_for_policer_type(ii, port_config,
                                                                       &storm_ctrl_params.packet_types))) {
                    SX_LOG_EXIT();
                    return sai_status;
                }
                storm_ctrl_params.policer_params = policer_entry->sx_policer_attr;
                /* We are using the oritinal policer settings saved in the DB.
                 *  But need to set this flag to false for storm policer API to work.*/
                storm_ctrl_params.policer_params.is_host_ifc_policer = false;
                if (SX_STATUS_SUCCESS !=
                    (sx_status =
                         storm_policer_functions.sx_api_port_storm_control_set_p(
                             gh_sdk,
                             SX_ACCESS_CMD_EDIT,
                             port_config->logical,
                             storm_control_ind, &storm_ctrl_params))) {
                    SX_LOG_ERR(
                        "Failed to commit policer port storm_binding[%d] changes. sdk message:%s. saipolicer:0x%" PRIx64 "\n",
                        storm_control_ind,
                        SX_STATUS_MSG(sx_status),
                        sai_policer);
                    SX_LOG_EXIT();
                    sai_status = sdk_to_sai(sx_status);
                    return sai_status;
                }
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_commit_changes(_In_ sai_object_id_t sai_policer)
{
    sai_status_t              sai_status;
    sx_status_t               sx_status;
    mlnx_policer_db_entry_t * policer_entry = NULL;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_entry))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (policer_entry->sx_policer_id_acl != SX_POLICER_ID_INVALID) {
        SX_LOG_NTC(
            "Calling sx_api_policer_set to commit for acl sx policer0x%" PRIx64 ". sai_policer:0x%" PRIx64 ".\n",
            policer_entry->sx_policer_id_acl,
            sai_policer);
        policer_entry->sx_policer_attr.is_host_ifc_policer = false;
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_policer_set(gh_sdk,
                                            SX_ACCESS_CMD_EDIT,
                                            &(policer_entry->sx_policer_attr),
                                            &(policer_entry->sx_policer_id_acl))
            )) {
            SX_LOG_ERR(
                "Failed to commit for acl sx policer0x%" PRIx64 ". sai_policer:0x%" PRIx64 ". Error message:%s.\n",
                policer_entry->sx_policer_id_acl,
                sai_policer,
                SX_STATUS_MSG(sx_status));

            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
    }
    if (policer_entry->sx_policer_id_trap != SX_POLICER_ID_INVALID) {
        SX_LOG_NTC(
            "Calling sx_api_policer_set to commit for trap sx policer0x%" PRIx64 ". sai_policer:0x%" PRIx64 ".\n",
            policer_entry->sx_policer_id_trap,
            sai_policer);
        policer_entry->sx_policer_attr.is_host_ifc_policer = true;
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_policer_set(gh_sdk,
                                            SX_ACCESS_CMD_EDIT,
                                            &(policer_entry->sx_policer_attr),
                                            &(policer_entry->sx_policer_id_trap))
            )) {
            SX_LOG_ERR(
                "Failed to commit for trap sx policer0x%" PRIx64 ". sai_policer:0x%" PRIx64 ". Error message:%s.\n",
                policer_entry->sx_policer_id_trap,
                sai_policer,
                SX_STATUS_MSG(sx_status));

            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
    }
    sai_status = sai_policer_commit_changes_to_port_bindings(sai_policer);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t sai_policer_attr_set(_In_ const sai_object_key_t* key,
                                         _In_ sai_attribute_t         sai_attr,
                                         _In_ char                  * attr_name)
{
    sai_status_t            sai_status;
    sx_policer_attributes_t sx_policer_attribs;
    sai_object_type_t       obj_type;

    SX_LOG_ENTER();

    memset(&sx_policer_attribs, 0, sizeof(sx_policer_attribs));

    obj_type = sai_object_type_query(key->key.object_id);
    if (SAI_OBJECT_TYPE_POLICER != obj_type) {
        SX_LOG_ERR("Unexpected obect type:%s, expected policer.\n", SAI_TYPE_STR(obj_type));
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    policer_db_cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_policer_get_sx_attribs_internal(key, &sx_policer_attribs, false))) {
        SX_LOG_ERR("Failed to obtain attribute value.\n");
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = fill_policer_data(false, 1, &sai_attr, &sx_policer_attribs))) {
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = db_write_sai_policer_attribs(key->key.object_id, &(sx_policer_attribs)))) {
        SX_LOG_ERR("Failed to change attribute for policer:0x%" PRIx64 ", attribute: %s.\n", key->key.object_id,
                   attr_name);
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = sai_policer_commit_changes(key->key.object_id))) {
        SX_LOG_ERR("Failed to commiting policer changes for sai_policer:0x%" PRIx64 ", attribute: %s.\n",
                   key->key.object_id,
                   attr_name);
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return sai_status;
    }

    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t sai_policer_attr_set_wrapper(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 _In_ sai_policer_attr_t           attr_id,
                                                 _In_ char                       * attr_name,
                                                 _In_ void                       * arg)
{
    sai_attribute_t sai_attr;
    sai_status_t    sai_status;

    UNREFERENCED_PARAMETER(arg);

    SX_LOG_ENTER();
    sai_attr.id    = attr_id;
    sai_attr.value = *value;
    sai_status     = sai_policer_attr_set(key, sai_attr, attr_name);
    SX_LOG_DBG("Result of setting %s:%d\n", attr_name, sai_status);
    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t sai_policer_color_source_set(_In_ const sai_object_key_t      *key,
                                                 _In_ const sai_attribute_value_t *value,
                                                 void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key,
                                          value,
                                          SAI_POLICER_ATTR_COLOR_SOURCE,
                                          "SAI_POLICER_ATTR_COLOR_SOURCE",
                                          arg);
    SX_LOG_EXIT();
    return status;
}


static sai_status_t sai_policer_cbs_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key, value, SAI_POLICER_ATTR_CBS, "SAI_POLICER_ATTR_CBS", arg);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sai_policer_cir_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key, value, SAI_POLICER_ATTR_CIR, "SAI_POLICER_ATTR_CIR", arg);
    SX_LOG_EXIT();
    return status;
}


static sai_status_t sai_policer_pbs_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key, value, SAI_POLICER_ATTR_PBS, "SAI_POLICER_ATTR_PBS", arg);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sai_policer_pir_set(_In_ const sai_object_key_t      *key,
                                        _In_ const sai_attribute_value_t *value,
                                        void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key, value, SAI_POLICER_ATTR_PIR, "SAI_POLICER_ATTR_PIR", arg);
    SX_LOG_EXIT();
    return status;
}


static sai_status_t sai_policer_green_packet_action_set(_In_ const sai_object_key_t      *key,
                                                        _In_ const sai_attribute_value_t *value,
                                                        void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key,
                                          value,
                                          SAI_POLICER_ATTR_GREEN_PACKET_ACTION,
                                          "SAI_POLICER_ATTR_GREEN_PACKET_ACTION",
                                          arg);
    SX_LOG_EXIT();
    return status;
}


static sai_status_t sai_policer_yellow_packet_action_set(_In_ const sai_object_key_t      *key,
                                                         _In_ const sai_attribute_value_t *value,
                                                         void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key,
                                          value,
                                          SAI_POLICER_ATTR_YELLOW_PACKET_ACTION,
                                          "SAI_POLICER_ATTR_YELLOW_PACKET_ACTION",
                                          arg);
    SX_LOG_EXIT();
    return status;
}

static sai_status_t sai_policer_red_packet_action_set(_In_ const sai_object_key_t      *key,
                                                      _In_ const sai_attribute_value_t *value,
                                                      void                             *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();
    status = sai_policer_attr_set_wrapper(key,
                                          value,
                                          SAI_POLICER_ATTR_RED_PACKET_ACTION,
                                          "SAI_POLICER_ATTR_RED_PACKET_ACTION",
                                          arg);
    SX_LOG_EXIT();
    return status;
}

static void policer_key_to_str(_In_ sai_object_id_t policer_id, _Out_ char *key_str)
{
    uint32_t policer_db_index = 0;

    if (SAI_STATUS_SUCCESS != mlnx_object_to_type(policer_id, SAI_OBJECT_TYPE_POLICER, &policer_db_index, NULL)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid policer key");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "policer key:%x", policer_db_index);
    }
}

static sai_status_t sx_meter_type_to_sai(_In_ sx_policer_meter_t sx_val, _Out_ int32_t* sai_val)
{
    SX_LOG_DBG("Input SX meter type:%d\n", sx_val);
    switch (sx_val) {
    case SX_POLICER_METER_PACKETS:
        *sai_val = SAI_METER_TYPE_PACKETS;
        break;

    case SX_POLICER_METER_TRAFFIC:
        *sai_val = SAI_METER_TYPE_BYTES;
        break;

    default:
        SX_LOG_ERR("Invalid sx policer meter value specified:%d\n", sx_val);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    SX_LOG_DBG("Output SAI meter type:%d\n", *sai_val);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sx_mode_type_to_sai(_In_ sx_policer_rate_type_e sx_val, _Out_ int32_t* sai_val)
{
    SX_LOG_DBG("Input SX mode type:%d\n", sx_val);
    switch (sx_val) {
    case SX_POLICER_RATE_TYPE_SX_E:
    case SX_POLICER_RATE_TYPE_SINGLE_RATE_E:
        *sai_val = SAI_POLICER_MODE_SR_TCM;
        break;

    case SX_POLICER_RATE_TYPE_DUAL_RATE_E:
        *sai_val = SAI_POLICER_MODE_TR_TCM;
        break;

    default:
        SX_LOG_ERR("Invalid policer mode value specified:%d\n", sx_val);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    SX_LOG_DBG("Output SAI mode type:%d\n", *sai_val);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sx_policer_action_to_sai(_In_ sx_policer_action_t sx_val, _Out_ int32_t* sai_val)
{
    SX_LOG_DBG("Input SX policer action: %d\n", sx_val);
    switch (sx_val) {
    case SX_POLICER_ACTION_DISCARD:
        *sai_val = SAI_PACKET_ACTION_DROP;
        break;

    case SX_POLICER_ACTION_FORWARD:
    case SX_POLICER_ACTION_FORWARD_SET_RED_COLOR:
        *sai_val = SAI_PACKET_ACTION_FORWARD;
        break;

    default:
        SX_LOG_ERR("Invalid policer action value specified:%x\n", sx_val);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    SX_LOG_DBG("Output SAI policer action: %d\n", *sai_val);
    return SAI_STATUS_SUCCESS;
}


/*
 *  SAI to SX conversion helper.
 *  Caller needs to make sure the Out parameter is a valid pointer
 */
static sai_status_t sai_policer_mode_to_sx(_In_ sai_policer_mode_t sai_val, _Out_ int32_t* sx_val)
{
    SX_LOG_DBG("Input SAI policer mode: %d\n", sai_val);
    switch (sai_val) {
    case SAI_POLICER_MODE_SR_TCM:
        *sx_val = SX_POLICER_RATE_TYPE_SINGLE_RATE_E;
        break;

    case SAI_POLICER_MODE_TR_TCM:
        *sx_val = SX_POLICER_RATE_TYPE_DUAL_RATE_E;
        break;

    case SAI_POLICER_MODE_STORM_CONTROL:
        *sx_val = SX_POLICER_RATE_TYPE_SINGLE_RATE_E;
        break;

    default:
        SX_LOG_ERR("Invalid policer mode value specified:%d\n", sai_val);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }

    SX_LOG_DBG("Output SX policer mode: %d\n", *sx_val);
    return SAI_STATUS_SUCCESS;
}

/*
 *  SAI to SX conversion helper.
 *  Caller needs to make sure the Out parameter is a valid pointer
 */
static sai_status_t sai_meter_type_to_sx(_In_ sai_meter_type_t sai_val, _Out_ int32_t* sx_val)
{
    SX_LOG_DBG("Input SAI meter type:%d\n", sai_val);
    switch (sai_val) {
    case SAI_METER_TYPE_PACKETS:
        *sx_val = SX_POLICER_METER_PACKETS;
        break;

    case SAI_METER_TYPE_BYTES:
        *sx_val = SX_POLICER_METER_TRAFFIC;
        break;

    default:
        SX_LOG_ERR("Invalid policer meter type value specified:%d\n", sai_val);
        return SAI_STATUS_INVALID_ATTR_VALUE_0;
    }
    SX_LOG_DBG("Output SX meter type:%d\n", *sx_val);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_meter_type_attrib(_In_ uint32_t               attr_count,
                                           _In_ const sai_attribute_t *attr_list,
                                           sx_policer_attributes_t    *sx_policer_attribs)
{
    SX_LOG_ENTER();
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index      = 0;
    sai_status_t                 status;
    int32_t                      value;

    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_METER_TYPE, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_METER_TYPE not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status = sai_meter_type_to_sx(attr_value->s32, &value))) {
            return status + index;
        } else {
            sx_policer_attribs->meter_type = value;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_policer_mode_attrib(_In_ uint32_t               attr_count,
                                             _In_ const sai_attribute_t *attr_list,
                                             sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;
    int32_t                      value;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_MODE, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_MODE not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (SAI_STATUS_SUCCESS !=
            (status = sai_policer_mode_to_sx(attr_value->s32, &value))) {
            SX_LOG_EXIT();
            return status + index;
        } else {
            sx_policer_attribs->rate_type = value;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_policer_color_source_attrib(_In_ bool                   set_defaults,
                                                     _In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list,
                                                     sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_COLOR_SOURCE, &attr_value, &index))) {
        SX_LOG_NTC("Attribute SAI_POLICER_ATTR_COLOR_SOURCE not present\n");

        /* Default is SAI_POLICER_COLOR_SOURCE_AWARE*/
        if (set_defaults) {
            SX_LOG_DBG("Setting default value TRUE for SAI_POLICER_ATTR_COLOR_SOURCE\n");
            sx_policer_attribs->color_aware = true;
        }
        status = SAI_STATUS_SUCCESS;
    } else {
        if (SAI_POLICER_COLOR_SOURCE_BLIND == attr_value->s32) {
            sx_policer_attribs->color_aware = false;
        } else if (SAI_POLICER_COLOR_SOURCE_AWARE == attr_value->s32) {
            sx_policer_attribs->color_aware = true;
        } else {
            SX_LOG_ERR("Invalid value specified for SAI_POLICER_ATTR_COLOR_SOURCE, value: %d\n", attr_value->s32);

            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_policer_cbs_attrib(_In_ uint32_t                    attr_count,
                                            _In_ const sai_attribute_t      *attr_list,
                                            _Inout_ sx_policer_attributes_t* sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_CBS, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_CBS not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (attr_value->u64 > UINT_MAX) {
            SX_LOG_ERR("The value of SAI_POLICER_ATTR_CBS exceeds supported maximum value");

            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }

        if (SX_POLICER_METER_PACKETS == sx_policer_attribs->meter_type) {
            /* sx_cbs == Log2 sai_cbs */
            sx_policer_attribs->cbs = (uint32_t)round(log10((double)attr_value->u64) / log10(2));
        } else {
            /* sx_CBS = Log2[(sai_cbs_bytes * 8) / 512] */
            sx_policer_attribs->cbs =
                (uint32_t)round(log10((double)attr_value->u64 * 8 / 512) / log10(2));
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_policer_cir_attrib(_In_ uint32_t                    attr_count,
                                            _In_ const sai_attribute_t      *attr_list,
                                            _Inout_ sx_policer_attributes_t* sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_CIR, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_CIR not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (attr_value->u64 > UINT_MAX) {
            SX_LOG_ERR("The value of SAI_POLICER_ATTR_CIR exceeds supported maximum value");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }

        if (SX_POLICER_METER_PACKETS == sx_policer_attribs->meter_type) {
            sx_policer_attribs->cir = (uint32_t)(attr_value->u64);
        } else {
            /* 8 * sai_CIR_bytes / (10^3) = sx_value [bits/sec] */
            sx_policer_attribs->cir = (uint32_t)(8 * attr_value->u64 / IR_UNITS);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t fill_policer_pbs_attrib(_In_ uint32_t                    attr_count,
                                            _In_ const sai_attribute_t      *attr_list,
                                            _Inout_ sx_policer_attributes_t* sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index      = 0;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_PBS, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_PBS not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (attr_value->u64 > UINT_MAX) {
            SX_LOG_ERR("The value of SAI_POLICER_ATTR_PBS exceeds supported maximum value");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
        if (SX_POLICER_METER_PACKETS == sx_policer_attribs->meter_type) {
            /* sx_cbs == Log2 sai_cbs */
            sx_policer_attribs->ebs = (uint32_t)round(log10((double)attr_value->u64) / log10(2));
        } else {
            /* sx_CBS = Log2[(sai_cbs_bytes * 8) / 512] */
            sx_policer_attribs->ebs =
                (uint32_t)round(log10((double)attr_value->u64 * 8 / 512) / log10(2));
        }
    }
    return status;
}

static sai_status_t fill_policer_pir_attrib(_In_ uint32_t                    attr_count,
                                            _In_ const sai_attribute_t      *attr_list,
                                            _Inout_ sx_policer_attributes_t* sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status = find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_PIR, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_PIR not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        if (attr_value->u64 > UINT_MAX) {
            SX_LOG_ERR("The value of SAI_POLICER_ATTR_PIR exceeds supported maximum value");
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
        if (SX_POLICER_METER_PACKETS == sx_policer_attribs->meter_type) {
            sx_policer_attribs->eir = (uint32_t)(attr_value->u64);
        } else {
            /* 8 * sai_CIR_bytes / (10^3) = sx_value [bits/sec] */
            sx_policer_attribs->eir = (uint32_t)(8 * attr_value->u64 / IR_UNITS);
        }
    }
    return status;
}

static sai_status_t fill_policer_green_action_attrib(_In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list,
                                                     sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    /* NOTE: There is no field in sx_policer_attributes representing green action, it's implied to have forward value always.
     *        For this reason, there is only a validation here.*/
    if (SAI_STATUS_SUCCESS !=
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_GREEN_PACKET_ACTION, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_GREEN_PACKET_ACTION not present\n");

        status = SAI_STATUS_SUCCESS;
    } else {
        /* If value is specified for green action, it must be forward.*/
        if (SAI_PACKET_ACTION_FORWARD != attr_value->s32) {
            SX_LOG_ERR(
                "Only SAI_PACKET_ACTION_FORWARD is supported for SAI_POLICER_ATTR_GREEN_PACKET_ACTION. input:%d\n",
                attr_value->s32);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
    }
    return status;
}

static sai_status_t fill_policer_yellow_action_attrib(_In_ bool                   set_defaults,
                                                      _In_ uint32_t               attr_count,
                                                      _In_ const sai_attribute_t *attr_list,
                                                      sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_YELLOW_PACKET_ACTION not present\n");

        if (set_defaults) {
            SX_LOG_DBG("Setting default value SX_POLICER_ACTION_FORWARD for SAI_POLICER_ATTR_YELLOW_PACKET_ACTION\n");
            sx_policer_attribs->yellow_action = SX_POLICER_ACTION_FORWARD_SET_YELLOW_COLOR;
        }
        status = SAI_STATUS_SUCCESS;
    } else {
        if (SAI_PACKET_ACTION_FORWARD != attr_value->s32) {
            SX_LOG_ERR("Only SAI_PACKET_ACTION_FORWARD is supported for yellow packet action. input:%d\n",
                       attr_value->s32);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
        sx_policer_attribs->yellow_action = SX_POLICER_ACTION_FORWARD_SET_YELLOW_COLOR;
    }
    SX_LOG_DBG("sx yellow_action : %d\n", sx_policer_attribs->yellow_action);
    return status;
}


static sai_status_t fill_policer_red_action_attrib(_In_ bool                   set_defaults,
                                                   _In_ uint32_t               attr_count,
                                                   _In_ const sai_attribute_t *attr_list,
                                                   sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_RED_PACKET_ACTION, &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_RED_PACKET_ACTION not present\n");

        if (set_defaults) {
            SX_LOG_DBG(
                "Setting default value SX_POLICER_ACTION_FORWARD for SAI_POLICER_ATTR_RED_PACKET_ACTION.\n");
            sx_policer_attribs->red_action = SX_POLICER_ACTION_FORWARD_SET_RED_COLOR;
        }
        status = SAI_STATUS_SUCCESS;
    } else {
        if (SAI_PACKET_ACTION_FORWARD == attr_value->s32) {
            sx_policer_attribs->red_action = SX_POLICER_ACTION_FORWARD_SET_RED_COLOR;
        } else if (SAI_PACKET_ACTION_DROP == attr_value->s32) {
            sx_policer_attribs->red_action = SX_POLICER_ACTION_DISCARD;
        } else {
            SX_LOG_ERR("Only drop and forward actions are supported red packet action %d\n", attr_value->s32);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + index;
        }
    }
    SX_LOG_DBG("sx red_action : %d\n", sx_policer_attribs->red_action);
    return status;
}

static sai_status_t fill_policer_counter_list_attrib(_In_ uint32_t               attr_count,
                                                     _In_ const sai_attribute_t *attr_list,
                                                     sx_policer_attributes_t    *sx_policer_attribs)
{
    const sai_attribute_value_t* attr_value = NULL;
    uint32_t                     index;
    sai_status_t                 status;

    if (SAI_STATUS_SUCCESS !=
        (status =
             find_attrib_in_list(attr_count, attr_list, SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST,
                                 &attr_value, &index))) {
        SX_LOG_DBG("Attribute SAI_POLICER_ATTR_ENABLE_COUNTER_LIST not present\n");
        status = SAI_STATUS_SUCCESS;
    } else {
        SX_LOG_ERR("Attribute SAI_POLICER_ATTR_ENABLE_COUNTER_LIST is present, but not supported by the HW\n");
        return SAI_STATUS_NOT_SUPPORTED;
    }
    return status;
}


/*
 *  This function fills in sx attributes structure with the array of SAI attributes passed int.
 *  if TRUE == set_defaults, then for values which are not present it'll assign the default values.
 *  if FALSE == set_defaults, then the value will not be set if corresponding SAI attribute is not present.
 *
 *  NOTE:
 *   if it's important for the caller to have specific type of attributes present,
 *   then prior to calling this function the caller must call check_attribs_metadata.
 *   For example to make sure all CREATE attributes are present,
 *   caller would call check_attribs_metadata(SAI_OPERATION_CREATE)
 */
static sai_status_t fill_policer_data(_In_ bool                   set_defaults,
                                      _In_ uint32_t               attr_count,
                                      _In_ const sai_attribute_t *attr_list,
                                      sx_policer_attributes_t    *sx_policer_attribs)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (NULL == sx_policer_attribs) {
        SX_LOG_ERR("NULL policer attrib\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sx_policer_attribs->ir_units = SX_POLICER_IR_UNITS_10_POWER_3_E;

    if (NULL == attr_list) {
        SX_LOG_ERR("NULL attr_list parameter\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_meter_type_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_mode_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_color_source_attrib(set_defaults, attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_cbs_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }


    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_cir_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_pbs_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_pir_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }


    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_green_action_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_yellow_action_attrib(set_defaults, attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_red_action_attrib(set_defaults, attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = fill_policer_counter_list_attrib(attr_count, attr_list, sx_policer_attribs))) {
        SX_LOG_EXIT();
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 *  Returns the value from g_sai_db_ptr->policers_db at db_policers_entry_index.
 */
sai_status_t db_get_sai_policer_data(_In_ sai_object_id_t            sai_policer_id,
                                     _Out_ mlnx_policer_db_entry_t** policer_entry)
{
    sai_status_t sai_status;
    uint32_t     db_policers_entry_index;


    SX_LOG_ENTER();

    SX_LOG_DBG("Input policer:0x%" PRIx64 "\n", sai_policer_id);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_policer_id, SAI_OBJECT_TYPE_POLICER, &db_policers_entry_index, NULL))) {
        SX_LOG_ERR("Failed to obtain policer db index. Invalid object type:%s passed in. object_id:0x%" PRIx64 "\n",
                   SAI_TYPE_STR(sai_policer_id),
                   sai_policer_id);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (db_policers_entry_index >= MAX_POLICERS) {
        SX_LOG_ERR("Invalid policer index: %d\n", db_policers_entry_index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!g_sai_db_ptr->policers_db[db_policers_entry_index].valid) {
        SX_LOG_ERR("Invalid policer entry requested; marked as invalid. index:%d\n", db_policers_entry_index);
        SX_LOG_EXIT();
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    *policer_entry = &(g_sai_db_ptr->policers_db[db_policers_entry_index]);

    SX_LOG_DBG("policer_db table index:%d\n", db_policers_entry_index);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


static sai_status_t db_remove_sai_policer_data(_In_ uint32_t db_policers_entry_index)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    SX_LOG_ENTER();

    SX_LOG_DBG("db_policers_entry_index:%d\n", db_policers_entry_index);

    if (db_policers_entry_index >= MAX_POLICERS) {
        SX_LOG_ERR("Invalid Policers table index:%d\n", db_policers_entry_index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }


    if (g_sai_db_ptr->policers_db[db_policers_entry_index].valid) {
        db_reset_policer_entry(db_policers_entry_index);
        g_sai_db_ptr->policers_db[db_policers_entry_index].valid = false;
    } else {
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        SX_LOG_ERR("Trying to free unoccupied entry in policers db table. index:%d\n", db_policers_entry_index);
    }

    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t db_write_sai_policer_attribs(_In_ sai_object_id_t          sai_policer_id,
                                                 _In_ sx_policer_attributes_t* sx_policer_attr)
{
    uint32_t     db_policers_entry_index;
    sai_status_t status;

    SX_LOG_ENTER();

    if (NULL == sx_policer_attr) {
        SX_LOG_ERR("NULL policer attribs\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_NULL_OBJECT_ID == sai_policer_id) {
        SX_LOG_ERR("NULL policer\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status = mlnx_object_to_type(sai_policer_id, SAI_OBJECT_TYPE_POLICER, &db_policers_entry_index, NULL))) {
        SX_LOG_ERR("Failed to obtain policer db index. object_id:0x%" PRIx64 "\n", sai_policer_id);
        SX_LOG_EXIT();
        return status;
    }

    if (MAX_POLICERS <= db_policers_entry_index) {
        SX_LOG_ERR("Invalid policer index:%d\n", db_policers_entry_index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!g_sai_db_ptr->policers_db[db_policers_entry_index].valid) {
        SX_LOG_ERR("Policer id:0x%" PRIx64 " resolved at invalid at db index:%d \n",
                   sai_policer_id,
                   db_policers_entry_index
                   );
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_attr          = *sx_policer_attr;
    g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_attr.ir_units = SX_POLICER_IR_UNITS_10_POWER_3_E;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

void db_reset_policer_entry(_In_ uint32_t db_policers_entry_index)
{
    SX_LOG_ENTER();
    assert(db_policers_entry_index < MAX_POLICERS);
    g_sai_db_ptr->policers_db[db_policers_entry_index].valid              = false;
    g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_id_trap = SX_POLICER_ID_INVALID;
    g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_id_acl  = SX_POLICER_ID_INVALID;
    memset(&(g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_attr), 0,
           sizeof(g_sai_db_ptr->policers_db[db_policers_entry_index].sx_policer_attr));
    SX_LOG_EXIT();
}

sai_status_t db_init_sai_policer_data(_In_ sx_policer_attributes_t* policer_attr,
                                      _Out_ uint32_t              * db_policers_entry_index_p)
{
    uint32_t ii;

    SX_LOG_ENTER();

    if (NULL == policer_attr) {
        SX_LOG_ERR("NULL policer attribs\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (NULL == db_policers_entry_index_p) {
        SX_LOG_ERR("NULL policer index\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    policer_db_cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    for (ii = 0; ii < MAX_POLICERS; ii++) {
        if (false == g_sai_db_ptr->policers_db[ii].valid) {
            break;
        }
    }

    if (MAX_POLICERS == ii) {
        SX_LOG_ERR("Policers table full\n");
        policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
        SX_LOG_EXIT();
        return SAI_STATUS_TABLE_FULL;
    }

    db_reset_policer_entry(ii);

    g_sai_db_ptr->policers_db[ii].valid                    = true;
    g_sai_db_ptr->policers_db[ii].sx_policer_attr.ir_units = SX_POLICER_IR_UNITS_10_POWER_3_E;
    g_sai_db_ptr->policers_db[ii].sx_policer_attr          = *policer_attr;

    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);

    *db_policers_entry_index_p = ii;

    SX_LOG_NTC("Created sai_policer db entry, at index : %d. NOTE, no sx_policer created.\n", ii);
    log_sx_policer_attributes(g_sai_db_ptr->policers_db[ii].sx_policer_id_trap,
                              &(g_sai_db_ptr->policers_db[ii].sx_policer_attr));

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t db_find_sai_policer_entry_ind(_In_ sx_policer_id_t sx_policer, _Out_ uint32_t* entry_index)
{
    sai_status_t status;
    uint32_t     policer_entry_ind;
    uint32_t     policer_entry_cnt = MLNX_SAI_ARRAY_LEN(g_sai_db_ptr->policers_db);

    if (NULL == entry_index) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (policer_entry_ind = 0; policer_entry_ind < policer_entry_cnt; policer_entry_ind++) {
        if (!g_sai_db_ptr->policers_db[policer_entry_ind].valid) {
            continue;
        }
        if (sx_policer == g_sai_db_ptr->policers_db[policer_entry_ind].sx_policer_id_trap) {
            break;
        }
        if (sx_policer == g_sai_db_ptr->policers_db[policer_entry_ind].sx_policer_id_acl) {
            break;
        }
    }

    if (policer_entry_ind == policer_entry_cnt) {
        status = SAI_STATUS_ITEM_NOT_FOUND;
    } else {
        *entry_index = policer_entry_ind;
        status       = SAI_STATUS_SUCCESS;
    }

    return status;
}


static sai_status_t mlnx_sai_create_policer(_Out_ sai_object_id_t      *policer_id,
                                            _In_ sai_object_id_t        switch_id,
                                            _In_ uint32_t               attr_count,
                                            _In_ const sai_attribute_t *attr_list)
{
    sai_status_t            sai_status;
    sai_object_id_t         sai_policer = SAI_NULL_OBJECT_ID;
    sx_policer_attributes_t sai_policer_attr;
    uint32_t                sai_policer_db_index             = 0;
    char                    list_str[MAX_LIST_VALUE_STR_LEN] = { 0 };
    char                    key_str[MAX_KEY_STR_LEN]         = { 0 };

    SX_LOG_ENTER();

    memset(&sai_policer_attr, 0, sizeof(sai_policer_attr));

    if (NULL == policer_id) {
        SX_LOG_ERR("NULL policer ID parameter\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = check_attribs_metadata(
             attr_count,
             attr_list,
             SAI_OBJECT_TYPE_POLICER,
             policer_vendor_attribs,
             SAI_COMMON_API_CREATE))) {
        SX_LOG_ERR("Failed policer attribs check during create operation, SAI status:%d\n", sai_status);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = sai_attr_list_to_str(
             attr_count,
             attr_list,
             SAI_OBJECT_TYPE_POLICER,
             MAX_LIST_VALUE_STR_LEN,
             list_str))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_NTC("Creating policer with attributes: %s\n", list_str);

    if (SAI_STATUS_SUCCESS !=
        (sai_status = fill_policer_data(true, attr_count, attr_list, &sai_policer_attr))) {
        SX_LOG_NTC("Initializing policer data failed\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = db_init_sai_policer_data(&sai_policer_attr, &sai_policer_db_index))) {
        SX_LOG_NTC("Failed processing policer initialization data\n");
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_create_object(SAI_OBJECT_TYPE_POLICER, sai_policer_db_index, NULL, &sai_policer))) {
        db_remove_sai_policer_data(sai_policer_db_index);
        SX_LOG_EXIT();
        return sai_status;
    }

    *policer_id = sai_policer;
    policer_key_to_str(*policer_id, key_str);
    SX_LOG_NTC("Created policer %s\n", key_str);

    SX_LOG_EXIT();

    return sai_status;
}

static sai_status_t mlnx_validate_port_policer_for_remove(_In_ sai_object_id_t sai_policer)
{
    uint32_t                 port_ind, ii;
    sai_status_t             status;
    mlnx_port_config_t      *port_config;
    mlnx_policer_db_entry_t* policer_db_data = NULL;

    SX_LOG_ENTER();

    if (SAI_NULL_OBJECT_ID == sai_policer) {
        SX_LOG_ERR("null policer entry.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS != (status = db_get_sai_policer_data(sai_policer, &policer_db_data))) {
        SX_LOG_ERR("Failed to obtain policer db data for sai policer:0x%" PRIx64 "\n", sai_policer);
        return status;
    }

    mlnx_port_foreach(port_config, port_ind) {
        for (ii = 0; ii < MLNX_PORT_POLICER_TYPE_MAX; ii++) {
            if (sai_policer == port_config->port_policers[ii]) {
                return SAI_STATUS_OBJECT_IN_USE;
            }
        }
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_remove_policer(_In_ sai_object_id_t sai_policer_id)
{
    sai_status_t             sai_status;
    sx_status_t              sx_status;
    sx_policer_attributes_t  policer_attr;
    char                     key_str[MAX_KEY_STR_LEN] = { 0 };
    mlnx_policer_db_entry_t* policer_db_data          = NULL;
    uint32_t                 db_policers_entry_index;
    sai_object_type_t        obj_type;

    SX_LOG_ENTER();

    memset(&policer_attr, 0, sizeof(policer_attr));

    obj_type = sai_object_type_query(sai_policer_id);

    if (SAI_OBJECT_TYPE_POLICER != obj_type) {
        SX_LOG_ERR("Invalid obect type:%s, expected policer.\n", SAI_TYPE_STR(obj_type));
        return SAI_STATUS_INVALID_PARAMETER;
    }

    policer_key_to_str(sai_policer_id, key_str);
    SX_LOG_NTC("Removing policer %s,:0x%" PRIx64 "\n", key_str, sai_policer_id);

    policer_db_cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);

    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer_id, &policer_db_data))) {
        SX_LOG_ERR("Failed to obtain policer db data for sai policer:0x%" PRIx64 "\n", sai_policer_id);
        goto exit;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_validate_port_policer_for_remove(sai_policer_id))) {
        SX_LOG_ERR("Failed to remove port policer entries. object_id:0x%" PRIx64 "\n", sai_policer_id);
        goto exit;
    }

    if (policer_db_data->sx_policer_id_acl != SX_POLICER_ID_INVALID) {
        policer_attr.is_host_ifc_policer = false;
        if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_set(gh_sdk,
                                                                 SX_ACCESS_CMD_DESTROY,
                                                                 &policer_attr,
                                                                 &policer_db_data->sx_policer_id_acl))) {
            SX_LOG_ERR("Failed to destroy acl SX policer:0x%" PRIx64 ". error message:%s.\n",
                       policer_db_data->sx_policer_id_acl,
                       SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto exit;
        }
        policer_db_data->sx_policer_id_acl = SX_POLICER_ID_INVALID;
    }
    if (policer_db_data->sx_policer_id_trap != SX_POLICER_ID_INVALID) {
        policer_attr.is_host_ifc_policer = true;
        if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_set(gh_sdk,
                                                                 SX_ACCESS_CMD_DESTROY,
                                                                 &policer_attr,
                                                                 &policer_db_data->sx_policer_id_trap))) {
            SX_LOG_ERR("Failed to destroy trap SX policer:0x%" PRIx64 ". error message:%s.\n",
                       policer_db_data->sx_policer_id_trap,
                       SX_STATUS_MSG(sx_status));
            sai_status = sdk_to_sai(sx_status);
            goto exit;
        }
        policer_db_data->sx_policer_id_trap = SX_POLICER_ID_INVALID;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_policer_id, SAI_OBJECT_TYPE_POLICER, &db_policers_entry_index, NULL))) {
        SX_LOG_ERR("Failed to obtain policer db index. object_id:0x%" PRIx64 "\n", sai_policer_id);
        goto exit;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = db_remove_sai_policer_data(db_policers_entry_index))) {
        SX_LOG_ERR("Failed to remove item from policer db. sai object_id:0x%" PRIx64 ", %s\n", sai_policer_id,
                   key_str);
        goto exit;
    }

exit:
    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_set_policer_attribute(_In_ sai_object_id_t policer_id, _In_ const sai_attribute_t *attr)
{
    sai_status_t           status;
    const sai_object_key_t key                      = { .key.object_id = policer_id };
    char                   key_str[MAX_KEY_STR_LEN] = { 0 };

    SX_LOG_ENTER();

    policer_key_to_str(policer_id, key_str);
    status = sai_set_attribute(&key, key_str, SAI_OBJECT_TYPE_POLICER, policer_vendor_attribs, attr);

    SX_LOG_EXIT();

    return status;
}

static sai_status_t mlnx_sai_get_policer_attribute(_In_ sai_object_id_t     policer_id,
                                                   _In_ uint32_t            attr_count,
                                                   _Inout_ sai_attribute_t *attr_list)
{
    const sai_object_key_t key                      = { .key.object_id = policer_id };
    char                   key_str[MAX_KEY_STR_LEN] = { 0 };
    sai_status_t           status;

    SX_LOG_ENTER();

    policer_key_to_str(policer_id, key_str);
    status = sai_get_attributes(&key, key_str, SAI_OBJECT_TYPE_POLICER, policer_vendor_attribs, attr_count, attr_list);

    SX_LOG_EXIT();
    return status;
}

static sai_status_t mlnx_do_policer_stats(_In_ sai_object_id_t           policer_id,
                                          _In_ uint32_t                  number_of_counters,
                                          _In_ const sai_policer_stat_t *counter_ids,
                                          _Out_ uint64_t               * counters,
                                          bool                           is_clear)
{
    sai_status_t                sai_status;
    sx_status_t                 sx_status;
    mlnx_port_config_t         *port_config;
    mlnx_policer_db_entry_t   * policer_entry = NULL;
    sx_policer_counters_t       policer_counters;
    sx_policer_counters_clear_t policer_counters_clear;
    uint32_t                    packet_type_ind;
    uint64_t                    aggregated_counter = 0;
    uint32_t                    port_ind;

    SX_LOG_ENTER();
    policer_counters_clear.clear_violation_counter = true;
    if (number_of_counters != 1) {
        SX_LOG_ERR("Only 1 counter is supported. policer:0x%" PRIx64 ".\n", policer_id);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto exit;
    }
    if (NULL == counter_ids) {
        SX_LOG_ERR("NULL counter_ids. policer:0x%" PRIx64 ".\n", policer_id);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto exit;
    }
    /* SDK supports only dropped packets. */
    if (SAI_POLICER_STAT_PACKETS != counter_ids[0]) {
        SX_LOG_ERR("Only SAI_POLICER_STAT_PACKETS are supported. policer:0x%" PRIx64 ".\n", policer_id);
        sai_status = SAI_STATUS_ATTR_NOT_SUPPORTED_0;
        goto exit;
    }
    if ((!is_clear) && (NULL == counters)) {
        SX_LOG_ERR("NULL out counters array. policer:0x%" PRIx64 ".\n", policer_id);
        sai_status = SAI_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    policer_db_cl_plock_excl_acquire(&g_sai_db_ptr->p_lock);
    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(policer_id, &policer_entry))) {
        goto exit;
    }
    log_sx_policer_attributes(policer_entry->sx_policer_id_trap, &policer_entry->sx_policer_attr);
    SX_LOG_DBG("entry is valid:%d\n", policer_entry->valid);

    if (SX_POLICER_ID_INVALID != policer_entry->sx_policer_id_acl) {
        if (is_clear) {
            if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_counters_clear_set(gh_sdk,
                                                                                    policer_entry->sx_policer_id_acl,
                                                                                    &policer_counters_clear))) {
                SX_LOG_ERR(
                    "Failed to clear policer:0x%" PRIx64 ". counters, acl sx policer:0x%" PRIx64 ", message:%s.\n",
                    policer_id,
                    policer_entry->sx_policer_id_acl,
                    SX_STATUS_MSG(sx_status));
                sai_status = sdk_to_sai(sx_status);
                goto exit;
            }
        } else {
            if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_counters_get(gh_sdk,
                                                                              policer_entry->sx_policer_id_acl,
                                                                              &policer_counters))) {
                SX_LOG_ERR(
                    "Failed to obtain policer:0x%" PRIx64 ". counters, acl sx policer:0x%" PRIx64 ", message:%s.\n",
                    policer_id,
                    policer_entry->sx_policer_id_acl,
                    SX_STATUS_MSG(sx_status));
                sai_status = sdk_to_sai(sx_status);
                goto exit;
            }
            aggregated_counter += policer_counters.violation_counter;
        }
    }

    if (SX_POLICER_ID_INVALID != policer_entry->sx_policer_id_trap) {
        if (is_clear) {
            if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_counters_clear_set(gh_sdk,
                                                                                    policer_entry->sx_policer_id_trap,
                                                                                    &policer_counters_clear))) {
                SX_LOG_ERR(
                    "Failed to clear policer:0x%" PRIx64 ". counters, trap sx policer:0x%" PRIx64 ", message:%s.\n",
                    policer_id,
                    policer_entry->sx_policer_id_trap,
                    SX_STATUS_MSG(sx_status));
                sai_status = sdk_to_sai(sx_status);
                goto exit;
            }
        } else {
            if (SX_STATUS_SUCCESS != (sx_status = sx_api_policer_counters_get(gh_sdk,
                                                                              policer_entry->sx_policer_id_trap,
                                                                              &policer_counters))) {
                SX_LOG_ERR(
                    "Failed to obtain policer:0x%" PRIx64 ". counters, trap sx policer:0x%" PRIx64 ", message:%s.\n",
                    policer_id,
                    policer_entry->sx_policer_id_trap,
                    SX_STATUS_MSG(sx_status));
                sai_status = sdk_to_sai(sx_status);
                goto exit;
            }
            aggregated_counter += policer_counters.violation_counter;
        }
    }

    mlnx_port_foreach(port_config, port_ind) {
        for (packet_type_ind = 0; packet_type_ind < MLNX_PORT_POLICER_TYPE_MAX; packet_type_ind++) {
            if (policer_id == port_config->port_policers[packet_type_ind]) {
                if (is_clear) {
                    if (SX_STATUS_SUCCESS != (sx_status =
                                                  sx_api_port_storm_control_counters_clear_set(gh_sdk,
                                                                                               port_config->logical,
                                                                                               packet_type_ind,
                                                                                               &policer_counters_clear)))
                    {
                        SX_LOG_ERR(
                            "Failed to clear storm counters for policer:0x%" PRIx64 ", storm control id:%d, port_db ind:%d, log_port:%d, message:%s.\n",
                            policer_id,
                            packet_type_ind,
                            port_config->index,
                            port_config->logical,
                            SX_STATUS_MSG(sx_status));
                        sai_status = sdk_to_sai(sx_status);
                        goto exit;
                    }
                } else {
                    if (SX_STATUS_SUCCESS != (sx_status =
                                                  sx_api_port_storm_control_counters_get(gh_sdk,
                                                                                         port_config->logical,
                                                                                         packet_type_ind,
                                                                                         &policer_counters))) {
                        SX_LOG_ERR(
                            "Failed to obtain storm counters for policer:0x%" PRIx64 ", storm control id:%d, port_db ind:%d, log_port:%d, message:%s.\n",
                            policer_id,
                            packet_type_ind,
                            port_config->index,
                            port_config->logical,
                            SX_STATUS_MSG(sx_status));
                        sai_status = sdk_to_sai(sx_status);
                        goto exit;
                    }
                    aggregated_counter += policer_counters.violation_counter;
                }
            }
        }
    }

    if (!is_clear) {
        counters[0] = aggregated_counter;
    }

exit:
    policer_db_cl_plock_release(&g_sai_db_ptr->p_lock);
    SX_LOG_EXIT();
    return sai_status;
}

static sai_status_t mlnx_sai_get_policer_statistics(_In_ sai_object_id_t           policer_id,
                                                    _In_ uint32_t                  number_of_counters,
                                                    _In_ const sai_policer_stat_t *counter_ids,
                                                    _Out_ uint64_t               * counters)
{
    return mlnx_do_policer_stats(policer_id, number_of_counters, counter_ids, counters, false);
}

/**
 * @brief Clear Policer statistics counters.
 *
 * @param[in] policer_id Policer id
 * @param[in] number_of_counters number of counters in the array
 * @param[in] counter_ids specifies the array of counter ids
 *
 * @return SAI_STATUS_SUCCESS on success
 *         Failure status code on error
 */
sai_status_t mlnx_sai_clear_policer_stats(_In_ sai_object_id_t           policer_id,
                                          _In_ uint32_t                  number_of_counters,
                                          _In_ const sai_policer_stat_t *counter_ids)
{
    return mlnx_do_policer_stats(policer_id, number_of_counters, counter_ids, NULL, true);
}

sai_status_t mlnx_policer_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;
    if (gh_sdk) {
        return sdk_to_sai(sx_api_policer_log_verbosity_level_set(gh_sdk, SX_LOG_VERBOSITY_BOTH, level, level));
    } else {
        return SAI_STATUS_SUCCESS;
    }
}

static sai_status_t sai_policer_remove_packets_for_type_from_all_traffic(
    _In_ mlnx_port_policer_type       port_policer_type_to_remove,
    _In_ mlnx_port_config_t          *port_config,
    _Out_opt_ sx_port_packet_types_t *packet_types_out)
{
    SX_LOG_ENTER();

    SX_LOG_DBG("input policer type to remove flags for:%d\n", port_policer_type_to_remove);
    SX_LOG_DBG("Initial state of packets: uc:%d, mc:%d, bc:%d, uuc:%d, umc:%d\n",
               packet_types_out->uc, packet_types_out->mc,
               packet_types_out->bc, packet_types_out->uuc, packet_types_out->umc);

    if (MLNX_PORT_POLICER_TYPE_REGULAR_INDEX == port_policer_type_to_remove) {
        SX_LOG_ERR("all traffic policer is not a valid source entry for removal of storm flags. port_db:%d\n",
                   port_config->index);
        SX_LOG_EXIT();
        return SAI_STATUS_FAILURE;
    }
    if (SAI_NULL_OBJECT_ID ==
        port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX]) {
        SX_LOG_ERR("all traffic policer db entry is NULL, port_db:%d\n", port_config->index);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_NULL_OBJECT_ID != port_config->port_policers[port_policer_type_to_remove]) {
        SX_LOG_ERR("port_db[%d] policer type:%d must be in reset state, but has policer:0x%" PRIx64 "\n",
                   port_config->index, port_policer_type_to_remove,
                   port_config->port_policers[port_policer_type_to_remove]);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    switch (port_policer_type_to_remove) {
    case MLNX_PORT_POLICER_TYPE_FLOOD_INDEX:
        packet_types_out->uc      =
            packet_types_out->umc = false;
        break;

    case MLNX_PORT_POLICER_TYPE_BROADCAST_INDEX:
        packet_types_out->bc = false;
        break;

    case MLNX_PORT_POLICER_TYPE_MULTICAST_INDEX:
        packet_types_out->mc = false;
        break;

    default:
        SX_LOG_ERR("Invalid policer storm type:%d\n", port_policer_type_to_remove);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    SX_LOG_DBG("state of packets policer: uc:%d, mc:%d, bc:%d, uuc:%d, umc:%d\n",
               packet_types_out->uc, packet_types_out->mc,
               packet_types_out->bc, packet_types_out->uuc, packet_types_out->umc);
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_policer_apply_packet_types_to_all_traffic_policer(_In_ mlnx_port_config_t    *port_config,
                                                                          _In_ sx_port_packet_types_t new_packet_types)
{
    sai_status_t                   sai_status;
    sx_status_t                    sx_status;
    sx_port_storm_control_params_t storm_ctrl_params;
    mlnx_policer_db_entry_t       *policer_db_entry = NULL;

    SX_LOG_ENTER();
    memset(&storm_ctrl_params, 0, sizeof(storm_ctrl_params));

    if (SAI_NULL_OBJECT_ID == port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX]) {
        SX_LOG_ERR("all traffic policer db entry is NULL, port_db:%d\n", port_config->index);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (SAI_STATUS_SUCCESS !=
        (sai_status =
             db_get_sai_policer_data(port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX],
                                     &policer_db_entry))) {
        SX_LOG_ERR("Failed to retrieve all traffic policer db entry. sai policer:0x%" PRIx64 ", pord_db:%d\n",
                   port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX], port_config->index);
        SX_LOG_EXIT();
        return sai_status;
    }
    storm_ctrl_params.packet_types   = new_packet_types;
    storm_ctrl_params.policer_params = policer_db_entry->sx_policer_attr;

    /* We are using the oritinal policer settings saved in the DB.
     *  But need to set this flag to false for storm policer API to work. */
    storm_ctrl_params.policer_params.is_host_ifc_policer = false;
    if (SX_STATUS_SUCCESS !=
        (sx_status =
             storm_policer_functions.sx_api_port_storm_control_set_p(
                 gh_sdk,
                 SX_ACCESS_CMD_EDIT,
                 port_config->logical,
                 MLNX_PORT_POLICER_TYPE_REGULAR_INDEX,
                 &storm_ctrl_params))) {
        SX_LOG_ERR(
            "Failed to update all traffic port storm_binding changes. sdk message:%s. saipolicer:0x%" PRIx64 ", db_port:%d, logical:%d\n",
            SX_STATUS_MSG(sx_status),
            port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX],
            port_config->index,
            port_config->logical);
        SX_LOG_EXIT();
        sai_status = sdk_to_sai(sx_status);
        return sai_status;
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t setup_storm_item(_In_ sai_object_id_t        sai_policer,
                                     _In_ mlnx_port_config_t    *port_config,
                                     _In_ mlnx_port_policer_type port_policer_type)
{
    sai_status_t                   sai_status;
    sx_status_t                    sx_status;
    sx_port_storm_control_params_t storm_ctrl_params;
    mlnx_policer_db_entry_t       *policer_entry = NULL;
    sx_port_packet_types_t         all_traffic_packet_types;

    SX_LOG_ENTER();
    memset(&storm_ctrl_params, 0, sizeof(storm_ctrl_params));
    memset(&all_traffic_packet_types, 0, sizeof(all_traffic_packet_types));
    if (port_policer_type >= MLNX_PORT_POLICER_TYPE_MAX) {
        SX_LOG_ERR(" Invalid policer type:%d\n", port_policer_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_entry))) {
        SX_LOG_ERR("Failed to obtain policer db entry. object_id:0x%" PRIx64 "\n", sai_policer);
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_NULL_OBJECT_ID != port_config->port_policers[port_policer_type]) {
        SX_LOG_ERR("port_db[%d] policer type index:%d. Already has a value:0x%" PRIx64 "\n",
                   port_config->index,
                   port_policer_type,
                   port_config->port_policers[port_policer_type]);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (sai_status =
                                   sai_policer_get_packet_flags_for_policer_type(
                                       port_policer_type,
                                       port_config,
                                       &storm_ctrl_params.packet_types))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    if ((SAI_NULL_OBJECT_ID != port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX]) &&
        (MLNX_PORT_POLICER_TYPE_REGULAR_INDEX != port_policer_type)) {
        /*  A new storm control policer (one of - flood, broadcast, multicast) is being setup.
         *   SDK has requirement that all storm policers must handle disjoint set of packet types.
         *   Since 'all traffic' storm policer already exists, we need to remove the flags it may handle
         *   for the newly setup storm policer - to satisfy the 'disjoint set' requirement.
         */
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       sai_policer_get_packet_flags_for_policer_type(
                                           MLNX_PORT_POLICER_TYPE_REGULAR_INDEX,
                                           port_config,
                                           &all_traffic_packet_types))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       sai_policer_remove_packets_for_type_from_all_traffic(
                                           port_policer_type,
                                           port_config,
                                           &all_traffic_packet_types))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 sai_policer_apply_packet_types_to_all_traffic_policer(port_config, all_traffic_packet_types))) {
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    storm_ctrl_params.policer_params = policer_entry->sx_policer_attr;
    /* We are using the oritinal policer settings saved in the DB.
     *  But need to set this flag to false for storm policer API to work.*/
    storm_ctrl_params.policer_params.is_host_ifc_policer = false;
    if (SX_STATUS_SUCCESS !=
        (sx_status = storm_policer_functions.sx_api_port_storm_control_set_p(
             gh_sdk,
             SX_ACCESS_CMD_ADD,
             port_config->logical,
             port_policer_type,
             &storm_ctrl_params))) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR("Failed to bind policer to port. SDK message:%s\n", SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sai_status;
    }
    port_config->port_policers[port_policer_type] = sai_policer;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_bind_policer_to_port(_In_ sai_object_id_t           sai_port,
                                           _In_ sai_object_id_t           sai_policer,
                                           _In_ mlnx_policer_bind_params* bind_params)
{
    sai_status_t        sai_status;
    mlnx_port_config_t *port_config = NULL;

    SX_LOG_ENTER();
    if (NULL == bind_params) {
        SX_LOG_ERR("NULL bind_params\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (bind_params->port_policer_type >= MLNX_PORT_POLICER_TYPE_MAX) {
        SX_LOG_ERR(" Invalid policer type:%d\n", bind_params->port_policer_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status = mlnx_port_by_obj_id(sai_port, &port_config);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_port_fetch_lag_if_lag_member(&port_config);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_NULL_OBJECT_ID != port_config->port_policers[bind_params->port_policer_type]) {
        SX_LOG_ERR(
            "Cannot bind policer:0x%" PRIx64 " for storm type:%d, to port:0x%" PRIx64 ", db:%d, because it already has a binding to another policer:0x%" PRIx64 "\n",
            sai_policer,
            bind_params->port_policer_type,
            port_config->saiport,
            port_config->index,
            port_config->port_policers[bind_params->port_policer_type]);
        return SAI_STATUS_OBJECT_IN_USE;
    }
    sai_status = setup_storm_item(sai_policer, port_config, bind_params->port_policer_type);
    if (SAI_STATUS_SUCCESS != sai_status) {
        SX_LOG_ERR(
            "Failed to bind policer to port. policer:0x%" PRIx64 ", port:0x%" PRIx64 ", policer type:%d. status:%d\n",
            sai_policer,
            sai_port,
            bind_params->port_policer_type,
            sai_status);
    } else {
        SX_LOG_NTC(
            "Created binding to port_db[%d] policer type:%d. sai port:0x%" PRIx64 ".sai policer:0x%" PRIx64 "\n",
            port_config->index,
            bind_params->port_policer_type,
            sai_port,
            sai_policer);
    }
    SX_LOG_EXIT();
    return sai_status;
}

/* SAI DB R/w is required */
sai_status_t mlnx_sai_unbind_policer_from_port(_In_ sai_object_id_t           sai_port,
                                               _In_ mlnx_policer_bind_params* bind_params)
{
    sai_status_t                   sai_status;
    mlnx_port_config_t            *port_config;
    mlnx_policer_db_entry_t       *policer_entry = NULL;
    sai_object_id_t                sai_policer   = SAI_NULL_OBJECT_ID;
    sx_status_t                    sx_status;
    sx_port_storm_control_params_t storm_ctrl_params;
    sx_port_packet_types_t         all_traffic_packet_types;

    SX_LOG_ENTER();
    if (NULL == bind_params) {
        SX_LOG_ERR("NULL bind params\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (bind_params->port_policer_type >= MLNX_PORT_POLICER_TYPE_MAX) {
        SX_LOG_ERR("Invalid policer type:%d\n", bind_params->port_policer_type);
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }
    memset(&storm_ctrl_params, 0, sizeof(storm_ctrl_params));
    memset(&all_traffic_packet_types, 0, sizeof(all_traffic_packet_types));

    sai_status = mlnx_port_by_obj_id(sai_port, &port_config);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    sai_status = mlnx_port_fetch_lag_if_lag_member(&port_config);
    if (SAI_ERR(sai_status)) {
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_NTC("sai port at port_db[%d]==:0x%" PRIx64 ". policer type:%d\n", port_config->index,
               sai_port, bind_params->port_policer_type);

    if (SAI_NULL_OBJECT_ID == port_config->port_policers[bind_params->port_policer_type]) {
        /* no sai policer to unbind */
        SX_LOG_WRN("sai port at port_db[%d]==:0x%" PRIx64 " has no policer binding for policer type:%d\n",
                   port_config->index,
                   port_config->saiport,
                   bind_params->port_policer_type);
        SX_LOG_EXIT();
        return SAI_STATUS_SUCCESS;
    }
    sai_policer = port_config->port_policers[bind_params->port_policer_type];
    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_entry))) {
        SX_LOG_ERR("Failed to obtain policer db entry. object_id:0x%" PRIx64 "\n", sai_policer);
        SX_LOG_EXIT();
        return sai_status;
    }
    if (SAI_STATUS_SUCCESS != (sai_status =
                                   sai_policer_get_packet_flags_for_policer_type(
                                       bind_params->port_policer_type,
                                       port_config,
                                       &storm_ctrl_params.packet_types))) {
        SX_LOG_EXIT();
        return sai_status;
    }
    storm_ctrl_params.policer_params = policer_entry->sx_policer_attr;

    /* We are using the original policer settings saved in the DB.
     *  But need to set this flag to false for storm policer API to work.*/
    storm_ctrl_params.policer_params.is_host_ifc_policer = false;
    if (SX_STATUS_SUCCESS !=
        (sx_status =
             storm_policer_functions.sx_api_port_storm_control_set_p(gh_sdk, SX_ACCESS_CMD_DELETE,
                                                                     port_config->logical,
                                                                     bind_params->port_policer_type,
                                                                     &storm_ctrl_params))) {
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_ERR(
            "Failed to unbind policer from port. policer:0x%" PRIx64 ", port:0x%" PRIx64 ", policer type:%d. SDK message:%s\n",
            sai_policer,
            sai_port,
            bind_params->port_policer_type,
            SX_STATUS_MSG(sx_status));
        SX_LOG_EXIT();
        return sai_status;
    }
    port_config->port_policers[bind_params->port_policer_type] = SAI_NULL_OBJECT_ID;

    /* Need to redistribute storm flags only when non-regular storm item is being removed. */
    if ((SAI_NULL_OBJECT_ID !=
         port_config->port_policers[MLNX_PORT_POLICER_TYPE_REGULAR_INDEX]) &&
        (MLNX_PORT_POLICER_TYPE_REGULAR_INDEX != bind_params->port_policer_type)) {
        if (SAI_STATUS_SUCCESS != (sai_status =
                                       sai_policer_get_packet_flags_for_policer_type(
                                           MLNX_PORT_POLICER_TYPE_REGULAR_INDEX,
                                           port_config,
                                           &all_traffic_packet_types))) {
            SX_LOG_EXIT();
            return sai_status;
        }
        if (SAI_STATUS_SUCCESS !=
            (sai_status =
                 sai_policer_apply_packet_types_to_all_traffic_policer(port_config, all_traffic_packet_types))) {
            SX_LOG_EXIT();
            return sai_status;
        }
    }
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_get_or_create_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                               _Out_ sx_policer_id_t* sx_policer,
                                                               _In_ bool              is_host_if_policer)
{
    sai_status_t             sai_status;
    sx_status_t              sx_status;
    mlnx_policer_db_entry_t *policer_data   = NULL;
    sx_policer_id_t         *new_sx_policer = NULL;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_data))) {
        SX_LOG_ERR("Failed to obtain sx_policer_id. sai policer object_id:0x%" PRIx64 "\n", sai_policer);
        SX_LOG_EXIT();
        return sai_status;
    }
    SX_LOG_DBG("is_host_if_policer:%d\n", is_host_if_policer);
    log_sx_policer_attributes(policer_data->sx_policer_id_trap, &(policer_data->sx_policer_attr));
    if (is_host_if_policer) {
        new_sx_policer                                    = &policer_data->sx_policer_id_trap;
        policer_data->sx_policer_attr.is_host_ifc_policer = true;
    } else {
        new_sx_policer                                    = &policer_data->sx_policer_id_acl;
        policer_data->sx_policer_attr.is_host_ifc_policer = false;
    }

    if (SX_POLICER_ID_INVALID == *new_sx_policer) {
        if (SX_STATUS_SUCCESS !=
            (sx_status = sx_api_policer_set(gh_sdk,
                                            SX_ACCESS_CMD_CREATE,
                                            &(policer_data->sx_policer_attr),
                                            new_sx_policer))) {
            SX_LOG_ERR("Failed to create policer, is_host_if_policer:%d error message:%s.\n",
                       is_host_if_policer,
                       SX_STATUS_MSG(sx_status));
            SX_LOG_EXIT();
            return sdk_to_sai(sx_status);
        }
        SX_LOG_NTC(
            "Created sx policer :0x%" PRIx64 " is_host_if_policer:%d, under sai_policer:0x%" PRIx64 ". reason - for binding\n",
            *new_sx_policer,
            is_host_if_policer,
            sai_policer);
    } else {
        SX_LOG_NTC(
            "Already exists - sx policer :0x%" PRIx64 " is_host_if_policer:%d, under sai_policer:0x%" PRIx64 "\n",
            *new_sx_policer,
            is_host_if_policer,
            sai_policer);
    }

    *sx_policer = *new_sx_policer;
    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_sai_get_or_create_regular_sx_policer_for_bind(_In_ sai_object_id_t   sai_policer,
                                                                _In_ bool              is_host_if_policer,
                                                                _Out_ sx_policer_id_t* sx_policer_id)
{
    sai_status_t             sai_status;
    sx_policer_id_t          sx_policer = 0;
    mlnx_policer_db_entry_t* policer_data;

    SX_LOG_ENTER();

    if (NULL == sx_policer_id) {
        SX_LOG_ERR("NULL sx_policer_id passed in\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (sai_status = db_get_sai_policer_data(sai_policer, &policer_data))) {
        SX_LOG_ERR("Failed to obtain sx_policer_id. sai policer object_id:0x%" PRIx64 "\n", sai_policer);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_get_or_create_sx_policer_for_bind(sai_policer, &sx_policer, is_host_if_policer))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    *sx_policer_id = sx_policer;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_sai_bind_policer_to_trap_group(_In_ sai_object_id_t sai_object_id,
                                                        _In_ sai_object_id_t sai_policer)
{
    sai_status_t    sai_status;
    sx_status_t     sx_status;
    sx_policer_id_t sx_policer;
    uint32_t        group_id;

    SX_LOG_ENTER();
    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_object_to_type(sai_object_id, SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, &group_id, NULL))) {
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SAI_STATUS_SUCCESS !=
        (sai_status = mlnx_sai_get_or_create_regular_sx_policer_for_bind(sai_policer, true, &sx_policer))) {
        SX_LOG_ERR("Failed to obtain sx_policer_id. sai policer object_id:0x%" PRIx64 "\n", sai_policer);
        SX_LOG_EXIT();
        return sai_status;
    }

    if (SX_STATUS_SUCCESS != (
            sx_status = sx_api_host_ifc_policer_bind_set(
                gh_sdk,
                SX_ACCESS_CMD_BIND,
                DEFAULT_ETH_SWID,
                group_id,
                sx_policer))) {
        SX_LOG_ERR("Policer bind failed - %s. line:%d\n", SX_STATUS_MSG(sx_status), __LINE__);
        sai_status = sdk_to_sai(sx_status);
        SX_LOG_EXIT();
        return sai_status;
    }

    SX_LOG_NTC(
        "Sai trap_group_id:0x%" PRIx64 ". sai policer object_id:0x%" PRIx64 ". sx_policer_id:0x%" PRIx64 ". group prio:%u\n",
        sai_object_id,
        sai_policer,
        sx_policer,
        group_id);


    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* NOTE: bind/unbind mechanism for ACLs is different, due to specifics of the ACL model.
 *   Policer is attached to ACL by setting SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER property on an acl entry.
 * SAI DB should be locked
 */
sai_status_t mlnx_sai_bind_policer(_In_ sai_object_id_t           sai_object_id,
                                   _In_ sai_object_id_t           sai_policer,
                                   _In_ mlnx_policer_bind_params* bind_params)
{
    sai_status_t      status;
    sai_object_type_t object_type = sai_object_type_query(sai_policer);

    SX_LOG_ENTER();

    if (SAI_NULL_OBJECT_ID == sai_policer) {
        SX_LOG_ERR("SAI_NULL_OBJECT_ID policer cannot be passed to this function.\n");
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_OBJECT_TYPE_POLICER != object_type) {
        SX_LOG_ERR("Unexpected obect type:%s, expected policer.\n", SAI_TYPE_STR(object_type));
        SX_LOG_EXIT();
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS != (status = mlnx_sai_unbind_policer(sai_object_id, bind_params))) {
        SX_LOG_EXIT();
        return status;
    }

    object_type = sai_object_type_query(sai_object_id);

    switch (object_type) {
    case SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:
        status = mlnx_sai_bind_policer_to_trap_group(sai_object_id, sai_policer);
        break;

    case SAI_OBJECT_TYPE_PORT:
        status = mlnx_sai_bind_policer_to_port(sai_object_id, sai_policer, bind_params);
        break;

    default:
        status = SAI_STATUS_NOT_SUPPORTED;
    }

    SX_LOG_EXIT();
    return status;
}

/* NOTE: unbind mechanism is different for ACLs, due to ACL model specifics.
 *   Policer is detached from ACL when delete_acl_entry is called to delete the acl entry to which
 *   policer was attached via SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER property.
 *   SAI DB should be locked
 */
sai_status_t mlnx_sai_unbind_policer(_In_ sai_object_id_t sai_object, _In_ mlnx_policer_bind_params* bind_params)
{
    sai_status_t      status;
    sai_object_type_t object_type = sai_object_type_query(sai_object);

    SX_LOG_ENTER();

    switch (object_type) {
    case SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:
        status = mlnx_sai_unbind_policer_from_trap_group(sai_object);
        break;

    case SAI_OBJECT_TYPE_PORT:
        status = mlnx_sai_unbind_policer_from_port(sai_object, bind_params);
        break;

    default:
        status = SAI_STATUS_NOT_SUPPORTED;
    }

    SX_LOG_EXIT();
    return status;
}

const sai_policer_api_t mlnx_policer_api = {
    mlnx_sai_create_policer,
    mlnx_sai_remove_policer,
    mlnx_sai_set_policer_attribute,
    mlnx_sai_get_policer_attribute,
    mlnx_sai_get_policer_statistics,
    mlnx_sai_clear_policer_stats,
};
