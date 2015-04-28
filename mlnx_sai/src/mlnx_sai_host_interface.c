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
#ifndef _WIN32
#include <net/if.h>
#endif

#undef  __MODULE__
#define __MODULE__ SAI_HOST_INTERFACE

static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_NOTICE;
static const sai_attribute_entry_t host_interface_attribs[] = {
    { SAI_HOST_INTERFACE_ATTR_TYPE, true, true, false,
      "Host interface type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_HOST_INTERFACE_ATTR_PORT_ID, false, true, false,
      "Host interface associated port", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_HOST_INTERFACE_ATTR_RIF_ID, false, true, false,
      "Host interface associated router interface", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_HOST_INTERFACE_ATTR_NAME, true, true, true,
      "Host interface name", SAI_ATTR_VAL_TYPE_CHARDATA },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

sai_status_t mlnx_host_interface_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_host_interface_port_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_host_interface_rif_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg);
sai_status_t mlnx_host_interface_name_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg);
sai_status_t mlnx_host_interface_name_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg);

static const sai_vendor_attribute_entry_t host_interface_vendor_attribs[] = {
    { SAI_HOST_INTERFACE_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_type_get, NULL,
      NULL, NULL },
    { SAI_HOST_INTERFACE_ATTR_PORT_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_port_get, NULL,
      NULL, NULL },
    { SAI_HOST_INTERFACE_ATTR_RIF_ID,
      { true, false, false, true },
      { true, false, false, true },
      mlnx_host_interface_rif_get, NULL,
      NULL, NULL },
    { SAI_HOST_INTERFACE_ATTR_NAME,
      { true, false, true, true },
      { true, false, true, true },
      mlnx_host_interface_name_get, NULL,
      mlnx_host_interface_name_set, NULL },
};
static void host_interface_key_to_str(_In_ const sai_host_interface_id_t hif_id, _Out_ char *key_str)
{
    snprintf(key_str, MAX_KEY_STR_LEN, "host interface %u", hif_id);
}

/*
 * Routine Description:
 *    Create host interface.
 *
 * Arguments:
 *    [out] hif_id - host interface id
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_create_host_interface(_Out_ sai_host_interface_id_t* hif_id,
                                        _In_ uint32_t                  attr_count,
                                        _In_ sai_attribute_t          *attr_list)
{
    sai_status_t                 status;
    const sai_attribute_value_t *type, *rif, *port, *name;
    uint32_t                     type_index, rif_index, port_index, name_index;
    char                         key_str[MAX_KEY_STR_LEN];
    char                         list_str[MAX_LIST_VALUE_STR_LEN];
    char                         command[100];
    sx_router_interface_param_t  intf_params;
    sx_interface_attributes_t    intf_attribs;
    sx_router_id_t               vrid;
    int                          system_err;

    SX_LOG_ENTER();

    if (NULL == hif_id) {
        SX_LOG_ERR("NULL host interface ID param\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_STATUS_SUCCESS !=
        (status =
             check_attribs_metadata(attr_count, attr_list, host_interface_attribs, host_interface_vendor_attribs,
                                    SAI_OPERATION_CREATE))) {
        SX_LOG_ERR("Failed attribs check\n");
        return status;
    }

    sai_attr_list_to_str(attr_count, attr_list, host_interface_attribs, MAX_LIST_VALUE_STR_LEN, list_str);
    SX_LOG_NTC("Create host interface, %s\n", list_str);

    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_TYPE, &type, &type_index));
    assert(SAI_STATUS_SUCCESS ==
           find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_NAME, &name, &name_index));

    if (SAI_HOST_INTERFACE_TYPE_RIF == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_RIF_ID, &rif, &rif_index))) {
            SX_LOG_ERR("Missing mandatory attribute rif id on create\n");
            return SAI_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_PORT_ID, &port, &port_index))) {
            SX_LOG_ERR("Invalid attribute port id for host interface rif on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + port_index;
        }
    } else if (SAI_HOST_INTERFACE_TYPE_PORT == type->s32) {
        if (SAI_STATUS_SUCCESS !=
            (status =
                 find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_PORT_ID, &port, &port_index))) {
            SX_LOG_ERR("Missing mandatory attribute port id on create\n");
            return SAI_MANDATORY_ATTRIBUTE_MISSING;
        }
        if (SAI_STATUS_ITEM_NOT_FOUND !=
            (status = find_attrib_in_list(attr_count, attr_list, SAI_HOST_INTERFACE_ATTR_RIF_ID, &rif, &rif_index))) {
            SX_LOG_ERR("Invalid attribute rif id for host interface port on create\n");
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + rif_index;
        }

        /* TODO : implement */
        SX_LOG_ERR("Host interface type port not implemented\n");
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + type_index;
    } else {
        SX_LOG_ERR("Invalid host interface type %d\n", type->s32);
        return SAI_STATUS_INVALID_ATTR_VALUE_0 + type_index;
    }


    if (SX_STATUS_SUCCESS !=
        (status = sx_api_router_interface_get(gh_sdk, rif->u32, &vrid, &intf_params, &intf_attribs))) {
        SX_LOG_ERR("Failed to get router interface - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    if (SX_L2_INTERFACE_TYPE_VLAN != intf_params.type) {
        SX_LOG_ERR("RIF type %s not implemented\n", SX_ROUTER_RIF_TYPE_STR(intf_params.type));
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + rif_index;
    }

    snprintf(command, sizeof(command), "ip link add link swid%d_eth name %s type vlan id %u",
             intf_params.ifc.vlan.swid, name->chardata, intf_params.ifc.vlan.vlan);
    system_err = system(command);
    if (0 != system_err) {
        SX_LOG_ERR("Command \"%s\" failed\n", command);
        return SAI_STATUS_FAILURE;
    }

    *hif_id = if_nametoindex(name->chardata);
    if (*hif_id == 0) {
        SX_LOG_ERR("Cannot find device \"%s\"\n", name->chardata);
        return SAI_STATUS_FAILURE;
    }

    host_interface_key_to_str(*hif_id, key_str);
    SX_LOG_NTC("Created host interface %s\n", key_str);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Remove host interface
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_remove_host_interface(_In_ sai_host_interface_id_t hif_id)
{
    char key_str[MAX_KEY_STR_LEN];
    char ifname[IF_NAMESIZE];
    int  system_err;
    char command[100];

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    SX_LOG_NTC("Remove host interface %s\n", key_str);

    if (NULL == if_indextoname(hif_id, ifname)) {
        SX_LOG_ERR("Cannot find ifindex %u\n", hif_id);
        return SAI_STATUS_FAILURE;
    }

    snprintf(command, sizeof(command), "ip link delete %s", ifname);
    system_err = system(command);
    if (0 != system_err) {
        SX_LOG_ERR("Command \"%s\" failed\n", command);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/*
 * Routine Description:
 *    Set host interface attribute
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_set_host_interface_attribute(_In_ sai_host_interface_id_t hif_id, _In_ const sai_attribute_t *attr)
{
    const sai_object_key_t key = { .host_interface_id = hif_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    return sai_set_attribute(&key, key_str, host_interface_attribs, host_interface_vendor_attribs, attr);
}

/*
 * Routine Description:
 *    Get host interface attribute
 *
 * Arguments:
 *    [in] hif_id - host interface id
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t mlnx_get_host_interface_attribute(_In_ sai_host_interface_id_t hif_id,
                                               _In_ uint32_t                attr_count,
                                               _Inout_ sai_attribute_t     *attr_list)
{
    const sai_object_key_t key = { .host_interface_id = hif_id };
    char                   key_str[MAX_KEY_STR_LEN];

    SX_LOG_ENTER();

    host_interface_key_to_str(hif_id, key_str);
    return sai_get_attributes(&key,
                              key_str,
                              host_interface_attribs,
                              host_interface_vendor_attribs,
                              attr_count,
                              attr_list);
}

/* Type [sai_host_interface_type_t] */
sai_status_t mlnx_host_interface_type_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    SX_LOG_ENTER();

    /* TODO : implement all types */
    value->s32 = SAI_HOST_INTERFACE_TYPE_RIF;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Assosiated Port [sai_port_id_t] */
sai_status_t mlnx_host_interface_port_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* Assosiated Router interface [sai_router_interface_id_t] */
sai_status_t mlnx_host_interface_rif_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/* Name [char[HOST_INTERFACE_NAME_SIZE]] (MANDATORY_ON_CREATE)
 * The maximum number of charactars for the name is HOST_INTERFACE_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
sai_status_t mlnx_host_interface_name_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    char                          ifname[IF_NAMESIZE];
    const sai_host_interface_id_t hif_id = key->host_interface_id;

    SX_LOG_ENTER();

    if (NULL == if_indextoname(hif_id, ifname)) {
        SX_LOG_ERR("Cannot find ifindex %u\n", hif_id);
        return SAI_STATUS_FAILURE;
    }

    strncpy(value->chardata, ifname, HOST_INTERFACE_NAME_SIZE);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Name [char[HOST_INTERFACE_NAME_SIZE]]
 * The maximum number of charactars for the name is HOST_INTERFACE_NAME_SIZE - 1 since
 * it needs the terminating null byte ('\0') at the end.  */
sai_status_t mlnx_host_interface_name_set(_In_ const sai_object_key_t      *key,
                                          _In_ const sai_attribute_value_t *value,
                                          void                             *arg)
{
    char                          ifname[IF_NAMESIZE];
    int                           system_err;
    char                          command[100];
    const sai_host_interface_id_t hif_id = key->host_interface_id;

    SX_LOG_ENTER();

    if (NULL == if_indextoname(hif_id, ifname)) {
        SX_LOG_ERR("Cannot find ifindex %u\n", hif_id);
        return SAI_STATUS_FAILURE;
    }

    snprintf(command, sizeof(command), "ip link set dev %s name %s", ifname, value->chardata);
    system_err = system(command);
    if (0 != system_err) {
        SX_LOG_ERR("Command \"%s\" failed.\n", command);
        return SAI_STATUS_FAILURE;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

const sai_host_interface_api_t host_interface_api = {
    mlnx_create_host_interface,
    mlnx_remove_host_interface,
    mlnx_set_host_interface_attribute,
    mlnx_get_host_interface_attribute,
};
