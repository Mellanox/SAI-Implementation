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

#if !defined (__MLNXSAI_H_)
#define __MLNXSAI_H_

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_api_cos.h>
#include <sx/sdk/sx_api_lag.h>
#include <sx/sdk/sx_api_mstp.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_fdb.h>
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_host_ifc.h>
#include <sx/sdk/sx_lib_host_ifc.h>
#include <sx/sdk/sx_api_policer.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_span.h>

extern sx_api_handle_t gh_sdk;
extern service_method_table_t g_services;

sai_status_t sdk_to_sai(sx_status_t status);
extern const sai_route_api_t route_api;
extern const sai_vr_api_t router_api;
extern const sai_switch_api_t switch_api;
extern const sai_port_api_t port_api;
extern const sai_fdb_api_t fdb_api;
extern const sai_neighbor_api_t neighbor_api;
extern const sai_next_hop_api_t next_hop_api;
extern const sai_router_interface_api_t router_interface_api;
extern const sai_vlan_api_t vlan_api;

#define DEFAULT_ETH_SWID 0
#define SWITCH_PORT_NUM 36
#define SWITCH_MAX_VR 1
#define PORT_SPEED_56 56000
#define PORT_SPEED_40 40000
#define PORT_SPEED_20 20000
#define PORT_SPEED_10 10000
#define PORT_SPEED_1  1000

#ifndef _WIN32
#define UNREFERENCED_PARAMETER(X)
#endif

#endif // __MLNXSAI_H_
