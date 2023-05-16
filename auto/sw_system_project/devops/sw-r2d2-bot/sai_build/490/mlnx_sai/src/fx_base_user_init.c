/*
Copyright 2018 Mellanox.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
*
* Omer Shabtai (omers@mellanox.com)
* 
* Use this file for adding any needed objects to the actions in your P4 program.
* for example forwarding objects, mirror analyzers, traps, etc...
* by directly calling SDK's sx_api calls.
*
* TODO - use Onyx to define all needed objects.
*
*/

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* flextrum */
#include <fx_base_api.h>
#include <flextrum_types.h> // For platform specific defines


/* Mellanox SDK */
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_bridge.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_fdb.h>
#include <sx/sdk/sx_api_flex_acl.h>
#include <sx/sdk/sx_api_flow_counter.h>
#include <sx/sdk/sx_api_host_ifc.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_tunnel.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_lib_flex_acl.h>
#include <sx/sdk/sx_lib_host_ifc.h>
#include <sx/sdk/sx_port.h>
#include <sx/sdk/sx_port_id.h>
#include <sx/sdk/sx_trap_id.h>

#include <arpa/inet.h>
#include <syslog.h>

#include <complib/sx_log.h>

#undef __MODULE__
#define __MODULE__ FXAPI_USER
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define FX_LOG(L, FMT, ...)                                                         \
    do {                                                                            \
        SX_LOG(L, "[%s] %s:%i: " FMT, __FILE__, __func__,__LINE__, ## __VA_ARGS__); \
    } while (0)

sx_status_t fx_extern_init(fx_handle_t handle) {

	FX_LOG(SX_LOG_INFO, "User init start\n");
	/* user code goes here */


	FX_LOG(SX_LOG_INFO, "User init end\n");
    return SX_STATUS_SUCCESS;
}

sx_status_t fx_extern_deinit(fx_handle_t handle) {
	FX_LOG(SX_LOG_INFO, "User deinit start\n");
	/* user code goes here */


	FX_LOG(SX_LOG_INFO, "User deinit end\n");
    return SX_STATUS_SUCCESS;
}
