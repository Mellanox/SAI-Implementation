/*
Copyright 2019 Mellanox.

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


#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* flextrum */
#include "fx_base_action.h"
#include "fx_base_api.h"

/* Mellanox SDK */
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_span.h>



#include <complib/sx_log.h>

/* -----------------------------------------------------------------*/
/* Logging */
#undef __MODULE__
#define __MODULE__ FXAPI_ACTION_INIT
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define FX_LOG(L, FMT, ...)                                                         \
    do {                                                                            \
        SX_LOG(L, "[%s] %s:%i: " FMT, __FILE__, __func__,__LINE__, ## __VA_ARGS__); \
    } while (0)


/*======================INIT===========================*/
sx_status_t fx_action_span_init(fx_handle_t handle)
{
    sx_status_t rc;
    sx_api_handle_t sdk_handle; // = handle->sdk_handle;
    rc = fx_sdk_handle_get(handle, &sdk_handle);
    if(rc) {
        FX_LOG(SX_LOG_ERROR, "FX base is not initialized: [%s]\n",SX_STATUS_MSG(rc));
        return rc;
    }

    /* SPAN init */
    sx_span_init_params_t span_init_params = {
      .version = SX_SPAN_MIRROR_HEADER_VERSION_1
    };

    rc = sx_api_span_init_set(sdk_handle, &span_init_params);
    if (SX_STATUS_ALREADY_INITIALIZED == rc) {
        // it's ok, system may have already initialized
        FX_LOG(SX_LOG_WARNING, "Could not initialize span: [%s]\n",SX_STATUS_MSG(rc));
        rc = SX_STATUS_SUCCESS;
    }
    else if (rc) {
        FX_LOG(SX_LOG_ERROR, "Could not initialize span: [%s]\n",SX_STATUS_MSG(rc));
    }
    else {
        FX_LOG(SX_LOG_INFO, "Initialized span module\n");
    }
    return rc;
}

sx_status_t fx_action_span_deinit(fx_handle_t handle) {
    sx_api_handle_t sdk_handle;
    sx_status_t rc = fx_sdk_handle_get(handle, &sdk_handle);
    if(rc) {
        FX_LOG(SX_LOG_ERROR, "FX base is not initialized: [%s]\n",SX_STATUS_MSG(rc));
        return rc;
    }

    rc = fx_action_span_sessions_delete(handle);
    if (rc) {
        FX_LOG(SX_LOG_ERROR, "Could not delete all span sessions: [%s]\n",SX_STATUS_MSG(rc));
    }
    else {
        FX_LOG(SX_LOG_INFO, "Deleted all span sessions\n");
    }

    rc = sx_api_span_deinit_set(sdk_handle);
    if (rc) {
        // NOS may have span already initialized
        FX_LOG(SX_LOG_WARNING, "Could not de-initialize span: [%s]\n",SX_STATUS_MSG(rc));
        rc = SX_STATUS_SUCCESS;
    }
    else {
        FX_LOG(SX_LOG_INFO, "De-initialized span module\n");
    }
    return rc;
}

/* -----------------------SPAN END------------------------------ */

