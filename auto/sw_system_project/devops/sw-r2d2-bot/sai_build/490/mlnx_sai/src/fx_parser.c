// START fx_parser.c: 
/*
 * fx_base_parser_stubs.c
 *
 * Empty implementations for platforms that do not support the
 * extended parser APIs
 *
 *  Created on: Dec 1, 2019
 *      Author: alanlo@mellanox.com
 */

#include <sx/sdk/sx_status.h>
#include <fx_base_parser.h>

// ----- flex parser stub init -----

sx_status_t fx_device_init(fx_handle_t handle, char* pci_dev)
{
    (void)handle;
    (void)pci_dev;
    return SX_STATUS_SUCCESS;
}

sx_status_t fx_device_deinit(fx_handle_t handle)
{
    (void)handle;
    return SX_STATUS_SUCCESS;
}

sx_status_t fx_parser_init(fx_handle_t handle)
{
    (void)handle;
    return SX_STATUS_SUCCESS;
}

sx_status_t fx_parser_deinit(fx_handle_t handle)
{
    (void)handle;
    return SX_STATUS_SUCCESS;
}

sx_status_t fx_span_header_type_set(fx_span_header_type_t type, sx_span_session_id_t session)
{
    (void)type;
    (void)session;
    return SX_STATUS_SUCCESS;
}

// ----- flex parser stub deinit -----





// DONE fx_parser.c: 
