/*
 * Copyright (C) Mellanox Technologies, Ltd. 2001-2014 ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies, Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */
#include "mlnx_sai.h"
#include "mlnx_sai_prm_api.h"

#undef  __MODULE__
#define __MODULE__ SAI_PRM_API

#define MLNX_SAI_PRM_API_C_


/************************************************
 *  Global variables
 ***********************************************/


/************************************************
 *  Local variables
 ***********************************************/
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

/************************************************
 *  Local function declarations
 ***********************************************/

/************************************************
 *  Function implementations
 ***********************************************/

sai_status_t mlnx_prm_api_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_set_get_pllp_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pllp_reg      *pllp_reg)
{
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!pllp_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PLLP: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pllp_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_pllp(pllp_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PLLP: local_port=%u swid=%u ib_port=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pllp_reg->local_port, swid_id, pllp_reg->label_port);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PLLP device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_spzr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_spzr_reg      *spzr_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    uint8_t        try = 0;
    sxd_reg_meta_t reg_meta;

    if (!spzr_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    for (try = 0; try < FW_MAX_QUERY_RETRIES; try++) {
        memset(&reg_meta, 0, sizeof(reg_meta));
        reg_meta.access_cmd = cmd;
        reg_meta.dev_id = dev_id;
        reg_meta.swid = swid_id;

        sxd_ret = sxd_access_reg_spzr(spzr_reg, &reg_meta, 1, handler, context);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            /* Sleep before next retry, let bus recovery */
            usleep(FW_QUERY_DELAY * (try + 1));
        } else {
            break;
        }
    }
    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed interacting with SPZR register command: "
                         "[%s] for device id: [%d] swid id: [%d] "
                         "error: [%d: %s]",
                         SXD_ACCESS_CMD_STR(cmd), dev_id, swid_id,
                         sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pmlp_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pmlp_reg      *pmlp_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    uint8_t        try = 0;
    uint8_t        lcl_port;
    sxd_reg_meta_t reg_meta;

    if (!pmlp_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    lcl_port = pmlp_reg->local_port;

    for (try = 0; try < FW_MAX_QUERY_RETRIES; try++) {
        memset(&reg_meta, 0, sizeof(reg_meta));
        reg_meta.access_cmd = cmd;
        reg_meta.dev_id = dev_id;
        reg_meta.swid = swid_id;

        MLNX_SAI_LOG_DBG("%s: cmd %s PMLP: local_port=%u swid=%u",
                         __func__, SXD_ACCESS_CMD_STR(cmd), lcl_port, swid_id);

        sxd_ret = sxd_access_reg_pmlp(pmlp_reg, &reg_meta, 1, handler, context);
        if (SXD_CHECK_FAIL(sxd_ret)) {
            /* Sleep before next retry, let bus recovery */
            usleep(FW_QUERY_DELAY * (try + 1));

            memset(pmlp_reg, 0, sizeof(*pmlp_reg));
            pmlp_reg->local_port = lcl_port;
        } else {
            break;
        }
    }

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed interacting with PMLP register command: "
                         "[%s] for device id: [%d] swid id: [%d] local port: [%d] "
                         "error: [%d: %s]",
                         SXD_ACCESS_CMD_STR(cmd), dev_id, swid_id, lcl_port,
                         sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pspa_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        uint8_t                  dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pspa_reg      *pspa_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!pspa_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;


    MLNX_SAI_LOG_DBG("%s: Before %s PSPA: local_port=%u sub_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd),
                     pspa_reg->local_port, pspa_reg->sub_port,  pspa_reg->swid);

    sxd_ret = sxd_access_reg_pspa(pspa_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PSPA: local_port=%u sub_port=%u swid=%u rc=%d %s",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pspa_reg->local_port,
                     pspa_reg->sub_port,  pspa_reg->swid, sxd_ret, SXD_STATUS_MSG(sxd_ret));

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed interacting with PSPA register command: "
                         "[%s] for device id: [%d] swid id:[%d] "
                         "register params: local_port:[%u],sub_port;[%u],swid:[%u], error:[%d: %s]",
                         SXD_ACCESS_CMD_STR(cmd), dev_id, swid_id,
                         pspa_reg->local_port, pspa_reg->sub_port,  pspa_reg->swid,
                         sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}


sai_status_t mlnx_set_get_paos_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_paos_reg      *paos_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!paos_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;
    paos_reg->swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PAOS: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), paos_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_paos(paos_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PAOS: local_port=%u swid=%u err=%d %s", __func__,
                     SXD_ACCESS_CMD_STR(cmd), paos_reg->local_port, swid_id, sxd_ret,
                     SXD_STATUS_MSG(sxd_ret));

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PAOS device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pplm_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pplm_reg      *pplm_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!pplm_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PPLM: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pplm_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_pplm(pplm_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PPLM: local_port=%u swid=%u err=%d %s",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pplm_reg->local_port,
                     swid_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PPLM device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pmtu_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pmtu_reg      *pmtu_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!pmtu_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PMTU: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pmtu_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_pmtu(pmtu_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PMTU: local_port=%u swid=%u err=%d %s",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pmtu_reg->local_port, swid_id,
                     sxd_ret, SXD_STATUS_MSG(sxd_ret));

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PMTU device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }

out:
    return status;
}

sai_status_t mlnx_set_get_ptys_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_ptys_reg      *ptys_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!ptys_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));
    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PTYS: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), ptys_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_ptys(ptys_reg, &reg_meta, 1, handler, context);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("Failed interacting with PTYS register command: "
                         "[%s] for device id: [%d] swid id: [%d] error: [%d: %s]",
                         SXD_ACCESS_CMD_STR(cmd), dev_id, swid_id, sxd_ret,
                         SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    MLNX_SAI_LOG_DBG("%s: After %s PTYS: local_port=%u swid=%u err=%d %s",
                     __func__, SXD_ACCESS_CMD_STR(cmd), ptys_reg->local_port,
                     swid_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));

out:
    return status;
}

sai_status_t mlnx_set_get_pvlc_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pvlc_reg      *pvlc_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret;
    sxd_reg_meta_t reg_meta;

    if (!pvlc_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PVLC: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pvlc_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_pvlc(pvlc_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PVLC: local_port=%u swid=%u err=%d %s",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pvlc_reg->local_port, swid_id,
                     sxd_ret, SXD_STATUS_MSG(sxd_ret));

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PVLC device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }

out:
    return status;
}

sai_status_t mlnx_set_get_plib_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_plib_reg      *plib_reg)
{
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!plib_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PLIB: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), plib_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_plib(plib_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PLIB: local_port=%u swid=%u ib_port=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), plib_reg->local_port, swid_id, plib_reg->ib_port);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PLIB device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_plibdb_register(sxd_access_cmd_t         cmd,
                                          uint8_t                  swid_id,
                                          sxd_dev_id_t             dev_id,
                                          sxd_completion_handler_t handler,
                                          void                    *context,
                                          struct ku_plibdb_reg    *plibdb_reg)
{
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!plibdb_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PLIBDB: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), plibdb_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_plibdb(plibdb_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PLIBDB: local_port=%u swid=%u ib_port_1x=%u ib_port_2x=%u ib_port_4x=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), plibdb_reg->local_port, swid_id,
                     plibdb_reg->ib_port_1x,
                     plibdb_reg->ib_port_2x,
                     plibdb_reg->ib_port_4x);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PLIBDB device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_hpkt_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_hpkt_reg      *hpkt_reg)
{
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!hpkt_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    sxd_ret = sxd_access_reg_hpkt(hpkt_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s HPKT: action=%u trap_group=%u trap_id=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), hpkt_reg->action, hpkt_reg->trap_group, hpkt_reg->trap_id);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in HPKT device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_ppbmc_register(sxd_access_cmd_t         cmd,
                                         uint8_t                  swid_id,
                                         sxd_dev_id_t             dev_id,
                                         sxd_completion_handler_t handler,
                                         void                    *context,
                                         struct ku_ppbmc_reg     *ppbmc_reg)
{
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!ppbmc_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PPBMC: local_port=%u swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), ppbmc_reg->local_port, swid_id);

    sxd_ret = sxd_access_reg_ppbmc(ppbmc_reg, &reg_meta, 1, handler, context);

    MLNX_SAI_LOG_DBG("%s: After %s PPBMC: local_port=%u swid=%u monitor_state=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), ppbmc_reg->local_port, swid_id, ppbmc_reg->monitor_state);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PPBMC device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pddr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pddr_reg      *pddr_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!pddr_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PDDR: local_port=%u, page_select=%u, swid=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pddr_reg->local_port, pddr_reg->page_select, swid_id);

    sxd_ret = sxd_access_reg_pddr(pddr_reg, &reg_meta, 1, handler, context);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PDDR device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pmaos_register(sxd_access_cmd_t         cmd,
                                         uint8_t                  swid_id,
                                         sxd_dev_id_t             dev_id,
                                         sxd_completion_handler_t handler,
                                         void                    *context,
                                         struct ku_pmaos_reg     *pmaos_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!pmaos_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PMAOS: module=%u, admin_status=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pmaos_reg->module, pmaos_reg->admin_status);

    sxd_ret = sxd_access_reg_pmaos(pmaos_reg, &reg_meta, 1, handler, context);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PMAOS device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_pplr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pplr_reg      *pplr_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!pplr_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PPLR: local_port=%u, lb_en=%u, lb_cap=%u",
                     __func__, SXD_ACCESS_CMD_STR(cmd), pplr_reg->local_port, pplr_reg->lb_en, pplr_reg->lb_cap);

    sxd_ret = sxd_access_reg_pplr(pplr_reg, &reg_meta, 1, handler, context);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PPLR device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}

sai_status_t mlnx_set_get_ppcr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_ppcr_reg      *ppcr_reg)
{
    sai_status_t   status = SAI_STATUS_SUCCESS;
    sxd_status_t   sxd_ret = SXD_STATUS_SUCCESS;
    sxd_reg_meta_t reg_meta;

    if (!ppcr_reg) {
        MLNX_SAI_LOG_ERR("%s: register is null\n", __func__);
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&reg_meta, 0, sizeof(reg_meta));

    reg_meta.access_cmd = cmd;
    reg_meta.dev_id = dev_id;
    reg_meta.swid = swid_id;

    MLNX_SAI_LOG_DBG("%s: Before %s PPCR: local_port=%u, plane=%u, aggregated_port=%u, num_of_planes=%u, swid=%u",
                     __func__,
                     SXD_ACCESS_CMD_STR(cmd),
                     ppcr_reg->local_port,
                     ppcr_reg->plane,
                     ppcr_reg->aggregated_port,
                     ppcr_reg->num_of_planes,
                     swid_id);

    sxd_ret = sxd_access_reg_ppcr(ppcr_reg, &reg_meta, 1, handler, context);

    if (SXD_CHECK_FAIL(sxd_ret)) {
        MLNX_SAI_LOG_ERR("%s: failed in PPCR device:[%d], error:[%d,%s]",
                         __func__, dev_id, sxd_ret, SXD_STATUS_MSG(sxd_ret));
        status = SAI_STATUS_FAILURE;
    }
out:
    return status;
}
