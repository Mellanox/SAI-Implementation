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
#include <errno.h>
#include "mlnx_sai.h"
#include "mlnx_sai_swid_api.h"

#undef  __MODULE__
#define __MODULE__ SAI_SWID_API

#define MLNX_SAI_SWID_API_C_


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
static void unpack_port_state(void* pi, sa_port_state_t* ps)
{
    uint32_t field;

    if (!pi || !ps) {
        MLNX_SAI_LOG_ERR("Get pi or ps NULL pointers.\n");
        return;
    }

    mad_decode_field(pi, IB_PORT_STATE_F, &field);
    ps->port_logical_state = (uint8_t)field;
    mad_decode_field(pi, IB_PORT_PHYS_STATE_F, &field);
    ps->port_phy_state = (uint8_t)field;

    mad_decode_field(pi, IB_PORT_LID_F, &field);
    ps->lid = (uint16_t)field;
}


sai_status_t sa_set_dr_path(ib_portid_t* portid)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!portid) {
        MLNX_SAI_LOG_ERR("Get portid NULL pointers.\n");
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    /* for 1U switch there is only 1 path and its 0 - so mem-set to zero is the
     * same as setting:
     * portid->drpath.p[0] = 0;
     * portid->drpath.cnt = 0;
     */
    memset(portid, 0, sizeof(*portid));
    portid->drpath.drdlid = 0xffff;
    portid->drpath.drslid = 0xffff;
out:
    return status;
}


static sai_status_t __get_port_info(swidapi_t *sa_ctx, int ib_port, sa_port_state_t *ps)
{
    char         portinfo[IB_SMP_DATA_SIZE];
    ib_portid_t  portid;
    void        *pi = portinfo;
    sai_status_t status = SAI_STATUS_SUCCESS;

    sa_set_dr_path(&portid);

    if (!smp_query_via(pi, &portid, IB_ATTR_PORT_INFO, ib_port, 0, sa_ctx->sport)) {
        MLNX_SAI_LOG_ERR("Failed to send port info MAD to route: %s\n",
                         portid2str(&portid));
        status = SAI_STATUS_FAILURE;
        goto out;
    }
    unpack_port_state(pi, ps);

out:
    return status;
}

/************************************************
 *  Function implementations
 ***********************************************/

sai_status_t mlnx_swid_api_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;
    return SAI_STATUS_SUCCESS;
}

sai_status_t sa_init(swidapi_t** sa_ctx, uint8_t swid_id, uint64_t sys_m_key)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    swidapi_t  * ctx = NULL;
    const char  *asic_id = NULL;
    const char  *num_of_asics = NULL;
    uint8_t      dev_ib_id = swid_id;
    int          mgmt_classes[6] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS,
                                     IB_PERFORMANCE_CLASS, 9, 10 };
    char         sx_ib_dev_name[MAX_IB_DEV_NAME] = {'\0'};

    MLNX_SAI_LOG_INF("%s: IB SWID API:INIT , SWID:[%d] ", __func__, swid_id);

    *sa_ctx = malloc(sizeof(swidapi_t));
    if (*sa_ctx == NULL) {
        status = SAI_STATUS_NO_MEMORY;
        goto out;
    }
    /* Local ptr for convenience */
    ctx = *sa_ctx;

    memset(ctx, 0, sizeof(swidapi_t));

    num_of_asics = getenv("NAMESPACE_COUNT");
    /* Multi ASIC Device */
    if ((num_of_asics != NULL) && (0 != strcmp(num_of_asics, ""))) {
        asic_id = getenv("NAMESPACE_ID");
        if ((asic_id == NULL) || (0 == strcmp(asic_id, ""))) {
            MLNX_SAI_LOG_ERR("No environment variable named 'NAMESPACE_ID'\n");
            status = SAI_STATUS_FAILURE;
            goto out;
        }
        dev_ib_id = (atoi(num_of_asics) * swid_id) + atoi(asic_id);
    }

    ctx->swid_num = swid_id;

    snprintf(sx_ib_dev_name, MAX_IB_DEV_NAME, "%s_%d", IB_DEV_PREFIX,
             dev_ib_id);

    ctx->sport = mad_rpc_open_port(sx_ib_dev_name, 0, mgmt_classes, 6);
    if (ctx->sport == NULL) {
        MLNX_SAI_LOG_ERR("%s: Mad rpc open port failed, device:[%s] port:[0], errno:[%d,%s]",
                         __FUNCTION__, sx_ib_dev_name,  errno, strerror(errno));
        sa_destroy(sa_ctx);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    smp_mkey_set(ctx->sport, sys_m_key);


    /* This is a way to handle the lost port_info mads. */
    /* The IS4 can handle only a single MAD at a time. */
    /* I assume that the IS4 is busy with statsd and opensm MADs, */
    /* and occasional port_info/counters MADs are dropped. */
    /* To face this, retries are increased and TO is decreased. */
    /* This lowers the probability of the IS4 unable to answer. */
    mad_rpc_set_retries(ctx->sport, IB_MAD_RPC_RETRIES_NUM);
    mad_rpc_set_timeout(ctx->sport, IB_MAD_RPC_TIMEOUR_MS);

    MLNX_SAI_LOG_INF("%s: IB DEVICE NAME : [%s]\n", __func__, sx_ib_dev_name);

out:
    /* coverity[check_after_deref:SUPPRESS] */
    if ((status != SAI_STATUS_SUCCESS) && sa_ctx) {
        /* coverity[double_free:SUPPRESS] */
        sa_destroy(sa_ctx);
    }
    MLNX_SAI_LOG_INF("%s: IB SWID API:  IB SWID API INIT DONE [Return value: %s]",
                     __func__, SX_STATUS_MSG(status));
    return status;
}

void sa_destroy(swidapi_t** sa_ctx)
{
    MLNX_SAI_LOG_INF("%s: IB SWID API: DEINIT", __func__);
    if (sa_ctx && *sa_ctx) {
        if ((*sa_ctx)->sport) {
            mad_rpc_close_port((*sa_ctx)->sport);
            (*sa_ctx)->sport = NULL;
        }
        free(*sa_ctx);
    }
    MLNX_SAI_LOG_INF("%s: IB SWID API:  IB SWID API DEINIT DONE", __func__);
}

sai_status_t sa_get_port_info(swidapi_t *sa_ctx, uint8_t ib_port, sa_port_state_t *ps)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint8_t      i = 0;

    if (!sa_ctx || !ps) {
        MLNX_SAI_LOG_ERR("Get sa_ctx or ps NULL pointers.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    for (i = 0; i < 2; i++) {
        status = __get_port_info(sa_ctx, ib_port, ps);
        if (status == SAI_STATUS_SUCCESS) {
            break;
        } else {
            MLNX_SAI_LOG_ERR("Failed to get port info for ib port %u, try number: %u\n", ib_port, i);
        }
    }

out:
    return status;
}

sai_status_t sa_get_swid_lid(swidapi_t *sa_ctx, uint16_t        *lid)
{
    sai_status_t    status = SAI_STATUS_SUCCESS;
    sa_port_state_t ps;

    if (!sa_ctx | !lid) {
        MLNX_SAI_LOG_ERR("Got sa_ctx or lid NULL pointers.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }
    /* notice we need to pass ib-port 0 since the LID is a not a physical port attribute */
    status = sa_get_port_info(sa_ctx, 0, &ps);
    if (SAI_STATUS_SUCCESS != status) {
        MLNX_SAI_LOG_ERR("Failed Get Port info for ib port %u \n", 0);
        goto out;
    }

    *lid = ps.lid;

out:
    return status;
}

sai_status_t sa_get_port_cnt(swidapi_t          *sa_ctx,
                             sxd_dev_id_t        dev_id,
                             uint8_t             ib_port,
                             ib_portid_t        *portid,
                             sa_port_counters_t *pc)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint8_t      buf[IB_PMA_DATA_SIZE];
    uint32_t     val;

    if (!sa_ctx || !pc || !portid) {
        MLNX_SAI_LOG_ERR("Get sa_ctx or ps NULL pointers.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }
    if (!pma_query_via(buf, portid, ib_port, DEFAULT_IB_GSA_TIMEOUT, IB_GSI_PORT_COUNTERS,
                       sa_ctx->sport)) {
        MLNX_SAI_LOG_NTC("Could not send MAD using LID:[%d] ", portid->lid);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    mad_decode_field(buf, IB_PC_ERR_SYM_F, &val);
    pc->symbol_err_cnt = (uint16_t)val;
    mad_decode_field(buf, IB_PC_ERR_RCV_F, &val);
    pc->rcv_err = (uint16_t)val;
    mad_decode_field(buf, IB_PC_XMT_DISCARDS_F, &val);
    pc->xmit_discards = (uint16_t)val;
    mad_decode_field(buf, IB_PC_ERR_XMTCONSTR_F, &val);
    pc->xmit_constraint_err = (uint8_t)val;
    mad_decode_field(buf, IB_PC_VL15_DROPPED_F, &val);
    pc->vl15_dropped = (uint16_t)val;
    /* The data fields are in dword - convert to bytes. */
    mad_decode_field(buf, IB_PC_XMT_BYTES_F, &val);
    pc->xmit_data_bytes = (val >> 30) ? 0xffffffff : val * 4;
    mad_decode_field(buf, IB_PC_RCV_BYTES_F, &val);
    pc->rcv_data_bytes = (val >> 30) ? 0xffffffff : val * 4;
    mad_decode_field(buf, IB_PC_XMT_PKTS_F, &val);
    pc->xmit_pkts = val;
    mad_decode_field(buf, IB_PC_RCV_PKTS_F, &val);
    pc->rcv_pkts = val;
    mad_decode_field(buf, IB_PC_XMT_WAIT_F, &val);
    pc->xmit_wait = val;

out:
    return status;
}

sai_status_t sa_get_ext_port_cnt(swidapi_t          *sa_ctx,
                                 sxd_dev_id_t        dev_id,
                                 uint8_t             ib_port,
                                 ib_portid_t        *portid,
                                 sa_port_counters_t *pc)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint8_t      buf[IB_PMA_DATA_SIZE];

    if (!sa_ctx || !pc || !portid) {
        MLNX_SAI_LOG_ERR("Get sa_ctx or ps NULL pointers.\n");
        status = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }
    if (!pma_query_via(buf, portid, ib_port, DEFAULT_IB_GSA_TIMEOUT, IB_GSI_PORT_COUNTERS_EXT,
                       sa_ctx->sport)) {
        MLNX_SAI_LOG_NTC("Could not send MAD using LID:[%d]", portid->lid);
        status = SAI_STATUS_FAILURE;
        goto out;
    }

    mad_decode_field(buf, IB_PC_EXT_XMT_BYTES_F, &pc->xmit_data_bytes);
    mad_decode_field(buf, IB_PC_EXT_RCV_BYTES_F, &pc->rcv_data_bytes);
    /* The data fields are in dword - convert to bytes. */
    pc->xmit_data_bytes = (pc->xmit_data_bytes >> 62) ? -1ULL : pc->xmit_data_bytes * 4;
    pc->rcv_data_bytes = (pc->rcv_data_bytes >> 62) ? -1ULL : pc->rcv_data_bytes * 4;

    mad_decode_field(buf, IB_PC_EXT_XMT_PKTS_F, &pc->xmit_pkts);
    mad_decode_field(buf, IB_PC_EXT_RCV_PKTS_F, &pc->rcv_pkts);

out:
    return status;
}

sai_status_t sa_set_sdk_node_desc(sxd_handle _sxd_handle, uint8_t dev_id, uint8_t swid_id,
                                  const char *node_description)
{
    struct ku_ib_node_description node_desc;
    sxd_ctrl_pack_t               ctrl_pack;
    sxd_status_t                  sxd_err;
    sai_status_t                  err = SAI_STATUS_SUCCESS;

    ;

    if (!node_description) {
        MLNX_SAI_LOG_ERR("Got node_description NULL pointers.\n");
        err = SAI_STATUS_INVALID_PARAMETER;
        goto out;
    }

    memset(&node_desc, 0, sizeof(node_desc));

    node_desc.dev_id = dev_id;
    memcpy(node_desc.node_description, node_description, sizeof(node_desc.node_description));
    node_desc.swid = swid_id;

    ctrl_pack.ctrl_cmd = CTRL_CMD_SET_SW_IB_NODE_DESC;
    ctrl_pack.cmd_body = &node_desc;

    sxd_err = sxd_ioctl(_sxd_handle, &ctrl_pack);
    if (sxd_err != SXD_STATUS_SUCCESS) {
        MLNX_SAI_LOG_ERR("Failed to set SDK node description for device:[%u] error:[%d,%s]",
                         dev_id, sxd_err, SXD_STATUS_MSG(sxd_err));
        err = SAI_STATUS_FAILURE;
        goto out;
    }

out:
    MLNX_SAI_LOG_DBG("SDK node description for device:[%d] done [Return value: %d]",
                     dev_id, err);
    return err;
}
