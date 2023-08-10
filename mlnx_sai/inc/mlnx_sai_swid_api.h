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

#ifndef MLNX_SAI_INC_MLNX_SAI_SWID_API_H_
#define MLNX_SAI_INC_MLNX_SAI_SWID_API_H_

#include "mlnx_sai.h"

/************************************************
 *  Local Defines
 ***********************************************/

/************************************************
 *  Local Macros
 ***********************************************/


/************************************************
 *  Local Type definitions
 ***********************************************/


/************************************************
 *  Defines
 ***********************************************/
typedef struct _sa_port_state {
    uint8_t   port_logical_state; /* PortState */
    uint8_t   port_phy_state;
    uint16_t lid;
} sa_port_state_t;

typedef enum swidapi_status {
    SARC_OK,
    SARC_ERROR,
    SARC_NOT_IMPLEMENTED,
    SARC_NOT_EXIST_MODULE,
    SARC_UNSUPPORTED_MODULE,
    SARC_UNSUPPORTED_SYSTEM,
    SARC_MAD_SEND_FAILED,
    SARC_UNSUPPORTED_FW_VER,
    SARC_FLINT_FAILED,
    SARC_NO_PCI_CONNECTION,
    SARC_NO_MGMT_IS4,
    SARC_CDMIF_ERROR,
    SARC_LID_NOT_ASSIGNED = 77,
    SARC_NO_DR_PATH = 88,
    SARC_DR_PORT_DOWN_ERROR = 89
} swidapi_status_t;

/************************************************
 *  Macros
 ***********************************************/


/************************************************
 *  Type definitions
 ***********************************************/
#define MAX_IB_DEV_NAME        100
#define IB_DEV_PREFIX          "sx_ib"
#define IB_SMP_DATA_SIZE       64
#define IB_PMA_DATA_SIZE       256
#define IB_MAD_RPC_RETRIES_NUM 10
#define IB_MAD_RPC_TIMEOUR_MS  300
#define DEFAULT_IB_GSA_TIMEOUT 100
/************************************************
 *  Global variables
 ***********************************************/


/************************************************
 *  Function declarations
 ***********************************************/


sai_status_t sa_init(swidapi_t** sa_ctx, uint8_t swid_id, uint64_t sys_m_key);

void sa_destroy(swidapi_t** sa_ctx);

/**
 * This function sends a mad to get_port_info.
 * It tries all the provided path until it finds one that works.
 * If it received only one path, it gives it a second chance if it is active.
 * @param sa_ctx: swidapi to use.
 * @param dr_path_list: Paths known to the requested device.
 * @param path_count: How many paths are known.
 * @param ib_port: Wanted port
 * @param ps [out]: speed state.
 * @param state_only: True if only want port state.
 * @param succeded_path [out]: In case succeeded, which of the provided paths succeeded.
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_get_port_info(swidapi_t       *sa_ctx,
                              uint8_t         ib_port,
                              sa_port_state_t *ps);

/**
 * This function sends a mad to get_port_info on ib port 0 and parse the LID
 * of the IB interface on success
 * @param sa_ctx: swidapi to use.
 * @param lid [out]: the LID of the SWID IB interface
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_get_swid_lid(swidapi_t       *sa_ctx,
                             uint16_t        *lid);

/**
 * This function sets the 1U dr_path for the port-id
 * @param port-id: port-id object
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_set_dr_path(ib_portid_t* portid);

/**
 * This function sends a mad to get the port counters for an IB port
 * @param sa_ctx: swidapi to use.
 * @param dev_id: the sx device ID
 * @param ib_port: Wanted port
 * @param pc [out]: port counters
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_get_port_cnt(swidapi_t          *sa_ctx,
                             sxd_dev_id_t        dev_id,
                             uint8_t             ib_port,
                             ib_portid_t        *portid,
                             sa_port_counters_t *pc);
/**
 * This function sends a mad to get the port extended counters for an IB port
 * @param sa_ctx: swidapi to use.
 * @param dev_id: the sx device ID
 * @param ib_port: Wanted port
 * @param pc [out]: port counters
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_get_ext_port_cnt(swidapi_t              *sa_ctx,
                                 sxd_dev_id_t            dev_id,
                                 uint8_t                 ib_port,
                                 ib_portid_t            *portid,
                                 sa_port_counters_t     *pc);

/*
 * This function sets the node description in SDK in case relevant MADs are
 * passed to CPU
 * @param _sxd_handle: an sxd handle
 * @param dev_id: the sx device ID
 * @param swid_id: swid_id
 * @param node_desc: the description text
 * @return 0 unless unexpected error happens.
 */
sai_status_t sa_set_sdk_node_desc(sxd_handle  _sxd_handle,
                                  uint8_t     dev_id,
                                  uint8_t     swid_id,
                                  const char *node_description);

#endif  /* MLNX_SAI_INC_MLNX_SAI_SWID_API_H_ */
