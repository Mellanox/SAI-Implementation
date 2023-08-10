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

#ifndef MLNX_SAI_INC_MLNX_SAI_PRM_API_H_
#define MLNX_SAI_INC_MLNX_SAI_PRM_API_H_


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
#define FW_MAX_QUERY_RETRIES (3)
#define FW_QUERY_DELAY       (100000)       /*in Millisecounds */

/************************************************
 *  Macros
 ***********************************************/


/************************************************
 *  Type definitions
 ***********************************************/


/************************************************
 *  Global variables
 ***********************************************/


/************************************************
 *  Function declarations
 ***********************************************/

sai_status_t mlnx_prm_api_log_set(sx_verbosity_level_t level);

/**
 * mlnx_set_get_pllp_register -
 *    PLLP - Port Local port to Label Port mapping Register
 * @param cmd     - Either set or get
 * @param swid_id - id of the swid
 * @param dev_id  - id of the Switch device
 * @param handler - Can be NULL
 * @param context - Can be NULL
 * @param pllp_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_pllp_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pllp_reg      *pllp_reg);

/**
 * mlnx_set_get_plib_register -
 *    PLIB - Port Local port to Label Port mapping Register
 * @param cmd     - Either set or get
 * @param swid_id - id of the swid
 * @param dev_id  - id of the Switch device
 * @param handler - Can be NULL
 * @param context - Can be NULL
 * @param plib_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_plib_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_plib_reg      *plib_reg);

/**
 * mlnx_set_get_plibdb_register -
 *    PLIBDB - Port Local port to InfiniBand Register
 * @param cmd     - Either set or get
 * @param swid_id - id of the swid
 * @param dev_id  - id of the Switch device
 * @param handler - Can be NULL
 * @param context - Can be NULL
 * @param plibdb_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_plibdb_register(sxd_access_cmd_t         cmd,
                                          uint8_t                  swid_id,
                                          sxd_dev_id_t             dev_id,
                                          sxd_completion_handler_t handler,
                                          void                    *context,
                                          struct ku_plibdb_reg    *plibdb_reg);

/**
 * mlnx_set_get_spzr_register -
 *    Encapsulation of SPZR register access to handle failures are retry flows.
 *    SPZR - IB Node Description
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param spzr_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_spzr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_spzr_reg      *spzr_reg);

/**
 * mlnx_set_get_pmlp_register -
 *    Encapsulation of PMLP register access to handle failures are retry flows.
 *    PMLP - Ports Module to Local Port Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pmlp_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_pmlp_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pmlp_reg      *pmlp_reg);

/**
 * mlnx_set_get_pspa_register -
 *    Encapsulation of PSPA register access to handle failures are retry flows.
 *    PSPA -  Port Switch Partition Allocation.
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pspa_reg - Returned data (cannot be NULL)
 * @return error code
 */
sai_status_t mlnx_set_get_pspa_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        uint8_t                  dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pspa_reg      *pspa_reg);

/**
 * mlnx_set_get_paos_register -
 *    PAOS - Ports Administrative and Operational Status Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param paos_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_paos_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_paos_reg      *paos_reg);

/**
 * mlnx_set_get_pplm_register -
 *    PPLM - Port Phy Link Mode
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pplm_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pplm_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pplm_reg      *pplm_reg);

/**
 * mlnx_set_get_pmtu_register -
 *    PMTU -  Port MTU Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pmtu_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pmtu_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pmtu_reg      *pmtu_reg);

/**
 * mlnx_set_get_ptys_register -
 *    Encapsulation of PTYS register access to handle failures are retry flows.
 *    PTYS - Port Type and Speed Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param ptys_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_ptys_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_ptys_reg      *ptys_reg);

/**
 * mlnx_set_get_pvlc_register -
 *    PVLC - Port Virtual Lane Capabilities
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pvlc_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pvlc_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pvlc_reg      *pvlc_reg);

/**
 * mlnx_set_get_hpkt_register -
 *    HPKT - Host PacKet Trap
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param hpkt_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_hpkt_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_hpkt_reg      *hpkt_reg);

/**
 * mlnx_set_get_ppbmc_register -
 *    PPBMC - Port Phy BER Monitor Control
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param ppbmc_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_ppbmc_register(sxd_access_cmd_t         cmd,
                                         uint8_t                  swid_id,
                                         sxd_dev_id_t             dev_id,
                                         sxd_completion_handler_t handler,
                                         void                    *context,
                                         struct ku_ppbmc_reg     *ppbmc_reg);

/**
 * mlnx_set_get_pddr_register -
 *    PDDR - Port Diagnostics Database Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pddr_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pddr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pddr_reg      *pddr_reg);
/**
 * mlnx_set_get_pmaos_register -
 *    PMAOS - Ports Module Administrative and Operational Status Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pmaos_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pmaos_register(sxd_access_cmd_t         cmd,
                                         uint8_t                  swid_id,
                                         sxd_dev_id_t             dev_id,
                                         sxd_completion_handler_t handler,
                                         void                    *context,
                                         struct ku_pmaos_reg     *pmaos_reg);

/**
 * mlnx_set_get_pplr_register -
 *    PPLR - Port Physical Loopback Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param pplr_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_pplr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_pplr_reg      *pplr_reg);
/**
 * mlnx_set_get_ppcr_register -
 *    PPCR - Port Planarized Configuration Register
 * @param cmd      - Either set or get
 * @param swid_id  - id of the swid
 * @param dev_id   - id of the Switch device
 * @param handler  - Can be NULL
 * @param context  - Can be NULL
 * @param ppcr_reg - Returned data (cannot be NULL)
 * @return error code
 */

sai_status_t mlnx_set_get_ppcr_register(sxd_access_cmd_t         cmd,
                                        uint8_t                  swid_id,
                                        sxd_dev_id_t             dev_id,
                                        sxd_completion_handler_t handler,
                                        void                    *context,
                                        struct ku_ppcr_reg      *ppcr_reg);

#endif  /* MLNX_SAI_INC_MLNX_SAI_PRM_API_H_ */
