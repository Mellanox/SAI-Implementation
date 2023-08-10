#include "sai_windows.h"
#include "sai.h"
#include "mlnx_sai.h"
#include "syslog.h"
#include <errno.h>
#include "assert.h"
#ifndef _WIN32
#include <dirent.h>
#include <netinet/ether.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/mman.h>
#include <pthread.h>
#endif
#include <sx/utils/dbg_utils.h>

#ifdef _WIN32
#undef CONFIG_SYSLOG
#endif

#undef  __MODULE__
#define __MODULE__ SAI_SWITCH_COMMON
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define SDK_START_CMD_STR_LEN 255
#define SAI_PATH              "/sai_db"


extern sai_db_t               *g_sai_db_ptr;
extern sai_switch_profile_id_t g_profile_id;
extern uint32_t                g_mlnx_shm_rm_size;
extern bool                    dfw_thread_asked_to_stop;
extern bool                    g_log_init;
extern uint32_t                g_device_id;
extern uint32_t                g_swid_id;
extern bool                    g_is_chipsim;

void log_cb(sx_log_severity_t severity, const char *module_name, char *msg);
void log_pause_cb(void);
size_t mlnx_sai_rm_db_size_get(void);
sai_status_t sai_dbg_do_dump(_In_ const char *dump_file_name);
sai_status_t mlnx_config_platform_parse(_In_ const char *platform);
uint8_t mlnx_port_mac_mask_get(void);
sai_status_t parse_port_info(xmlDoc *doc, xmlNode * port_node);
sx_status_t get_chip_type(enum sxd_chip_types* chip_type);
sai_status_t mlnx_sai_db_initialize(const char *config_file, sx_chip_types_t chip_type);
sai_status_t mlnx_cb_table_init(void);

#ifdef CONFIG_SYSLOG
void log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    if (!g_log_init) {
        openlog("SDK", 0, LOG_USER);
        g_log_init = true;
    }

    mlnx_syslog(severity, module_name, "%s", msg);
}

void log_pause_cb(void)
{
    closelog();
    g_log_init = false;
}
#else
void log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    UNREFERENCED_PARAMETER(severity);
    UNREFERENCED_PARAMETER(module_name);
    UNREFERENCED_PARAMETER(msg);
}
#endif /* CONFIG_SYSLOG */


/* The number of ports on the switch [uint32_t] */
sai_status_t mlnx_switch_port_number_get(_In_ const sai_object_key_t   *key,
                                         _Inout_ sai_attribute_value_t *value,
                                         _In_ uint32_t                  attr_index,
                                         _Inout_ vendor_cache_t        *cache,
                                         void                          *arg)
{
    SX_LOG_ENTER();

    cl_plock_acquire(&g_sai_db_ptr->p_lock);
    value->u32 = g_sai_db_ptr->ports_number;
    cl_plock_release(&g_sai_db_ptr->p_lock);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_switch_max_ports_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = MAX_PORTS;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the port list [sai_object_list_t] */
sai_status_t mlnx_switch_port_list_get(_In_ const sai_object_key_t   *key,
                                       _Inout_ sai_attribute_value_t *value,
                                       _In_ uint32_t                  attr_index,
                                       _Inout_ vendor_cache_t        *cache,
                                       void                          *arg)
{
    sai_object_id_t    *ports = NULL;
    sai_status_t        status;
    mlnx_port_config_t *port;
    uint32_t            ii, jj = 0;

    SX_LOG_ENTER();

    ports = calloc(MAX_PORTS, sizeof(*ports));
    if (!ports) {
        SX_LOG_ERR("Failed to allocate memory\n");
        return SAI_STATUS_NO_MEMORY;
    }

    sai_db_write_lock();

    mlnx_port_phy_foreach(port, ii) {
        ports[jj++] = port->saiport;
    }

    status = mlnx_fill_objlist(ports, g_sai_db_ptr->ports_number, &value->objlist);

    sai_db_unlock();

    free(ports);
    SX_LOG_EXIT();
    return status;
}

/* Get the CPU Port [sai_object_id_t] */
sai_status_t mlnx_switch_cpu_port_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    sai_status_t status;

    SX_LOG_ENTER();

    if (SAI_STATUS_SUCCESS != (status = mlnx_create_object(SAI_OBJECT_TYPE_PORT, CPU_PORT, NULL, &value->oid))) {
        return status;
    }

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

/* Get the Max MTU in bytes, Supported by the switch [uint32_t] */
sai_status_t mlnx_switch_max_mtu_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    SX_LOG_ENTER();

    value->u32 = g_resource_limits.port_mtu_max;

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


/* Default switch MAC Address [sai_mac_t] */
sai_status_t mlnx_switch_src_mac_get(_In_ const sai_object_key_t   *key,
                                     _Inout_ sai_attribute_value_t *value,
                                     _In_ uint32_t                  attr_index,
                                     _Inout_ vendor_cache_t        *cache,
                                     void                          *arg)
{
    sai_status_t  status;
    sx_mac_addr_t mac;

    SX_LOG_ENTER();

    sai_db_read_lock();

    status = mlnx_switch_get_mac(&mac);
    if (SAI_ERR(status)) {
        goto out;
    }

    memcpy(value->mac, &mac,  sizeof(value->mac));

out:
    sai_db_unlock();
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_switch_init_connect_get(_In_ const sai_object_key_t   *key,
                                          _Inout_ sai_attribute_value_t *value,
                                          _In_ uint32_t                  attr_index,
                                          _Inout_ vendor_cache_t        *cache,
                                          void                          *arg)
{
    mlnx_object_id_t mlnx_switch_id = {0};
    sai_status_t     status;

    SX_LOG_ENTER();

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_SWITCH, key->key.object_id, &mlnx_switch_id);
    if (SAI_ERR(status)) {
        SX_LOG_EXIT();
        return status;
    }

    value->booldata = mlnx_switch_id.id.is_created;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_switch_profile_id_get(_In_ const sai_object_key_t   *key,
                                        _Inout_ sai_attribute_value_t *value,
                                        _In_ uint32_t                  attr_index,
                                        _Inout_ vendor_cache_t        *cache,
                                        void                          *arg)
{
    SX_LOG_ENTER();
    value->u32 = g_profile_id;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}


/* The current value of the maximum temperature
 * retrieved from the switch sensors, in Celsius [int32_t] */
sai_status_t mlnx_switch_max_temp_get(_In_ const sai_object_key_t   *key,
                                      _Inout_ sai_attribute_value_t *value,
                                      _In_ uint32_t                  attr_index,
                                      _Inout_ vendor_cache_t        *cache,
                                      void                          *arg)
{
    struct ku_mtmp_reg tmp_reg;
    sxd_reg_meta_t     reg_meta;
    int16_t            tmp = 0;
    sxd_status_t       sxd_status;

    #define TEMP_MASUREMENT_UNIT 0.125

    SX_LOG_ENTER();

    memset(&tmp_reg, 0, sizeof(tmp_reg));
    memset(&reg_meta, 0, sizeof(reg_meta));
    tmp_reg.sensor_index = 0;
    reg_meta.access_cmd = SXD_ACCESS_CMD_GET;
    reg_meta.dev_id = g_device_id;
    reg_meta.swid = g_swid_id;

    sxd_status = sxd_access_reg_mtmp(&tmp_reg, &reg_meta, 1, NULL, NULL);
    if (sxd_status) {
        SX_LOG_ERR("Access_mtmp_reg failed with status (%s:%d)\n", SXD_STATUS_MSG(sxd_status), sxd_status);
        return SAI_STATUS_FAILURE;
    }
    if (((int16_t)tmp_reg.temperature) < 0) {
        tmp = (0xFFFF + ((int16_t)tmp_reg.temperature) + 1);
    } else {
        tmp = (int16_t)tmp_reg.temperature;
    }
    value->s32 = (int32_t)(tmp * TEMP_MASUREMENT_UNIT);

    SX_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_restart_type_get(_In_ const sai_object_key_t   *key,
                                   _Inout_ sai_attribute_value_t *value,
                                   _In_ uint32_t                  attr_index,
                                   _Inout_ vendor_cache_t        *cache,
                                   void                          *arg)
{
    SX_LOG_ENTER();
    value->s32 = SAI_SWITCH_RESTART_TYPE_ANY;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_nv_storage_get(_In_ const sai_object_key_t   *key,
                                 _Inout_ sai_attribute_value_t *value,
                                 _In_ uint32_t                  attr_index,
                                 _Inout_ vendor_cache_t        *cache,
                                 void                          *arg)
{
    SX_LOG_ENTER();
    /* SDK persistent files for ISSU approximate size */
    value->u64 = 100;
    SX_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}


/* DFW feature functions */
static sai_status_t mlnx_switch_dump_health_event_prepare_stage_dir(_In_ const char *stage_dir)
{
    const char create_or_clear_dir_command_fmt[] = "mkdir -p %s && rm -rf %s/*";
    char       create_or_clear_dir_command[2 * (SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX) + 100];
    int        system_err;

    snprintf(create_or_clear_dir_command,
             sizeof(create_or_clear_dir_command),
             create_or_clear_dir_command_fmt,
             stage_dir,
             stage_dir);

    system_err = system(create_or_clear_dir_command);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", create_or_clear_dir_command);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static void mlnx_switch_dump_health_event_fill_metadata(_In_ FILE *stream, _In_ sx_event_health_notification_t *event)
{
    sx_event_health_ecc_data_t *ecc_data = NULL;

    dbg_utils_print_module_header(stream, "SDK health event metadata");

    dbg_utils_print_field(stream, "Device ID:", &event->device_id, PARAM_UINT8_E);
    dbg_utils_print_field(stream, "Severity:", sx_health_severity_str(event->severity), PARAM_STRING_E);
    dbg_utils_print_field(stream, "Cause:", sx_health_cause_str(event->cause), PARAM_STRING_E);
    dbg_utils_print_field(stream, "Was debug started:", &event->was_debug_started, PARAM_BOOL_E);
    dbg_utils_print_field(stream, "IRISC ID:", &event->irisc_id, PARAM_UINT8_E);

    if (event->cause == SX_HEALTH_CAUSE_ECC_E) {
        ecc_data = &event->data.ecc_data;
        dbg_utils_print_field(stream, "ECC slot index:", &ecc_data->slot_index, PARAM_UINT16_E);
        dbg_utils_print_field(stream, "ECC device index:", &ecc_data->device_index, PARAM_UINT16_E);
        switch (event->severity) {
        case SX_HEALTH_SEVERITY_FATAL_E:
            dbg_utils_print_field(stream, "ECC uncorrected:",
                                  &ecc_data->ecc_stats.ecc_uncorrected, PARAM_UINT32_E);
            break;

        case SX_HEALTH_SEVERITY_NOTICE_E:
            dbg_utils_print_field(stream, "ECC corrected:",
                                  &ecc_data->ecc_stats.ecc_corrected, PARAM_UINT32_E);
            break;

        default:
            SX_LOG_ERR("Unexpected event severity - %s\n", sx_health_severity_str(event->severity));
        }
    }
}

static sai_status_t mlnx_switch_dump_health_event_remove_extra_dumps(_In_ const char *path, _In_ int limit)
{
    const char dfw_archive_name_pattern[] = "sai-dfw-*.tar";
    const char get_all_dump_archives_command_fmt[] = "ls -1ht %s/%s 2>/dev/null";
    const char skip_newest_files_command_fmt[] = "tail -n +%d";
    const char xargs_remove_files_command[] = "xargs rm -f";
    char       get_all_dump_archives_command[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 100];
    char       skip_newest_files_command[100];
    char       complex_command[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 250];
    int        system_err;

    snprintf(get_all_dump_archives_command,
             sizeof(get_all_dump_archives_command),
             get_all_dump_archives_command_fmt,
             path,
             dfw_archive_name_pattern);
    snprintf(skip_newest_files_command, sizeof(skip_newest_files_command), skip_newest_files_command_fmt, limit + 1); /* Skip N, starts from N+1 */
    snprintf(complex_command,
             sizeof(complex_command),
             "%s|%s|%s",
             get_all_dump_archives_command,
             skip_newest_files_command,
             xargs_remove_files_command);

    system_err = system(complex_command);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", complex_command);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}


static sai_status_t mlnx_switch_dump_health_event_move_dumps_from_stage_dir(_In_ const char *stage_dir)
{
#ifndef _WIN32
    /* Comments in next lines described parameters to pass into printf as %s */
    const char                       tar_command_fmt[] = "tar -C %s -cf %s ."; /* 1 - directory, 2 - archive name */
    const char                       dfw_archive_name_fmt[] = "%s/sai-dfw-%lu.tar"; /* 1 - directory, 2 - expected timestamp */
    const char                       clear_stage_dir_cmd_fmt[] = "rm -rf %s/*"; /* 1 - Directory */
    const mlnx_dump_configuration_t *dump_conf = &g_sai_db_ptr->dump_configuration;
    struct timespec                  tm;
    int                              system_err;
    sai_status_t                     sai_status;
    char                             dfw_archive_name[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 100];
    char                             tar_command[2 * (SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 100)];
    char                             clear_stage_dir_cmd[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 100];

    clock_gettime(CLOCK_REALTIME, &tm);
    snprintf(dfw_archive_name, sizeof(dfw_archive_name), dfw_archive_name_fmt, dump_conf->path, tm.tv_sec);
    snprintf(tar_command, sizeof(tar_command), tar_command_fmt, stage_dir, dfw_archive_name);
    snprintf(clear_stage_dir_cmd, sizeof(clear_stage_dir_cmd), clear_stage_dir_cmd_fmt, stage_dir);

    sai_status = mlnx_switch_dump_health_event_remove_extra_dumps(dump_conf->path, dump_conf->max_events_to_store - 1);
    if (SAI_ERR(sai_status)) {
        /* Error printed inside function */
        return SAI_STATUS_FAILURE;
    }

    /* Create archive */
    system_err = system(tar_command);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", tar_command);
        return SAI_STATUS_FAILURE;
    }

    /* Delete files from stage dir */
    system_err = system(clear_stage_dir_cmd);
    if (0 != system_err) {
        SX_LOG_ERR("Failed running \"%s\".\n", clear_stage_dir_cmd);
        return SAI_STATUS_FAILURE;
    }
#endif

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_health_event_handle(_In_ sx_event_health_notification_t *event)
{
#ifndef _WIN32
    const char                       dump_stage_dir_name[] = "_stage";
    const char                       sai_sdk_dump_file_name[] = "sai_sdk_dump.txt";
    const mlnx_dump_configuration_t *dump_conf = &g_sai_db_ptr->dump_configuration;
    DIR                             *d = NULL;
    char                             dump_file_name[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 20];
    char                             dump_stage_dir[SX_API_DUMP_PATH_LEN_LIMIT + PATH_MAX + 1];
    const char                      *event_severity_str = sx_health_severity_str(event->severity);
    const char                      *event_cause_str = sx_health_cause_str(event->cause);
    int                              event_log_level;
    FILE                            *dump_file = NULL;
    sai_status_t                     sai_status = SAI_STATUS_SUCCESS;
    sx_status_t                      sdk_status = SX_STATUS_SUCCESS;
    sx_dbg_extra_info_t              dbg_info;
    sx_event_health_ecc_data_t      *ecc_data = NULL;

    if (NULL == (d = opendir(dump_conf->path))) {
        SX_LOG_ERR("Directory for dumps is not exists, skip\n");
        return SAI_STATUS_FAILURE;
    } else {
        closedir(d);
    }

    snprintf(dump_stage_dir, sizeof(dump_stage_dir), "%s/%s", dump_conf->path, dump_stage_dir_name);
    snprintf(dump_file_name, sizeof(dump_file_name), "%s/%s", dump_stage_dir, sai_sdk_dump_file_name);

    mlnx_switch_dump_health_event_prepare_stage_dir(dump_stage_dir);

    sai_status = sai_dbg_do_dump(dump_file_name);
    if (SAI_ERR(sai_status)) {
        SX_LOG_ERR("Failed to generate SAI dump into %s\n", dump_file_name);
        return sai_status;
    }

    dump_file = fopen(dump_file_name, "a");
    if (NULL == dump_file) {
        SX_LOG_ERR("Error opening file %s with write permission\n", dump_file_name);
        return SAI_STATUS_FAILURE;
    }

    mlnx_switch_dump_health_event_fill_metadata(dump_file, event);
    fclose(dump_file);

    /* Start sync sx_api_dbg_generate_dump_extra */
    memset(&dbg_info, 0, sizeof(dbg_info));
    dbg_info.dev_id = SX_DEVICE_ID;
    dbg_info.force_db_refresh = true;
#if __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
    strncpy(dbg_info.path, dump_stage_dir, sizeof(dbg_info.path));
    dbg_info.path[sizeof(dbg_info.path) - 1] = 0;
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
    if ((SX_HEALTH_SEVERITY_CRIT_E == event->severity) || (SX_HEALTH_SEVERITY_ERR_E == event->severity)) {
        dbg_info.ir_dump_enable = true;
    }

    if (SX_STATUS_SUCCESS != (sdk_status = sx_api_dbg_generate_dump_extra(gh_sdk, &dbg_info))) {
        MLNX_SAI_LOG_ERR("Error generating extended sdk dump, sx status: %s\n", SX_STATUS_MSG(sdk_status));
    }

    sai_status = mlnx_switch_dump_health_event_move_dumps_from_stage_dir(dump_stage_dir);
    if (SAI_ERR(sai_status)) {
        /* Error printed inside function */
        return sai_status;
    }

    switch (event->severity) {
    case SX_HEALTH_SEVERITY_CRIT_E:
    case SX_HEALTH_SEVERITY_ERR_E:
        event_log_level = SX_LOG_ERROR;
        break;

    case SX_HEALTH_SEVERITY_NOTICE_E:
        event_log_level = SX_LOG_NOTICE;
        break;

    /* WARNING, also in case of unknown severity - used WARNING level */
    default:
        event_log_level = SX_LOG_WARNING;
    }

    /* This should be syslog message */
    SX_LOG(event_log_level, "Health event happened, severity %s, cause %s\n", event_severity_str, event_cause_str);

    if (event->cause == SX_HEALTH_CAUSE_ECC_E) {
        ecc_data = &event->data.ecc_data;
        switch (event->severity) {
        case SX_HEALTH_SEVERITY_FATAL_E:
            event_log_level = SX_LOG_ERROR;
            SX_LOG(event_log_level,
                   "ECC uncorrected stats updated, slot index %u, device index %u, ECC uncorrected counter %u\n",
                   ecc_data->slot_index,
                   ecc_data->device_index,
                   ecc_data->ecc_stats.ecc_uncorrected);
            break;

        case SX_HEALTH_SEVERITY_NOTICE_E:
            event_log_level = SX_LOG_NOTICE;
            SX_LOG(event_log_level,
                   "ECC corrected stats updated, slot index %u, device index %u, ECC corrected counter %u\n",
                   ecc_data->slot_index,
                   ecc_data->device_index,
                   ecc_data->ecc_stats.ecc_corrected);
            break;

        default:
            SX_LOG_ERR("Unexpected ECC event severity - %s\n", event_severity_str);
            return SAI_STATUS_FAILURE;
        }
    }
#endif /* ifndef _WIN32 */

    return SAI_STATUS_SUCCESS;
}

static sai_status_t mlnx_switch_rearm_dfw(_In_ sx_api_handle_t api_handle)
{
    sx_dbg_control_params_t dbg_params;
    sx_status_t             status;

    memset(&dbg_params, 0, sizeof(dbg_params));
    dbg_params.fw_fatal_event_config.fw_fatal_event_enable = TRUE;
    dbg_params.fw_fatal_event_config.auto_extraction_policy = SX_DBG_POLICY_NO_AUTO_DEBUG_EXTRACTION_E;
    dbg_params.dev_id = g_device_id;
    if (SX_STATUS_SUCCESS != (status = sx_api_fw_dbg_control_set(api_handle, SX_ACCESS_CMD_SET, &dbg_params))) {
        SX_LOG_ERR("sx_api_dfw_dbg_control_set failed for dev id %d", dbg_params.dev_id);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}


void mlnx_switch_dfw_thread_func(_In_ void *context)
{
    sx_api_handle_t                 api_handle = SX_API_INVALID_HANDLE;
    sx_event_health_notification_t *event = NULL;
    sx_user_channel_t               callback_channel;
    uint8_t                        *p_packet = NULL;
    uint32_t                        packet_size;
    sx_receive_info_t              *receive_info = NULL;
    fd_set                          descr_set;
    struct timeval                  timeout;
    int                             ret_val;
    sx_status_t                     status = SX_STATUS_SUCCESS;
    sai_status_t                    sai_status = SAI_STATUS_SUCCESS;

    if (g_is_chipsim) {
        SX_LOG_ERR("This function is not supported on ChipSim.\n");
        return;
    }
    memset(&callback_channel, 0, sizeof(callback_channel));

    if (SX_STATUS_SUCCESS != (status = sx_api_open(sai_log_cb, &api_handle))) {
        MLNX_SAI_LOG_ERR("Can't open connection to SDK - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_open(api_handle, &callback_channel.channel.fd))) {
        SX_LOG_ERR("host ifc open port fd failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    callback_channel.type = SX_USER_CHANNEL_TYPE_FD;
    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_trap_id_register_set(api_handle, SX_ACCESS_CMD_REGISTER,
                                                                            g_swid_id,
                                                                            SX_TRAP_ID_SDK_HEALTH_EVENT,
                                                                            &callback_channel))) {
        SX_LOG_ERR("host ifc trap register SX_TRAP_ID_SDK_HEALTH_EVENT failed - %s.\n", SX_STATUS_MSG(status));
        goto out;
    }

    receive_info = (sx_receive_info_t*)calloc(1, sizeof(*receive_info));
    if (NULL == receive_info) {
        SX_LOG_ERR("Can't allocate receive_info memory\n");
        status = SX_STATUS_NO_MEMORY;
        goto out;
    }

    p_packet = (uint8_t*)malloc(sizeof(*p_packet) * SX_HOST_EVENT_BUFFER_SIZE_MAX);
    if (NULL == p_packet) {
        SX_LOG_ERR("Can't allocate packet memory\n");
        status = SX_STATUS_NO_MEMORY;
        goto out;
    }
    SX_LOG_NTC("DFW packet buffer size %u\n", SX_HOST_EVENT_BUFFER_SIZE_MAX);

    if (SAI_STATUS_SUCCESS != (sai_status = mlnx_switch_rearm_dfw(api_handle))) {
        goto out;
    }

    while (!dfw_thread_asked_to_stop) {
        FD_ZERO(&descr_set);
        FD_SET(callback_channel.channel.fd.fd, &descr_set);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        ret_val = select(FD_SETSIZE, &descr_set, NULL, NULL, &timeout);

        if (-1 == ret_val) {
            SX_LOG_ERR("select ended with error/interrupt %s\n", strerror(errno));
            status = SX_STATUS_ERROR;
            goto out;
        }

        if (ret_val > 0) {
            if (FD_ISSET(callback_channel.channel.fd.fd, &descr_set)) {
                packet_size = SX_HOST_EVENT_BUFFER_SIZE_MAX;
                if (SX_STATUS_SUCCESS !=
                    (status =
                         sx_lib_host_ifc_recv(&callback_channel.channel.fd, p_packet, &packet_size, receive_info))) {
                    SX_LOG_ERR("sx_api_host_ifc_recv on callback fd failed with error %s out size %u\n",
                               SX_STATUS_MSG(status), packet_size);
                    goto out;
                }

                if (SX_TRAP_ID_SDK_HEALTH_EVENT != receive_info->trap_id) {
                    continue;
                }

                event = &receive_info->event_info.sdk_health;
                if ((SX_HEALTH_CAUSE_DUMP_COMPLETED_E == event->cause) ||
                    (SX_HEALTH_CAUSE_DUMP_FAILED_E == event->cause)) {
                    SX_LOG_NTC("DFW thread got %s async dump.\n",
                               (SX_HEALTH_CAUSE_DUMP_COMPLETED_E == event->cause) ? "completed" : "failed");
#ifndef _WIN32
                    sem_post(&g_sai_db_ptr->dfw_sem);
#endif /* ifndef _WIN32 */
                } else {
                    /* Not start handling event if max dumps is not configured */
                    if (0 == g_sai_db_ptr->dump_configuration.max_events_to_store) {
                        sai_status = SAI_STATUS_SUCCESS;
                        continue;
                    }

                    sai_status = mlnx_switch_health_event_handle(event);
                    if (SAI_ERR(sai_status)) {
                        SX_LOG_ERR("SDK health event handle failed.\n");
                        sai_status = SAI_STATUS_SUCCESS;
                        continue;
                    }

                    /* rearm event only for notice/warning, don't rearm on error and above to avoid event loop as system is
                     * considered unstable */
                    if ((event->severity == SX_HEALTH_SEVERITY_WARN_E) ||
                        (event->severity == SX_HEALTH_SEVERITY_NOTICE_E)) {
                        if (SAI_STATUS_SUCCESS != (sai_status = mlnx_switch_rearm_dfw(api_handle))) {
                            goto out;
                        }
                    }
                }
            }
        }
    }

out:
    SX_LOG_NTC("Closing DFW thread - %s.\n", SX_STATUS_MSG(status));

    if (SX_STATUS_SUCCESS != (status = sx_api_host_ifc_close(api_handle, &callback_channel.channel.fd))) {
        SX_LOG_ERR("host ifc close port fd failed - %s.\n", SX_STATUS_MSG(status));
    }

    if (SX_API_INVALID_HANDLE != api_handle) {
        if (SX_STATUS_SUCCESS != (status = sx_api_close(&api_handle))) {
            SX_LOG_ERR("API close failed.\n");
        }
    }

    if (NULL != p_packet) {
        free(p_packet);
    }

    if (NULL != receive_info) {
        free(receive_info);
    }
}


void switch_key_to_str(_In_ sai_object_id_t switch_id, _Out_ char *key_str)
{
    mlnx_object_id_t mlnx_switch_id = { 0 };
    sai_status_t     status;

    status = sai_to_mlnx_object_id(SAI_OBJECT_TYPE_SWITCH, switch_id, &mlnx_switch_id);
    if (SAI_ERR(status)) {
        snprintf(key_str, MAX_KEY_STR_LEN, "Invalid Switch ID");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "Switch ID %u", mlnx_switch_id.id.is_created);
    }
}


static sai_status_t mlnx_wait_for_sdk(const char *sdk_ready_var)
{
    const double time_unit = 0.001;

    while (0 != access(sdk_ready_var, F_OK)) {
#ifndef _WIN32
        usleep(time_unit);
#endif
    }

    return SAI_STATUS_SUCCESS;
}


mlnx_platform_type_t mlnx_platform_type_get(void)
{
    return g_sai_db_ptr->platform_type;
}


sai_status_t mlnx_sdk_start(mlnx_sai_boot_type_t boot_type)
{
    sai_status_t sai_status;
    int          system_err, cmd_len;
    char         sdk_start_cmd[SDK_START_CMD_STR_LEN] = {0};
    const char  *sniffer_var = NULL;
    const char  *sniffer_cmd = "";
    const char  *vlagrind_cmd = "";
    const char  *syslog_cmd = "";
    const char  *fastboot_cmd = "";
    const char  *sdk_ready_var = NULL;
    char         sdk_ready_cmd[SDK_START_CMD_STR_LEN] = {0};

    sdk_ready_var = getenv("SDK_READY_FILE");
    if (!sdk_ready_var || (0 == strcmp(sdk_ready_var, ""))) {
        sdk_ready_var = "/tmp/sdk_ready";
    }
    cmd_len = snprintf(sdk_ready_cmd,
                       SDK_START_CMD_STR_LEN,
                       "rm %s",
                       sdk_ready_var);
    assert(cmd_len < SDK_START_CMD_STR_LEN);

    system_err = system(sdk_ready_cmd);
    if (0 == system_err) {
        MLNX_SAI_LOG_DBG("%s removed\n", sdk_ready_var);
    } else {
        MLNX_SAI_LOG_DBG("unable to remove %s\n", sdk_ready_var);
    }

    sniffer_var = getenv("SX_SNIFFER_ENABLE");
    if (sniffer_var && (0 == strcmp(sniffer_var, "1"))) {
        sniffer_cmd = "LD_PRELOAD=\"libsxsniffer.so\"";
    }

#ifdef SDK_VALGRIND
    vlagrind_cmd = "valgrind --tool=memcheck --leak-check=full --error-exitcode=1 --undef-value-errors=no "
                   "--run-libc-freeres=yes --max-stackframe=15310736";
#endif
#ifdef CONFIG_SYSLOG
    syslog_cmd = "--logger libsai.so";
#endif
    if ((BOOT_TYPE_WARM == boot_type) || (BOOT_TYPE_FAST == boot_type)) {
        fastboot_cmd = "env FAST_BOOT=1";
    }

    cmd_len = snprintf(sdk_start_cmd,
                       SDK_START_CMD_STR_LEN,
                       "%s %s %s sx_sdk %s &",
                       sniffer_cmd,
                       vlagrind_cmd,
                       fastboot_cmd,
                       syslog_cmd);
    assert(cmd_len < SDK_START_CMD_STR_LEN);

    system_err = system(sdk_start_cmd);
    if (0 != system_err) {
        MLNX_SAI_LOG_ERR("Failed running sx_sdk\n");
        return SAI_STATUS_FAILURE;
    }

    sai_status = mlnx_wait_for_sdk(sdk_ready_var);
    assert(SAI_STATUS_SUCCESS == sai_status);

    return SAI_STATUS_SUCCESS;
}


sai_status_t sai_db_unload(boolean_t erase_db)
{
    int          err = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (erase_db == TRUE) {
        cl_shm_destroy(SAI_PATH);
        if (g_sai_db_ptr != NULL) {
            cl_plock_destroy(&g_sai_db_ptr->p_lock);
        }
    }

    if (g_sai_db_ptr != NULL) {
        err = munmap(g_sai_db_ptr, sizeof(*g_sai_db_ptr) + g_mlnx_shm_rm_size);
        if (err == -1) {
            SX_LOG_ERR("Failed to unmap the shared memory of the SAI DB\n");
            status = SAI_STATUS_FAILURE;
        }

        g_sai_db_ptr = NULL;
    }

    return status;
}


sai_status_t sai_db_create()
{
    int         err;
    int         shmid;
    cl_status_t cl_err;

    cl_err = cl_shm_create(SAI_PATH, &shmid);
    if (cl_err) {
        if (errno == EEXIST) { /* one retry is allowed */
            MLNX_SAI_LOG_ERR("Shared memory of the SAI already exists, destroying it and re-creating\n");
            cl_shm_destroy(SAI_PATH);
            cl_err = cl_shm_create(SAI_PATH, &shmid);
        }

        if (cl_err) {
            MLNX_SAI_LOG_ERR("Failed to create shared memory for SAI DB %s\n", strerror(errno));
            return SAI_STATUS_NO_MEMORY;
        }
    }

    g_mlnx_shm_rm_size = (uint32_t)mlnx_sai_rm_db_size_get();

    if (ftruncate(shmid, sizeof(*g_sai_db_ptr) + g_mlnx_shm_rm_size) == -1) {
        MLNX_SAI_LOG_ERR("Failed to set shared memory size for the SAI DB\n");
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    g_sai_db_ptr =
        mmap(NULL, sizeof(*g_sai_db_ptr) + g_mlnx_shm_rm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
    if (g_sai_db_ptr == MAP_FAILED) {
        MLNX_SAI_LOG_ERR("Failed to map the shared memory of the SAI DB\n");
        g_sai_db_ptr = NULL;
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    cl_err = cl_plock_init_pshared(&g_sai_db_ptr->p_lock);
    if (cl_err) {
        MLNX_SAI_LOG_ERR("Failed to initialize the SAI DB rwlock\n");
        err = munmap(g_sai_db_ptr, sizeof(*g_sai_db_ptr) + g_mlnx_shm_rm_size);
        if (err == -1) {
            MLNX_SAI_LOG_ERR("Failed to unmap the shared memory of the SAI DB\n");
        }
        g_sai_db_ptr = NULL;
        cl_shm_destroy(SAI_PATH);
        return SAI_STATUS_NO_MEMORY;
    }

    return SAI_STATUS_SUCCESS;
}


#ifndef _WIN32

sai_status_t parse_elements(xmlDoc *doc, xmlNode * a_node)
{
    xmlNode       *cur_node, *ports_node;
    xmlChar       *key;
    sai_status_t   status;
    sx_mac_addr_t *base_mac_addr;
    const char    *profile_mac_address;

    /* parse all siblings of current element */
    for (cur_node = a_node; cur_node != NULL; cur_node = cur_node->next) {
        if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"platform_info"))) {
            key = xmlGetProp(cur_node, (const xmlChar*)"type");
            if (!key) {
                MLNX_SAI_LOG_ERR("Failed to parse platform xml config: platform_info type is not specified\n");
                return SAI_STATUS_FAILURE;
            }

            status = mlnx_config_platform_parse((const char*)key);
            if (SAI_ERR(status)) {
                xmlFree(key);
                return SAI_STATUS_FAILURE;
            }
            xmlFree(key);
            return parse_elements(doc, cur_node->children);
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"device-mac-address"))) {
            profile_mac_address = g_mlnx_services.profile_get_value(g_profile_id, KV_DEVICE_MAC_ADDRESS);
            if (NULL == profile_mac_address) {
                key = xmlNodeListGetString(doc, cur_node->children, 1);
                MLNX_SAI_LOG_NTC("mac: %s\n", key);
                base_mac_addr = ether_aton_r((const char*)key, &g_sai_db_ptr->base_mac_addr);
                strncpy(g_sai_db_ptr->dev_mac, (const char*)key, sizeof(g_sai_db_ptr->dev_mac));
                g_sai_db_ptr->dev_mac[sizeof(g_sai_db_ptr->dev_mac) - 1] = 0;
                xmlFree(key);
            } else {
                MLNX_SAI_LOG_NTC("mac k/v: %s\n", profile_mac_address);
                base_mac_addr = ether_aton_r(profile_mac_address, &g_sai_db_ptr->base_mac_addr);
                strncpy(g_sai_db_ptr->dev_mac, profile_mac_address, sizeof(g_sai_db_ptr->dev_mac));
                g_sai_db_ptr->dev_mac[sizeof(g_sai_db_ptr->dev_mac) - 1] = 0;
            }
            if (base_mac_addr == NULL) {
                MLNX_SAI_LOG_ERR("Error parsing device mac address\n");
                return SAI_STATUS_FAILURE;
            }
            if (base_mac_addr->ether_addr_octet[5] & (~mlnx_port_mac_mask_get())) {
                MLNX_SAI_LOG_ERR("Device mac address must be aligned by %u %02x\n",
                                 mlnx_port_mac_mask_get(), base_mac_addr->ether_addr_octet[5]);
                return SAI_STATUS_FAILURE;
            }
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"number-of-physical-ports"))) {
            key = xmlNodeListGetString(doc, cur_node->children, 1);
            g_sai_db_ptr->ports_number = (uint32_t)atoi((const char*)key);
            MLNX_SAI_LOG_NTC("ports num: %u\n", g_sai_db_ptr->ports_number);
            xmlFree(key);
            if (g_sai_db_ptr->ports_number > MAX_PORTS) {
                MLNX_SAI_LOG_ERR("Ports number %u bigger then max %u\n", g_sai_db_ptr->ports_number, MAX_PORTS);
                return SAI_STATUS_FAILURE;
            }
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"ports-list"))) {
            for (ports_node = cur_node->children; ports_node != NULL; ports_node = ports_node->next) {
                if ((!xmlStrcmp(ports_node->name, (const xmlChar*)"port-info"))) {
                    if (SAI_STATUS_SUCCESS != (status = parse_port_info(doc, ports_node->children))) {
                        return status;
                    }
                }
            }
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"issu-enabled"))) {
            key = xmlNodeListGetString(doc, cur_node->children, 1);
            g_sai_db_ptr->issu_enabled = (uint32_t)atoi((const char*)key);
            MLNX_SAI_LOG_NTC("issu enabled: %u\n", g_sai_db_ptr->issu_enabled);
            /* divide ACL resources by half for FFB */
            g_sai_db_ptr->acl_divider = g_sai_db_ptr->issu_enabled ? 2 : 1;
            xmlFree(key);
        } else if ((!xmlStrcmp(cur_node->name, (const xmlChar*)"pbhash_gre"))) {
            key = xmlNodeListGetString(doc, cur_node->children, 1);
            g_sai_db_ptr->pbhash_gre = (uint32_t)atoi((const char*)key);
            MLNX_SAI_LOG_NTC("policy based hash enabled, GRE: %u\n", g_sai_db_ptr->pbhash_gre);
            xmlFree(key);
        } else {
            /* parse all children of current element */
            if (SAI_STATUS_SUCCESS != (status = parse_elements(doc, cur_node->children))) {
                return status;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t mlnx_parse_config(const char *config_file)
{
    xmlDoc      *doc = NULL;
    xmlNode     *root_element = NULL;
    sai_status_t status;

    LIBXML_TEST_VERSION;

    doc = xmlReadFile(config_file, NULL, 0);

    if (doc == NULL) {
        MLNX_SAI_LOG_ERR("could not parse config file %s\n", config_file);
        return SAI_STATUS_FAILURE;
    }

    root_element = xmlDocGetRootElement(doc);

    sai_db_write_lock();

    MLNX_SAI_LOG_NTC("Loading port map from %s ...\n", config_file);

    status = parse_elements(doc, root_element);

    if (g_sai_db_ptr->ports_configured != g_sai_db_ptr->ports_number) {
        MLNX_SAI_LOG_ERR("mismatch of port number and configuration %u %u\n",
                         g_sai_db_ptr->ports_configured, g_sai_db_ptr->ports_number);
        status = SAI_STATUS_FAILURE;
    }

    if (g_sai_db_ptr->platform_type == MLNX_PLATFORM_TYPE_INVALID) {
        MLNX_SAI_LOG_ERR("g_sai_db_ptr->platform_type (<platform_info> type in XML config) is not initialized\n");
        status = SAI_STATUS_FAILURE;
    }

    msync(g_sai_db_ptr, sizeof(*g_sai_db_ptr), MS_SYNC);
    sai_db_unlock();

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return status;
}
#else /* ifndef _WIN32 */
sai_status_t mlnx_parse_config(const char *config_file)
{
    UNUSED_PARAM(config_file);
    return SAI_STATUS_SUCCESS;
}
#endif /* ifndef _WIN32 */

sai_status_t mlnx_switch_common_log_set(sx_verbosity_level_t level)
{
    LOG_VAR_NAME(__MODULE__) = level;
    return SAI_STATUS_SUCCESS;
}


sai_status_t mlnx_sai_rm_initialize(const char *config_file)
{
    sai_status_t     status;
    sxd_chip_types_t chip_type;
    sx_chip_types_t  sx_chip_type;

    status = get_chip_type(&chip_type);
    if (SX_ERR(status)) {
        SX_LOG_ERR("get_chip_type failed\n");
        return SAI_STATUS_FAILURE;
    }
    sx_chip_type = convert_chip_sxd_to_sx(chip_type);

    MLNX_SAI_LOG_DBG("Chip type - %s\n", SX_CHIP_TYPE_STR(sx_chip_type));

    status = rm_chip_limits_get(sx_chip_type, &g_resource_limits);
    if (SX_ERR(status)) {
        MLNX_SAI_LOG_ERR("Failed to get chip resources - %s.\n", SX_STATUS_MSG(status));
        return sdk_to_sai(status);
    }

    status = mlnx_sai_db_initialize(config_file, sx_chip_type);
    if (SAI_ERR(status)) {
        return status;
    }

    status = mlnx_cb_table_init();
    if (SAI_ERR(status)) {
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sx_chip_types_t convert_chip_sxd_to_sx(sxd_chip_types_t chip_type)
{
    switch (chip_type) {
    case (SXD_CHIP_TYPE_QUANTUM):
        return SX_CHIP_TYPE_QUANTUM;

    case (SXD_CHIP_TYPE_QUANTUM2):
        return SX_CHIP_TYPE_QUANTUM2;

    case (SXD_CHIP_TYPE_QUANTUM3):
        return SX_CHIP_TYPE_QUANTUM3;

    default:
        MLNX_SAI_LOG_ERR("Chip type is not supported by SAI\n");
        return SX_CHIP_TYPE_UNKNOWN;
    }
}
