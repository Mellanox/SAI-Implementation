#ifndef FLEXSDK_H
#define FLEXSDK_H

#include "flextrum_types.h"
#include "fx_base_api.h"
#ifdef __cplusplus
extern "C"{
#endif


typedef int (*init_flex_api_fn) (fx_handle_t *handle);
typedef int (*deinit_flex_api_fn)(fx_handle_t handle);
typedef int (*init_extern_fn) ();
typedef int (*deinit_extern_fn) ();
typedef void (*show_flex_api_fn) ();

typedef int (*init_pipe_fn) (uint16_t* in_ports, uint16_t in_port_count, uint16_t* in_rifs, uint16_t in_rif_count, uint16_t* out_ports, uint16_t out_port_count, uint16_t* out_rifs, uint16_t out_rif_count);
typedef int (*deinit_pipe_fn) (uint16_t* in_ports, uint16_t in_port_count, uint16_t* in_rifs, uint16_t in_rif_count, uint16_t* out_ports, uint16_t out_port_count, uint16_t* out_rifs, uint16_t out_rif_count);
typedef int (*create_pipe_fn) (uint16_t* ports, uint16_t port_count);
typedef int (*delete_pipe_fn) (uint16_t* ports, uint16_t port_count);
typedef int (*add_table_entry_fn) (void** keys,void** masks,void** params,fx_action_id_t action, sx_acl_rule_offset_t* offset_ptr); // TODO add const to all types
typedef int (*remove_table_entry_fn) (sx_acl_rule_offset_t offset);
typedef int (*add_table_range_entry_fn) (uint32_t start,uint32_t end, uint8_t action_id, uint8_t* range_rule_handle);
typedef int (*remove_table_range_entry_fn) (uint8_t range_rule_handle);
typedef int (*read_rule_counters_fn) ();
typedef int (*clear_rule_counters_fn) ();
#ifdef __cplusplus
}
#endif

#endif
