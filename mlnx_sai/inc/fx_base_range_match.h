/*
* fx_base_range_match.h
*
* Defines Struct and functionality of Range match for a given table.
* Each range has id, user can later match on the id of each range to set costum action.
*
* Currently device support : Spectrum
*
*/ 

#ifndef _FX_BASE_RANGE_MATCH_H_
#define _FX_BASE_RANGE_MATCH_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "fx_base_api.h"
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
 
#ifdef __cplusplus
extern "C"{
#endif


#define BITVEC_LEN 12
#define MAX_RANGE_ENTRIES 12 // The maximal number of supported range entries - currenly 12 (limited by action ids, TODO can be more for multi range with same action)
#define RANGE_WDT 32 // 32 bit is the maximal range type supported


typedef uint8_t fx_range_action_id_t; // in [0,11] - the bit in the metadata that will be set upon range match

typedef struct fx_comperator_ll_node_t{
	uint32_t comparison_value; // the value for the range cut. Currentl only samller then is implemented.
	uint8_t  num_of_acl_rules; // number of acl rules needed to implement the comperator.
	uint32_t num_of_range_rules; // number of range rules that uses this comperator. if 0, node can be deleted.
	uint16_t action_bitvec;	// bit vector values that will be set if  key is between this node comparison value and the next node.
	struct fx_comperator_ll_node_t* next;
} fx_comperator_ll_node_t;

typedef struct fx_range_entry_t{
	uint32_t start;
	uint32_t end;
	fx_range_action_id_t action_id;
	// uint32_t acl_start_offset; // for counters
	// uint32_t acl_end_offset; // for counters
	boolean_t valid;
}fx_range_entry_t;

typedef struct fx_range_table_t {
	// TODO add default action? currently 12'd0.
	fx_comperator_ll_node_t* comperator_ll_start;
	fx_comperator_ll_node_t* backup_comperator_ll_start; // each range change/add/remove that will fail, will use this list to revert configuration.
	fx_range_entry_t range_entries_list[MAX_RANGE_ENTRIES];
}fx_range_table_t;



/* internal use functions */
void print_bits(uint32_t x,uint32_t n);
void print_bits_w_mask(uint32_t x,uint32_t m);
uint8_t fx_count_set_bits(uint32_t n);
uint32_t fx_range_count_acl_rules(fx_comperator_ll_node_t* comperator_ll_node);
fx_comperator_ll_node_t* fx_range_cfg_comperator(uint32_t comperator_value, uint32_t num_of_range_rules, uint16_t action_bitvec, fx_comperator_ll_node_t* next);
void fx_range_delete_ll(fx_comperator_ll_node_t** node);
sx_status_t fx_range_copy_ll(fx_comperator_ll_node_t* orig_node, fx_comperator_ll_node_t** copy_node);
void fx_range_update_action_bitvec(fx_range_table_t* range_table);
void fx_get_key_mask_recursive(uint32_t comperator_value, uint8_t bit_indx, uint8_t rule_indx,uint32_t* acl_key_list, uint32_t* acl_mask_list);
sx_status_t fx_range_add_comperator(fx_range_table_t* range_table, uint32_t comparison_value);
sx_status_t fx_range_remove_comperator(fx_range_table_t* range_table, uint32_t comparison_value);
uint32_t fx_range_get_rules_list_count(fx_range_table_t* range_table);
sx_status_t fx_range_compile_rules(fx_range_table_t* range_table, fx_key_list_t keys[],fx_param_list_t action_params[], sx_acl_rule_offset_t offsets_list[],uint32_t rule_cnt);
sx_status_t fx_range_init_table(fx_range_table_t** range_table);
sx_status_t fx_add_range_entry(fx_range_table_t* range_table, uint32_t start,uint32_t end, fx_range_action_id_t action_id,sx_acl_rule_offset_t* range_entry_handle);
sx_status_t fx_remove_range_entry(fx_range_table_t* range_table, sx_acl_rule_offset_t range_entry_handle);
sx_status_t fx_range_deinit_table(fx_range_table_t* range_table);

//----------------------DEBUG TEMP--------------------

// // debug function
// void print_bits(uint32_t x,uint32_t n);

// void print_bits_w_mask(uint32_t x,uint32_t m);

// typedef struct sx_flex_acl_flex_rule_t{
// 	uint8_t 	valid;
// 	uint32_t	key;
// 	uint32_t	mask;
// 	uint32_t	action;
// }sx_flex_acl_flex_rule_t;

// sx_status_t sx_api_acl_flex_rules_set(
// 		const int 	handle,
// 		const int 	cmd,
// 		const int 	region_id,
// 		uint32_t * 	offsets_list_p,
// 		const sx_flex_acl_flex_rule_t * 	rules_list_p,
// 		const uint32_t 	rules_cnt 
// 		);

//----------------------------------------------
#ifdef __cplusplus
}
#endif

#endif //_FX_BASE_RANGE_MATCH_H_
