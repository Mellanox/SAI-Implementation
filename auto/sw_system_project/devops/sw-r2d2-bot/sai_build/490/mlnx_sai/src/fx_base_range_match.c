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

#include <stdio.h>  
#include <stdlib.h>
#include "fx_base_range_match.h"

#undef __MODULE__
#define __MODULE__ FXAPI_RANGE
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define FX_LOG(L, FMT, ...)                                                         \
    do {                                                                            \
        SX_LOG(L, "[%s] %s:%i: " FMT, __FILE__, __func__,__LINE__, ## __VA_ARGS__); \
    } while (0)

//#include <fx_base_api.h>

/**
* @brief Flex range func for internal use. will devide each comperator to a series of tcam rules.
* In general, each bigger (smaller) comperator costs the number of '0' ('1') in the binary representation of the coperator value.
*
* TODO add polarity (comperator for bigger/smaller then).
*/

/**
*@brief This file describes and implements the functions needed for range match implementation
*/

void print_bits(uint32_t x,uint32_t n)
{
    int i;
    for(i=n-1; i>=0; i--) {
        (x & (1 << i)) ? putchar('1') : putchar('0');
    }
}

void print_bits_w_mask(uint32_t x,uint32_t m)
{
    int i;
    for(i=8*sizeof(x)-1; i>=0; i--) {
    	((m & (1 << i))==0) ? putchar('*') :
        (x & (1 << i)) ? putchar('1') : putchar('0');
    }
}

uint8_t fx_count_set_bits(uint32_t n){
	uint8_t count = 0;
	while (n){
	count += n & 1;
	n >>= 1;
	}
	return count;
}


/** @brief counts how many rules it will take to implement the range rules for all rules in the linked list */
uint32_t fx_range_count_acl_rules(fx_comperator_ll_node_t* comperator_ll_node){
	uint32_t rule_count=0;
	while(comperator_ll_node != NULL){
		FX_LOG(SX_LOG_INFO, "Rule_count, com value %u, acl rules count %u \n", comperator_ll_node->comparison_value ,comperator_ll_node->num_of_acl_rules);
		rule_count += comperator_ll_node->num_of_acl_rules;
		comperator_ll_node = comperator_ll_node->next;
	}
	return rule_count;
}



/** @brief creates a new node in the comperator link list and configures all needed ASIC rules for it.
* return NULL upon unsuccessful operation.
*/
fx_comperator_ll_node_t* fx_range_cfg_comperator(uint32_t comperator_value, uint32_t num_of_range_rules, uint16_t action_bitvec, fx_comperator_ll_node_t* next){
	//TODO protect malloc
	// TODO return sx_status. it's ugly now!!
	fx_comperator_ll_node_t* node = (fx_comperator_ll_node_t*) malloc (sizeof(fx_comperator_ll_node_t));
	if (node == NULL){
		FX_LOG(SX_LOG_ERROR, "fx_range_cfg_comperator cannot create new ll node, returning.\n");
		return node;
	} 
	node->comparison_value = comperator_value;
	node->num_of_range_rules = num_of_range_rules;
	node->action_bitvec = action_bitvec;
	node->next = next;

	// TODO ugly:
	switch(comperator_value){
		case 0:
			node->num_of_acl_rules = 0; break;
		case -1:
			node->num_of_acl_rules = 1; break;
		default:
			node->num_of_acl_rules = fx_count_set_bits(comperator_value);
	}
	return node;
}

/** @brief recursive delete link list from given node */
void fx_range_delete_ll(fx_comperator_ll_node_t** node){
	if(*node==NULL) {
		/* FX_LOG(SX_LOG_ERROR, "node is NULL\n"); */
		return;
	}
	fx_range_delete_ll(&(*node)->next);
	FX_LOG(SX_LOG_INFO, "Deleting ll node value: %u, num_of_acl_rules: %u.\n",(*node)->comparison_value,(*node)->num_of_acl_rules);
	free(*node);
	*node = NULL;
	return;
}

/** @brief backup range link list
*/
sx_status_t fx_range_copy_ll(fx_comperator_ll_node_t* orig_node, fx_comperator_ll_node_t** copy_node){
	if (orig_node==NULL){
		FX_LOG(SX_LOG_INFO, "ll end, deleting backup ll end.\n");
		fx_range_delete_ll(copy_node); 
		return SX_STATUS_SUCCESS;
	}
	else if (*copy_node == NULL){
		FX_LOG(SX_LOG_INFO, "Creating new node, value: %u.\n", orig_node->comparison_value);
		*copy_node = fx_range_cfg_comperator(orig_node->comparison_value,orig_node->num_of_range_rules,orig_node->action_bitvec,NULL);
		if (!*copy_node) {
			FX_LOG(SX_LOG_ERROR, "Failed to allocate memroy for new node\n");
			return (SX_STATUS_NO_MEMORY);
		}
		return fx_range_copy_ll(orig_node->next,&(*copy_node)->next);
	}
	else{
		FX_LOG(SX_LOG_INFO, "Modifing exsiting node, value: %u.\n", orig_node->comparison_value);
		(*copy_node)->comparison_value   = orig_node->comparison_value ;
		(*copy_node)->num_of_range_rules = orig_node->num_of_range_rules;
		(*copy_node)->num_of_acl_rules   = orig_node->num_of_acl_rules;
		(*copy_node)->action_bitvec     = orig_node->action_bitvec;
		return fx_range_copy_ll(orig_node->next,&(*copy_node)->next);
	}
}


/** @ brief sets all relevant action vector bits in each linked list node according the tables range rules and thier action id's */
void fx_range_update_action_bitvec(fx_range_table_t* range_table){
	// TODO can save time by updating a single rule entry at a time.

	// clear all action bitvec
	fx_comperator_ll_node_t* ll_node = range_table->comperator_ll_start;
	while (ll_node != NULL){
		ll_node->action_bitvec = 0;
		ll_node = ll_node->next;			
	}

	// set bit in bitvect for each comperator in range bounds.
	fx_range_action_id_t range_action_id;
	uint32_t range_start;
	uint32_t range_end;
	for (uint8_t i=0; i<MAX_RANGE_ENTRIES ; i++){
		FX_LOG(SX_LOG_INFO, "Rule %u\n.",i);
		ll_node = range_table->comperator_ll_start;
		range_action_id =	range_table->range_entries_list[i].action_id;
		range_start	 = 	range_table->range_entries_list[i].start;
		range_end 	 = 	range_table->range_entries_list[i].end;
		if (range_table->range_entries_list[i].valid){
			while (ll_node != NULL){
				if ( (ll_node->comparison_value > range_start) &&
					 (ll_node->comparison_value <=  range_end)){
					ll_node->action_bitvec |=  (1<<range_action_id); // set bit
				}
				ll_node = ll_node->next;
			}
		}
	}
}

/** @brief creates needed {keys,masks} for all acl rules needed to implement a comperator
* Example smaller than 4'b1011, acl match are  {0xxx , 100x , 1010}
*/
void fx_get_range_key_mask(uint32_t comperator_value, fx_key_list_t keys[], uint32_t rule_offset){
    for (int bit_indx = 31; bit_indx>=0; bit_indx--) {
        if (comperator_value & (1<<bit_indx)){
            keys[rule_offset].keys[0].key.len = 4; //TODO: should be taken from p4
            keys[rule_offset].keys[0].mask.len = 4; //TODO: should be taken from p4
            uint32_t key_value = (comperator_value ^ (1<<(bit_indx)));
            uint32_t mask_value = (0xffffffff << bit_indx);
            memcpy(keys[rule_offset].keys[0].key.data, &key_value, keys[rule_offset].keys[0].key.len); // current bit becomes 0
            memcpy(keys[rule_offset].keys[0].mask.data, &mask_value, keys[rule_offset].keys[0].mask.len); // all zeros after current bit
            rule_offset+=1;
        }
    }
}


/** @brief recursively scans linked list and if needed adds node for new copmerator. if comerator exsits, the function increase the node range rules count by 1.
*/
sx_status_t fx_range_add_comperator(fx_range_table_t* range_table, uint32_t comparison_value){
	// handle head change or empty list: (should never get here if default entry is set);

	if( (range_table->comperator_ll_start == NULL) || (range_table->comperator_ll_start->comparison_value > comparison_value)){
		FX_LOG(SX_LOG_INFO, "Changing head.\n");
		fx_comperator_ll_node_t* new_node = fx_range_cfg_comperator(comparison_value, 1, 0 , range_table->comperator_ll_start);
		if (new_node == NULL){
			return SX_STATUS_NO_MEMORY;
		}
		else{
			range_table->comperator_ll_start = new_node;
			return SX_STATUS_SUCCESS;
		}
	}
	else if (range_table->comperator_ll_start->comparison_value == comparison_value){
		range_table->comperator_ll_start->num_of_range_rules += 1;
		return SX_STATUS_SUCCESS;
	}

	fx_comperator_ll_node_t* next = range_table->comperator_ll_start->next;
	fx_comperator_ll_node_t* current = range_table->comperator_ll_start;

	while (next != NULL){
		// Desired value exsists.
		if (next->comparison_value == comparison_value) {
			FX_LOG(SX_LOG_INFO, "Comparison value exsits. not adding new comperator.\n");
			next->num_of_range_rules += 1;
			return SX_STATUS_SUCCESS;
		}
		// add new node before node
		else if (next->comparison_value > comparison_value) {
			FX_LOG(SX_LOG_INFO, "Adding new comperator before comperator %u.\n",next->comparison_value);
			fx_comperator_ll_node_t* new_node = fx_range_cfg_comperator(comparison_value, 1, 0 , next);
			if(new_node==NULL){
				return SX_STATUS_NO_MEMORY;
			}
			else{
				current->next = new_node;
				FX_LOG(SX_LOG_INFO, "Done.\n");
				return SX_STATUS_SUCCESS;
			}
		}
		current = current->next;
		next = next->next;
	}
	// add in list end
	FX_LOG(SX_LOG_ERROR, "Adding compertor in list end. NO DEFAULT VALUE???.\n");
	current->next = fx_range_cfg_comperator(comparison_value, 1, 0 , NULL);
	if(current->next==NULL){
		return SX_STATUS_NO_MEMORY;
	}
	else{
		FX_LOG(SX_LOG_INFO, "Done.\n");
		return SX_STATUS_SUCCESS;
	}
}

/** @brief scans linked list and reduces the node's range rules count by 1. if count reached 0, the function deletes comperator node
*/
sx_status_t fx_range_remove_comperator(fx_range_table_t* range_table, uint32_t comparison_value){
	// reduce nume_of_range_rules from node by 1. if num == 0 remove node.

	fx_comperator_ll_node_t* current = range_table->comperator_ll_start;
	if ((current == NULL) || (current->comparison_value>comparison_value)){
		FX_LOG(SX_LOG_ERROR, "Value not found, node value %u\n",current?current->comparison_value:0);
		return SX_STATUS_PARAM_ERROR;
	}
	fx_comperator_ll_node_t* next = range_table->comperator_ll_start->next;
	if(current->comparison_value==comparison_value){
		// remove ll head
		FX_LOG(SX_LOG_INFO, "Removing from ll head\n");
		current->num_of_range_rules -= 1;
		if(current->num_of_range_rules == 0){
			range_table->comperator_ll_start = next;
			free(current);
		}
		return SX_STATUS_SUCCESS;
	}

	while (current->comparison_value <= comparison_value){
		// end of ll or ll is empty
		if ((next == NULL) || (next->comparison_value > comparison_value)){
			FX_LOG(SX_LOG_INFO, "Value not found\n");
			return SX_STATUS_PARAM_ERROR;
		}
		// Desired value exsists.
		else if (next->comparison_value == comparison_value) {
			next->num_of_range_rules -= 1;
			if(next->num_of_range_rules == 0){
				FX_LOG(SX_LOG_INFO, "%u, num of range rules is 0\n.",next->comparison_value);
				current->next = next->next;
				free(next);
			}
			return SX_STATUS_SUCCESS;
		}
		else { //(node->comparison_value < comparison_value){
			FX_LOG(SX_LOG_INFO, "Node value %u, continue to next node\n",current->comparison_value);
			current = next;
			next = next->next;
		}
	}
	// shoud not reach here
	FX_LOG(SX_LOG_ERROR, "In search, comparison value: %u\n",comparison_value);
	return SX_STATUS_ERROR;
}

uint32_t fx_range_get_rules_list_count(fx_range_table_t* range_table){
	// TODO if we count on default entry, we can use only new list length.
	uint32_t rule_list_len_old = fx_range_count_acl_rules(range_table->backup_comperator_ll_start);
	uint32_t rule_list_len_new = fx_range_count_acl_rules(range_table->comperator_ll_start);
	return (rule_list_len_old > rule_list_len_new) ? rule_list_len_old : rule_list_len_new ;	
}


/* @brief */
sx_status_t fx_range_compile_rules(fx_range_table_t* range_table, fx_key_list_t keys[],fx_param_list_t action_params[], sx_acl_rule_offset_t offsets_list[],uint32_t rule_cnt){
	// currently replace ALL rules!! TODO make more efficient
	// check current amount of valid rules
	uint32_t rule_list_len_old = fx_range_count_acl_rules(range_table->backup_comperator_ll_start);
	uint32_t rule_list_len_new = fx_range_count_acl_rules(range_table->comperator_ll_start);
	FX_LOG(SX_LOG_DEBUG, "Rules count: old: %u. new: %u\n",rule_list_len_old,rule_list_len_new);
	uint32_t rule_list_len = (rule_list_len_old > rule_list_len_new) ? rule_list_len_old : rule_list_len_new ;
	if (rule_cnt != rule_list_len){
		FX_LOG(SX_LOG_ERROR, "rules_list size mismatch, %d : %d\n",rule_cnt,rule_list_len ); // TODO maybe malloc the keys and rules here?
		return SX_STATUS_NO_MEMORY;
	}
	FX_LOG(SX_LOG_INFO, "Num of new rules: %u\n",rule_list_len_new);

	/* if  number of ASIC rules > number of new rules, add non valid rules at the end. TODO: can just add default rule in the end!!!*/
	// if (rule_list_len_old > rule_list_len_new){
	// 	for (uint32_t offset=rule_list_len_new ; offset<rule_list_len_old ; offset++){
	// 		rules_list[offset].valid=0;
	// 	}	
	// }

	// create rules list from link list
	uint32_t offset =0;
	fx_comperator_ll_node_t* node = range_table->comperator_ll_start;

	while(node !=NULL){
		FX_LOG(SX_LOG_INFO, "Creating key,mask for value: %u\n",node->comparison_value);
		if(node->comparison_value != -1){
			fx_get_range_key_mask(node->comparison_value, keys, offset);
		}
		else{
			memset(keys[offset].keys[0].key.data, 0, keys[offset].keys[0].key.len);
			memset(keys[offset].keys[0].mask.data, 0, keys[offset].keys[0].mask.len);
		}
		// TODO pref: can do without copying.
		for (uint32_t i = offset; i<(offset+node->num_of_acl_rules);i++){
			FX_LOG(SX_LOG_INFO, "Adding range %u, comp_rule %u, action_bitvec %u\n",i,i-offset,node->action_bitvec);
			action_params[i].params[0].data = (uint8_t*) &node->action_bitvec;
			action_params[i].params[0].len = 2;
			offsets_list[i] = i;
		}
		offset += node->num_of_acl_rules;
		node = node->next;
	}
	FX_LOG(SX_LOG_INFO, "Created rules list.\n");
	return(SX_STATUS_SUCCESS);
	// return 0;
}

sx_status_t fx_add_range_entry(fx_range_table_t* range_table,uint32_t start,uint32_t end, fx_range_action_id_t action_id,sx_acl_rule_offset_t* range_entry_handle){
	// find avaliable range index (TODO if range entry == action_id, can use action id as index)
	// range_entry_handle = (uint8_t*) malloc(sizeof(uint8_t));
	// if(*range_entry_handle==NULL){ return SX_STATUS_NO_MEMORY;}
	sx_status_t rc;
	for (uint8_t i=0; i<MAX_RANGE_ENTRIES ; i++){
		if (range_table->range_entries_list[i].valid)
			continue;
		else{
			*range_entry_handle = i;
			FX_LOG(SX_LOG_INFO, "Add range entry, using handle %d, %u.\n",i, *range_entry_handle);
			range_table->range_entries_list[i].start=start;
			range_table->range_entries_list[i].end = end;
			range_table->range_entries_list[i].action_id = action_id;
			if (start!=0){
				rc = fx_range_add_comperator(range_table,start);
				if (rc) {
					//revert comperators link list
					FX_LOG(SX_LOG_ERROR, "Using backup rules. new range was not added.\n");
					fx_range_copy_ll(range_table->backup_comperator_ll_start, &range_table->comperator_ll_start);
					return (rc);
				}
			}
			sx_status_t rc = fx_range_add_comperator(range_table,end);
			if (rc) {
				//revert comperators link list
				FX_LOG(SX_LOG_ERROR, "Using backup rules. new range was not added.\n");
				fx_range_copy_ll(range_table->backup_comperator_ll_start, &range_table->comperator_ll_start);
				return (rc);
			}

			range_table->range_entries_list[i].valid=true;
			fx_range_update_action_bitvec(range_table);
			//backup ll
			fx_range_copy_ll(range_table->comperator_ll_start, &range_table->backup_comperator_ll_start);
			return SX_STATUS_SUCCESS;
		}
	}
	// no avaliable range entry.
	FX_LOG(SX_LOG_ERROR, "No more range rules avaliable\n");
	return SX_STATUS_NO_MEMORY; //no more avaliable entries (TODO currently limited to 12 entries)
}

sx_status_t fx_remove_range_entry(fx_range_table_t* range_table,sx_acl_rule_offset_t range_entry_handle){
	if(!range_table->range_entries_list[range_entry_handle].valid){
		FX_LOG(SX_LOG_ERROR, "Requested to remove invalid entry\n");
		return SX_STATUS_PARAM_ERROR;
	}
	uint32_t start = range_table->range_entries_list[range_entry_handle].start;
	uint32_t end = range_table->range_entries_list[range_entry_handle].end;
	sx_status_t rc;
	if (start!=0){
		rc = fx_range_remove_comperator(range_table,start);
		if (rc) {
			//revert comperators link list
			FX_LOG(SX_LOG_ERROR, "Using backup rules. range was not removed.\n");
			fx_range_copy_ll(range_table->backup_comperator_ll_start, &range_table->comperator_ll_start);
			return (rc);
		}
	}
	rc = fx_range_remove_comperator(range_table,end);
	if (rc) {
		//revert comperators link list
		FX_LOG(SX_LOG_ERROR, "Using backup rules. range was not removed.\n");
		fx_range_copy_ll(range_table->backup_comperator_ll_start, &range_table->comperator_ll_start);
		return (rc);
	}
	FX_LOG(SX_LOG_INFO, "Removed 2 comperators.\n");
	range_table->range_entries_list[range_entry_handle].valid = 0;
	fx_range_update_action_bitvec(range_table);
			
	//creates rule list and replaces the ASIC rules.
	//rc = fx_range_insert_range_rules(range_table);

	//backup ll
	fx_range_copy_ll(range_table->comperator_ll_start, &range_table->backup_comperator_ll_start);
	return SX_STATUS_SUCCESS;
}


/** @brief initialize needed structs for table with range match*/
sx_status_t fx_range_init_table(fx_range_table_t** range_table){
	(*range_table) = malloc(sizeof(fx_range_table_t));
	if ((*range_table) == NULL){
		FX_LOG(SX_LOG_ERROR, "No memory to create key list\n");
	return SX_STATUS_NO_MEMORY;
	} 
	// TODO - add comerator instead? create default rule with default action (12'd0)
	(*range_table)->comperator_ll_start= fx_range_cfg_comperator(-1, 1, 0 , NULL);
	(*range_table)->backup_comperator_ll_start=NULL;
	for (uint8_t i=0; i<MAX_RANGE_ENTRIES ; i++)
		(*range_table)->range_entries_list[i].valid = false;
	return (SX_STATUS_SUCCESS);
}

/** @brief deinitialize structs for table with range match*/
sx_status_t fx_range_deinit_table(fx_range_table_t* range_table){
	// TODO - add comerator instead? create default rule with default action (12'd0)
	for (uint8_t i=0; i<MAX_RANGE_ENTRIES ; i++){
		if (range_table->range_entries_list[i].valid ){
			fx_remove_range_entry(range_table,i);
		}
	}

	fx_range_delete_ll(&range_table->backup_comperator_ll_start);
	fx_range_delete_ll(&range_table->comperator_ll_start);
	free(range_table);
	return (SX_STATUS_SUCCESS);
}
