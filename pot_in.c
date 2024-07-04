/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 *------------------------------------------------------------------
 * pot_in.c - SRv6 Masquerading Proxy (pot_in) function
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6_pot_in/pot_in.h>
#include <vnet/fib/ip6_fib.h>

unsigned char function_name[] = "SRv6-pot_in-plugin";
unsigned char keyword_str[] = "End.pot_in";
unsigned char def_str[] = "Endpoint to perform Proof Of Transit over SRv6 Network";
unsigned char params_str[] = "nh <next-hop> oif <iface-out> iif <iface-in>"; // CLI command

srv6_pot_in_main_t srv6_pot_in_main;

dpo_type_t srv6_pot_in_dpo_type; 

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int srv6_pot_in_localsid_creation_fn (ip6_sr_localsid_t * localsid) {

  // ---- PRINT ---- // 
  FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
  fprintf(file, ">> srv6_pot_in_localsid_creation_fn <<\n --------------------- \n");  
  fclose(file); 
  //

  srv6_pot_in_main_t *sm = &srv6_pot_in_main;
  srv6_pot_in_localsid_t *ls_mem = localsid->plugin_mem;
  adj_index_t nh_adj_index = ADJ_INDEX_INVALID;

  /* Step 1: Prepare xconnect adjacency for sending packets to the VNF */

  /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
  nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6,
				      VNET_LINK_IP6, &ls_mem->nh_addr,
				      ls_mem->sw_if_index_out);
  if (nh_adj_index == ADJ_INDEX_INVALID)
    return -5;

  localsid->nh_adj = nh_adj_index;


  /* Step 2: Prepare inbound policy for packets returning from the VNF */

  /* Sanitise the SW_IF_INDEX */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  ls_mem->sw_if_index_in))
    return -3;

  vnet_sw_interface_t *sw = vnet_get_sw_interface (sm->vnet_main,
						   ls_mem->sw_if_index_in);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return -3;

  int ret = vnet_feature_enable_disable ("ip6-unicast", "srv6-pot_in",
					 ls_mem->sw_if_index_in, 1, 0, 0);
  if (ret != 0)
    return -1;

  return 0;
}

static int srv6_pot_in_localsid_removal_fn (ip6_sr_localsid_t * localsid) {

  // ---- PRINT ---- // 
  FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
  fprintf(file, ">> srv6_pot_in_localsid_removal_fn <<\n --------------------- \n");  
  fclose(file); 
  //

  srv6_pot_in_localsid_t *ls_mem = localsid->plugin_mem;

  /* Remove hardware indirection (from sr_steering.c:137) */
  int ret = vnet_feature_enable_disable ("ip6-unicast", "srv6-pot_in",
					 ls_mem->sw_if_index_in, 0, 0, 0);
  if (ret != 0)
    return -1;

  /* Unlock (OIF, NHOP) adjacency (from sr_localsid.c:103) */
  adj_unlock (localsid->nh_adj);

  /* Clean up local SID memory */
  clib_mem_free (localsid->plugin_mem);

  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 * format_srv6_pot_in_localsid (u8 * s, va_list * args) {
  
  // it is called when teh system need to print the information about the LocalSID
  // it prints (part of) the configuration about the localsid when 'show sr localsid' is executed

  srv6_pot_in_localsid_t *ls_mem = va_arg (*args, void *);

  vnet_main_t *vnm = vnet_get_main ();

  return (format (s,
		  "Next-hop:\t%U\n"
		  "\tOutgoing iface: %U\n"
		  "\tIncoming iface: %U",
		  format_ip6_address, &ls_mem->nh_addr.ip6,
		  format_vnet_sw_if_index_name, vnm, ls_mem->sw_if_index_out,
		  format_vnet_sw_if_index_name, vnm, ls_mem->sw_if_index_in));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword unformat_srv6_pot_in_localsid (unformat_input_t * input, va_list * args) {
  
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_pot_in_localsid_t *ls_mem;

  vnet_main_t *vnm = vnet_get_main ();

  ip46_address_t nh_addr;
  u32 sw_if_index_out;
  u32 sw_if_index_in;

  // parse the CLI command 
  // "sr localsid address SID behavior <...here...>"
  if (unformat (input, "end.pot_in nh %U oif %U iif %U",
		unformat_ip6_address, &nh_addr.ip6,
		unformat_vnet_sw_interface, vnm, &sw_if_index_out,
		unformat_vnet_sw_interface, vnm, &sw_if_index_in))
    {
      /* Allocate a portion of memory */
      ls_mem = clib_mem_alloc (sizeof *ls_mem);

      /* Set to zero the memory */
      clib_memset (ls_mem, 0, sizeof *ls_mem);

      /* Our brand-new car is ready */
      clib_memcpy (&ls_mem->nh_addr.ip6, &nh_addr.ip6,
		   sizeof (ip6_address_t));
      ls_mem->sw_if_index_out = sw_if_index_out;
      ls_mem->sw_if_index_in = sw_if_index_in;

      /* Dont forget to add it to the localsid */
      *plugin_mem_p = ls_mem;
      return 1;
    }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_pot_in_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: dynamic_proxy_index:[%u]", index));
}

void
srv6_pot_in_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_pot_in_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_pot_in_vft = {
  .dv_lock = srv6_pot_in_dpo_lock,
  .dv_unlock = srv6_pot_in_dpo_unlock,
  .dv_format = format_srv6_pot_in_dpo,
};

const static char *const srv6_pot_in_ip6_nodes[] = {
  "srv6-pot_in-localsid",
  NULL,
};

const static char *const *const srv6_pot_in_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_pot_in_ip6_nodes,
};

/**********************/
static clib_error_t * srv6_pot_in_init (vlib_main_t * vm) {

  // executed once at the beginning when the plugin is loaded

  // ---- PRINT ---- // 
  FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
  fprintf(file, ">> srv6_pot_in_init <<\n --------------------- \n");  
  fclose(file); 
  //


  srv6_pot_in_main_t *sm = &srv6_pot_in_main;
  int rv = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  // Create DPO 
  srv6_pot_in_dpo_type = dpo_register_new_type (&srv6_pot_in_vft, srv6_pot_in_nodes);
  sm->srv6_pot_in_dpo_type = srv6_pot_in_dpo_type;

  
  // Register SRv6 LocalSID 
  rv = sr_localsid_register_function (vm,
				      function_name,
				      keyword_str,
				      def_str,
				      params_str,
				      128,
				      &sm->srv6_pot_in_dpo_type,
				      format_srv6_pot_in_localsid,
				      unformat_srv6_pot_in_localsid,
				      srv6_pot_in_localsid_creation_fn,
				      srv6_pot_in_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;
  

  return 0;
}

VNET_FEATURE_INIT (srv6_pot_in_rewrite, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-pot_in",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_pot_in_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Proof of transit for SRv6 network",
};

int pot_in_enable_disable (srv6_pot_in_main_t * sm, ip6_address_t * bsid, int enable_disable) {
  ip6_sr_main_t *srm = &sr_main; // pointer to SR main datastructure  
  ip6_sr_policy_t *policy; // pointer to the policy data structure
  ip6_sr_sl_t *segment_list; // pointer to the segment list data structure

  int rv = 0; // return value
  uword *p = 0; 
  u32 *sl_index;

  load_balance_path_t path;
  path.path_index = FIB_NODE_INDEX_INVALID;
  load_balance_path_t *ip6_path_vector =0;

  // recover the index of the policy associated with the bsid 
  p = mhash_get (&srm->sr_policies_index_hash, bsid);

  if(p==0) { 
		rv = 1;
 		return rv;
	}

  // get the pointer to the existing policy structure that need to be Live-Live configured 
  policy = pool_elt_at_index(srm->sr_policies, p[0]);

  dpo_reset(&policy->ip6_dpo);
  dpo_set(&policy->ip6_dpo, srv6_pot_in_dpo_type, DPO_PROTO_IP6, policy - srm->sr_policies);

  // update the FIB to use the configured DPO 
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
      .ip6 = policy->bsid,
    }
  };

  /* Remove existing spray policy DPO from the FIB */  
  fib_table_entry_special_remove (srm->fib_table_ip6, &pfx, FIB_SOURCE_SR);
  /* Update FIB entry's DPO pointing the Live-Live processing node */
  fib_table_entry_special_dpo_update (srm->fib_table_ip6,
            &pfx,
            FIB_SOURCE_SR,
            FIB_ENTRY_FLAG_EXCLUSIVE,
            &policy->ip6_dpo);

  path.path_weight = 1;


  vec_foreach (sl_index, policy->segments_lists){
    segment_list =  pool_elt_at_index(srm->sid_lists, *sl_index);
    /* Modify the precompute size to Encap */
    // segment_list->rewrite = live_compute_rewrite_encaps(segment_list->rewrite); 
    /* Change the SLs' DPO to the Live-Live encapsulation DPO */
    dpo_reset(&segment_list->ip6_dpo);
    dpo_set (&segment_list->ip6_dpo, srv6_pot_in_dpo_type, DPO_PROTO_IP6, segment_list - srm->sid_lists);
    path.path_dpo = segment_list->ip6_dpo;
    vec_add1(ip6_path_vector, path);
  }

  /* Setting the Live-Live policy type*/
  policy->type = 2;
  /* Keep modified policy in the plugin*/
  sm->pot_in_policy = policy;

  return rv;
}

// ENABLE DISABLE COMMAND
static clib_error_t * pot_in_enable_disable_command_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd) {

  srv6_pot_in_main_t * sm = &srv6_pot_in_main;
  ip6_address_t bsid;
  int enable_disable = 1;
  int b = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "bsid %U", unformat_ip6_address, &bsid))
      b=1;
    else
      break;
  }

  if (b==0)
    return clib_error_return (0, "Please specify bsid of the policy");
    
  rv = pot_in_enable_disable (sm, &bsid, enable_disable);

  switch(rv) {
  case 0:
    break;

  case 1:
    return clib_error_return (0, "No policies matched with the bsid");
    break;  
  default:
    return clib_error_return (0, "pot_in_enable_disable returned %d", rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (sr_content_command, static) = {
    .path = "pot_in sr policy",
    .short_help = "pot_in sr policy bsid <bsid> [disable]",
    .function = pot_in_enable_disable_command_fn,
};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
