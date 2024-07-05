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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <srv6_pot_in/pot_in.h>
#include <arpa/inet.h>


/******************************* Packet tracing *******************************/

typedef struct
{
  u32 localsid_index;
} srv6_pot_in_localsid_trace_t;

typedef struct
{
  ip6_address_t src, dst;
} srv6_pot_in_rewrite_trace_t;

static u8 *
format_srv6_pot_in_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_pot_in_localsid_trace_t *t = va_arg (*args, srv6_pot_in_localsid_trace_t *);

  return format (s, "SRv6-pot_in-localsid: localsid_index %d", t->localsid_index);
}

static u8 *
format_srv6_pot_in_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_pot_in_rewrite_trace_t *t = va_arg (*args, srv6_pot_in_rewrite_trace_t *);

  return format (s, "srv6-pot_in: src %U dst %U",
		 format_ip6_address, &t->src, format_ip6_address, &t->dst);
}


/***************************** Node registration ******************************/

vlib_node_registration_t srv6_pot_in_rewrite_node;


/****************************** Packet counters *******************************/

#define foreach_srv6_pot_in_rewrite_counter \
_(PROCESSED, "srv6-pot_in rewritten packets") \
_(NO_SRH, "(Error) No SRH.")

typedef enum
{
#define _(sym,str) SRV6_pot_in_REWRITE_COUNTER_##sym,
  foreach_srv6_pot_in_rewrite_counter
#undef _
    SRV6_pot_in_REWRITE_N_COUNTERS,
} srv6_pot_in_rewrite_counters;

static char *srv6_pot_in_rewrite_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_pot_in_rewrite_counter
#undef _
};


/********************************* Next nodes *********************************/

typedef enum
{
  SRV6_pot_in_LOCALSID_NEXT_ERROR,
  SRV6_pot_in_LOCALSID_NEXT_REWRITE,
  SRV6_pot_in_LOCALSID_N_NEXT,
} srv6_pot_in_localsid_next_t;

typedef enum
{
  SRV6_pot_in_REWRITE_NEXT_ERROR,
  SRV6_pot_in_REWRITE_NEXT_LOOKUP,
  SRV6_pot_in_REWRITE_N_NEXT,
} srv6_pot_in_rewrite_next_t;


/******************************* Local SID node *******************************/

/**
 * @brief SRv6 masquerading.
 */
static_always_inline void
end_pot_in_processing (vlib_buffer_t * b0,
		   ip6_header_t * ip0,
		   ip6_sr_header_t * sr0,
		   ip6_sr_localsid_t * ls0, u32 * next0)
{
  ip6_address_t *new_dst0;

  if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_IPV6_ROUTE ||
		     sr0->type != ROUTING_HEADER_TYPE_SR))
    {
      *next0 = SRV6_pot_in_LOCALSID_NEXT_ERROR;
      return;
    }

  if (PREDICT_FALSE (sr0->segments_left == 0))
    {
      *next0 = SRV6_pot_in_LOCALSID_NEXT_ERROR;
      return;
    }

  /* Decrement Segments Left */
  sr0->segments_left -= 1;

  /* Set Destination Address to Last Segment (index 0) */
  new_dst0 = (ip6_address_t *) (sr0->segments);
  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

  /* Set Xconnect adjacency to VNF */
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
}

/**
 * @brief Graph node for applying SRv6 masquerading.
 */
static uword srv6_pot_in_localsid_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame) {

  // ------------ // 
  FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
  fprintf(file, ">> srv6_pot_in_localsid_fn <<\n --------------------- \n");  
  fclose(file); 
  //

  // then error...

  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  // (input frame): array of indexes pointing to the buffers
  from = vlib_frame_vector_args (frame); 

  // number of packets in the input frame
  n_left_from = frame->n_vectors;

  // index of the next node in the graph (chached one)
  next_index = node->cached_next_index;

  u32 thread_index = vm->thread_index;

  while (n_left_from > 0) {

      // number of slot available in the output frame
      u32 n_left_to_next;

      // it prepares an output frame in the current node for the next node (next_index): it populates to_next and n_left_to_next
      // An output frame is a container that collects packets in transit to the next node in the processing pipeline
	    // vlib_get_next_frame obtains the memory structure where the data packets passed to the next node will reside
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

    while (n_left_from > 0 && n_left_to_next > 0) {
	    u32 bi0;
	    vlib_buffer_t *b0;
	    ip6_header_t *ip0 = 0;
	    ip6_sr_header_t *sr0;
	    ip6_sr_localsid_t *ls0;
	    u32 next0 = SRV6_pot_in_LOCALSID_NEXT_REWRITE;

	    bi0 = from[0]; // get the index of the first packet in the frame 
	    to_next[0] = bi0; // 
	    from += 1; // move the pointer: a packet have been processed 
	    to_next += 1;
	    n_left_from -= 1; // decrese the number of packets to be processed
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0); // obtain the pointer of the buffer identified by the index bi0 
	    ip0 = vlib_buffer_get_current (b0); // obtain the pointer to the ipv6 header of the pointer
	    sr0 = (ip6_sr_header_t *) (ip0 + 1); // obtain the pointer to the segment routing header

      // ------------ // 
      FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
      fprintf(file, ">> INFO <<\n"); 
      fprintf(file, ">> next_header: %u <<\n", ip0->protocol);
      fprintf(file, ">> protocol: %u <<\n", sr0->protocol);
      fprintf(file, ">> length: %u <<\n", sr0->length);
      fprintf(file, ">> type: %u <<\n", sr0->type);
      fprintf(file, ">> segments_left: %u <<\n", sr0->segments_left);
      fprintf(file, ">> last_entry: %u <<\n", sr0->last_entry);
      fprintf(file, ">> flags: 0x%02x <<\n", sr0->flags);
      fprintf(file, "   - Protected: %s\n", (sr0->flags & IP6_SR_HEADER_FLAG_PROTECTED) ? "Yes" : "No");
      fprintf(file, "   - OAM: %s\n", (sr0->flags & IP6_SR_HEADER_FLAG_OAM) ? "Yes" : "No");
      fprintf(file, "   - Alert: %s\n", (sr0->flags & IP6_SR_HEADER_FLAG_ALERT) ? "Yes" : "No");
      fprintf(file, "   - HMAC: %s\n", (sr0->flags & IP6_SR_HEADER_FLAG_HMAC) ? "Yes" : "No");
      fprintf(file, ">> tag: %u <<\n", sr0->tag);

      // Stampare gli indirizzi IP dei segmenti
      int num_segments = (sr0->length + 1) * 8 / sizeof(ip6_address_t);
      fprintf(file, ">> Segment Addresses:\n");
      for (int i = 0; i < num_segments; ++i) {
          char addr_str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET6, &sr0->segments[i], addr_str, sizeof(addr_str));
          fprintf(file, "   - Segment %d: %s\n", i + 1, addr_str);
      }

      char src_address[46];
      char dst_address[46];
      inet_ntop(10, &ip0->src_address, src_address, 46);
      inet_ntop(10, &ip0->dst_address, dst_address, 46);

      fprintf(file, ">> src_address: %s <<\n", src_address);
      fprintf(file, ">> dst_address: %s <<\n", dst_address);
      fclose(file); 
      //



	    /* Lookup the SR End behavior based on IP DA (adj) */
	    ls0 = pool_elt_at_index (sm->localsids,
		  		   vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

	    /* SRH processing */
	    end_pot_in_processing (b0, ip0, sr0, ls0, &next0);

	    if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	      {
	        srv6_pot_in_localsid_trace_t *tr =
		  vlib_add_trace (vm, node, b0, sizeof *tr);
	        tr->localsid_index = ls0 - sm->localsids;
	      }

	    /* This increments the SRv6 per LocalSID counters. */
	    vlib_increment_combined_counter (((next0 ==
		  			     SRV6_pot_in_LOCALSID_NEXT_ERROR) ?
		  			    &(sm->sr_ls_invalid_counters) :
		  			    &(sm->sr_ls_valid_counters)),
		  			   thread_index, ls0 - sm->localsids,
		  			   1, vlib_buffer_length_in_chain (vm,
		  							   b0));

	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
		  			   n_left_to_next, bi0, next0);
	  } 

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_pot_in_localsid_node) = {
  .function = srv6_pot_in_localsid_fn,
  .name = "srv6-pot_in-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_pot_in_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SRV6_pot_in_LOCALSID_N_NEXT,
  .next_nodes = {
    [SRV6_pot_in_LOCALSID_NEXT_REWRITE] = "ip6-rewrite",
    [SRV6_pot_in_LOCALSID_NEXT_ERROR] = "error-drop",
  },
};


/******************************* Rewriting node *******************************/

/**
 * @brief SRv6 de-masquerading.
 */
static_always_inline void end_pot_in_rewriting (
      vlib_node_runtime_t * node,
		  vlib_buffer_t * b0,
		  ip6_header_t * ip0, ip6_sr_header_t * sr0, u32 * next0) {

  if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_IPV6_ROUTE ||
		     sr0->type != ROUTING_HEADER_TYPE_SR))
    {
      b0->error = node->errors[SRV6_pot_in_REWRITE_COUNTER_NO_SRH];
      *next0 = SRV6_pot_in_REWRITE_NEXT_ERROR;
      return;
    }

  /* Restore Destination Address to active segment (index SL) */
  if (sr0->segments_left != 0)
    {
      ip6_address_t *new_dst0;
      new_dst0 = (ip6_address_t *) (sr0->segments) + sr0->segments_left;
      ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
      ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
    }
}

/**
 * @brief Graph node for applying SRv6 de-masquerading.
 */
static uword
srv6_pot_in_rewrite_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  // ---- PRINT ---- // 
  FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
  fprintf(file, ">>> srv6_pot_in_rewrite_fn <<<\n --------------------- \n");  
  fclose(file); 
  //

  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0;
	  u32 next0 = SRV6_pot_in_REWRITE_NEXT_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  /* SRH processing */
	  end_pot_in_rewriting (node, b0, ip0, sr0, &next0);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_pot_in_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof tr->src.as_u8);
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof tr->dst.as_u8);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_pot_in_rewrite_node.index,
			       SRV6_pot_in_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_pot_in_rewrite_node) = {
  .function = srv6_pot_in_rewrite_fn,
  .name = "srv6-pot_in",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_pot_in_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_pot_in_REWRITE_N_COUNTERS,
  .error_strings = srv6_pot_in_rewrite_counter_strings,
  .n_next_nodes = SRV6_pot_in_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_pot_in_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_pot_in_REWRITE_NEXT_ERROR] = "error-drop",
  },
};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
