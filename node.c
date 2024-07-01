	/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pot_in/pot_in.h>

typedef struct 
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} pot_in_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* packet trace format function */
static u8 * format_pot_in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pot_in_trace_t * t = va_arg (*args, pot_in_trace_t *);
  
  s = format (s, "POT_IN: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, "  new src %U -> new dst %U",
              my_format_mac_address, t->new_src_mac, 
              my_format_mac_address, t->new_dst_mac);
  return s;
}

vlib_node_registration_t pot_in_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pot_in_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) POT_IN_ERROR_##sym,
  foreach_pot_in_error
#undef _
  POT_IN_N_ERROR,
} pot_in_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * pot_in_error_strings[] = 
{
#define _(sym,string) string,
  foreach_pot_in_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum 
{
  POT_IN_NEXT_IP4,
  POT_IN_DROP,
  POT_IN_N_NEXT,
} pot_in_next_t;

#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)


// MAIN FUNCTION OF THE NODE  
VLIB_NODE_FN (pot_in_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
  u32 n_left_from, *from, *to_next; // to_next: pointer to the output frame, it is an array of indexes representing the buffers
  pot_in_next_t next_index;

  u32 pkts_swapped = 0; // number of swapped packets

  from = vlib_frame_vector_args (frame); // (input frame): array of indexes pointing to the buffer
  n_left_from = frame->n_vectors;   // number of packets in the input frame
  next_index = node->cached_next_index; // index of the next node in the graph (chached one)

  while (n_left_from > 0) { // loop until there are packets to process

    u32 n_left_to_next; // number of slot available in the output frame
    // to_next: array of indexes in the outut frame

    // it prepares an output frame in the current node for the next node (next_index): it populates to_next and n_left_to_next
    // An output frame is a container that collects packets in transit to the next node in the processing pipeline
	  // vlib_get_next_frame obtains the memory structure where the data packets passed to the next node will reside
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
	    u32 bi0; // index of the buffer b0
	    vlib_buffer_t *b0; // pointer to the buffer b0 of the incoming packet
	    u32 next0 = POT_IN_NEXT_IP4; // to be changed ?? 
	    u32 sw_if_index0 = 0; // to be removed

	    // pointer to the ip4 header 
	    ip4_header_t *ip0;

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;

      // update the counters 
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;
      // 

	    b0 = vlib_get_buffer (vm, bi0); // obtain the pointer of the buffer identified by the index bi0 
	    /*
	     * Direct from the driver, we should be at offset 0
	     * aka at &b0->data[0]
	     */
	    ASSERT (b0->current_data == 0); // b0->current_data represent the offset within b0

      // get the pointer to the ipv4 header of b0
	    ip0 = vlib_buffer_get_current (b0);

      // print the first 20 bytes of the IPv4 header 
      FILE* file = fopen("/home/gianluca/Desktop/dump.txt", "a");
      for(int i=0; i<20; i++){
        printf("%02x", *(u8*)(((void*)ip0)+i)); 
        
        // print on the file 
        fprintf(file, "%02x ", *(u8*)(((void*)ip0)+i));  
        // 
      }
      fprintf(file, "\n");  
      fclose(file); 
      //

	    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	      pot_in_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      // clib_memcpy (t->new_src_mac, en0->src_address, sizeof (t->new_src_mac));
	      // clib_memcpy (t->new_dst_mac, en0->dst_address, sizeof (t->new_dst_mac));
	    }

	    pkts_swapped += 1;

	    /* verify speculative enqueue, maybe switch current next frame */
      	// it verifies that the cached frame was the correct one
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
	  }

	// it commits the frame (add to pending vector) for the next node
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  // it keeps track of the number of packets that have been processed (swapped)
  vlib_node_increment_counter (vm, pot_in_node.index, POT_IN_ERROR_SWAPPED, pkts_swapped);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pot_in_node) = 
{
  .name = "pot_in",
  .vector_size = sizeof (u32),
  .format_trace = format_pot_in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(pot_in_error_strings),
  .error_strings = pot_in_error_strings,

  .n_next_nodes = POT_IN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [POT_IN_NEXT_IP4] = "ip4-lookup",
        [POT_IN_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
