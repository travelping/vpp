/*
 * Copyright (c) 2018 Travelping GmbH
 *
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

#define _LGPL_SOURCE		/* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>		/* QSBR RCU flavor */

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>

#if (CLIB_DEBUG > 0)
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_classify_error		\
  _(CLASSIFY, "good packets classify")

static char *upf_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_classify_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_CLASSIFY_ERROR_##sym,
  foreach_upf_classify_error
#undef _
    UPF_CLASSIFY_N_ERROR,
} upf_classify_error_t;

typedef enum
{
  UPF_CLASSIFY_NEXT_DROP,
  UPF_CLASSIFY_NEXT_PROCESS,
  UPF_CLASSIFY_N_NEXT,
} upf_classify_next_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 pdr_idx;
  u32 next_index;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_classify_trace_t;

u8 *
format_upf_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_classify_trace_t *t = va_arg (*args, upf_classify_trace_t *);
  u32 indent = format_get_indent (s);

  s =
    format (s,
	    "upf_session%d cp-seid 0x%016" PRIx64
	    " pdr %d, next_index = %d\n%U%U", t->session_index, t->cp_seid,
	    t->pdr_idx, t->next_index, format_white_space, indent,
	    format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

always_inline int
ip4_address_is_equal (const ip4_address_t * a, const ip4_address_t * b)
{
  return a->as_u32 == b->as_u32;
}

always_inline int
ip4_address_is_equal_masked (const ip4_address_t * a,
			     const ip4_address_t * b,
			     const ip4_address_t * mask)
{
  return (a->as_u32 & mask->as_u32) == (b->as_u32 & mask->as_u32);
}

always_inline int
upf_acl_classify_one (vlib_main_t * vm, u32 teid, u8 * data, u8 is_ip4,
		      upf_acl_t * acl)
{
  udp_header_t *proto_hdr;

  if (! !is_ip4 != ! !acl->is_ip4)
    return 0;

  if (acl->match_teid && teid != acl->teid)
    return 0;

  if (is_ip4)
    {
      ip4_header_t *ip4h = (ip4_header_t *) data;

      switch (acl->match_ue_ip)
	{
	case UPF_ACL_UL:
	  if (!ip4_address_is_equal (&acl->ue_ip.ip4, &ip4h->src_address))
	    return 0;
	  break;
	case UPF_ACL_DL:
	  if (!ip4_address_is_equal (&acl->ue_ip.ip4, &ip4h->dst_address))
	    return 0;
	  break;
	default:
	  break;
	}

      if ((ip4h->protocol & acl->mask.protocol) !=
	  (acl->match.protocol & acl->mask.protocol))
	return 0;

      if (!ip4_address_is_equal_masked (&ip4h->src_address,
					&acl->match.src_address.ip4,
					&acl->mask.src_address.ip4) ||
	  !ip4_address_is_equal_masked (&ip4h->dst_address,
					&acl->match.dst_address.ip4,
					&acl->mask.dst_address.ip4))
	return 0;

      proto_hdr = (udp_header_t *) ip4_next_header (ip4h);
    }
  else
    {
      ip6_header_t *ip6h = (ip6_header_t *) data;

      switch (acl->match_ue_ip)
	{
	case UPF_ACL_UL:
	  if (!ip6_address_is_equal (&acl->ue_ip.ip6, &ip6h->src_address))
	    return 0;
	  break;
	case UPF_ACL_DL:
	  if (!ip6_address_is_equal (&acl->ue_ip.ip6, &ip6h->dst_address))
	    return 0;
	  break;
	}

      if ((ip6h->protocol & acl->mask.protocol) !=
	  (acl->match.protocol & acl->mask.protocol))
	return 0;

      if (!ip6_address_is_equal_masked (&ip6h->src_address,
					&acl->match.src_address.ip6,
					&acl->mask.src_address.ip6) ||
	  !ip6_address_is_equal_masked (&ip6h->dst_address,
					&acl->match.dst_address.ip6,
					&acl->mask.dst_address.ip6))
	return 0;

      proto_hdr = (udp_header_t *) ip6_next_header (ip6h);
    }

  if (clib_net_to_host_u16 (proto_hdr->src_port) < acl->mask.src_port ||
      clib_net_to_host_u16 (proto_hdr->src_port) > acl->match.src_port ||
      clib_net_to_host_u16 (proto_hdr->dst_port) < acl->mask.dst_port ||
      clib_net_to_host_u16 (proto_hdr->dst_port) > acl->match.dst_port)
    return 0;

  return 1;
}

always_inline u32
upf_acl_classify (vlib_main_t * vm, vlib_buffer_t * b, flow_entry_t * flow,
		  struct rules * active, u8 is_ip4)
{
  u32 next = UPF_CLASSIFY_NEXT_DROP;
  u16 precedence = ~0;
  upf_acl_t *acl, *acl_vec;
  u32 teid;
  u8 *pl;

  teid = vnet_buffer (b)->gtpu.teid;
  pl = vlib_buffer_get_current (b) + vnet_buffer (b)->gtpu.data_offset;
  vnet_buffer (b)->gtpu.pdr_idx = ~0;

  acl_vec = is_ip4 ? active->v4_acls : active->v6_acls;
  vec_foreach (acl, acl_vec)
  {
    if (acl->precedence < precedence &&
	upf_acl_classify_one (vm, teid, pl, is_ip4, acl))
      {
	precedence = acl->precedence;
	vnet_buffer (b)->gtpu.pdr_idx = acl->pdr_idx;
	next = UPF_CLASSIFY_NEXT_PROCESS;

	gtp_debug ("match PDR: %u\n", acl->pdr_idx);
      }
  }

  return next;
}

static uword
upf_classify (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  upf_session_t *sess = NULL;
  struct rules *active;
  u32 sidx = 0;
  u32 len;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      flow_entry_t *flow;
      u8 is_reverse;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sidx = vnet_buffer (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);
	  active = sx_get_rules (sess, SX_ACTIVE);

	  next = UPF_CLASSIFY_NEXT_PROCESS;

	  flow = pool_elt_at_index (fm->flows, vnet_buffer (b)->gtpu.flow_id);
	  ASSERT (flow != NULL);

	  is_reverse = vnet_buffer (b)->gtpu.is_reverse;
	  vnet_buffer (b)->gtpu.pdr_idx = flow->pdr_id[is_reverse];

	  if (vnet_buffer (b)->gtpu.pdr_idx == ~0)
	    next = upf_acl_classify (vm, b, flow, active, is_ip4);
	  else if (flow->stats[0].bytes > 4096 && flow->stats[1].bytes > 4096)
	    {
	      /* stop flow classification after 4k in each direction */
	      clib_warning ("Stopping Flow Classify after 4k");
	      flow->next[0] = flow->next[1] = FT_NEXT_PROCESS;
	    }

	  if (vnet_buffer (b)->gtpu.pdr_idx != ~0)
	    flow->pdr_id[is_reverse] = vnet_buffer (b)->gtpu.pdr_idx;

	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_classify_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_idx = vnet_buffer (b)->gtpu.pdr_idx;
	      tr->next_index = next;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
upf_ip4_classify (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return upf_classify (vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
upf_ip6_classify (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return upf_classify (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_classify_node) = {
  .function = upf_ip4_classify,
  .name = "upf-ip4-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip4-process",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (upf_ip4_classify_node, upf_ip4_classify);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_classify_node) = {
  .function = upf_ip6_classify,
  .name = "upf-ip6-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip6-process",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (upf_ip6_classify_node, upf_ip6_classify);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
