/*
 * Copyright (c) 2019 Travelping GmbH
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

#include <inttypes.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/drop_dpo.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

#ifndef CLIB_MARCH_VARIANT
/**
 * DPO type registered for these GBP FWD
 */
dpo_type_t upf_session_dpo_type;

static inline upf_session_t *
upf_session_dpo_get (index_t index)
{
  upf_main_t *gtm = &upf_main;

  return (pool_elt_at_index (gtm->sessions, index));
}

static inline upf_session_t *
upf_session_get_from_dpo (const dpo_id_t * dpo)
{
  ASSERT (upf_session_dpo_type == dpo->dpoi_type);

  return (upf_session_dpo_get (dpo->dpoi_index));
}

static inline index_t
upf_session_dpo_get_index (upf_session_t * sx)
{
  upf_main_t *gtm = &upf_main;

  return (sx - gtm->sessions);
}

static void
upf_session_dpo_lock (dpo_id_t * dpo)
{
  upf_session_t *sx;

  sx = upf_session_get_from_dpo (dpo);
  sx->dpo_locks++;
}

static void
upf_session_dpo_unlock (dpo_id_t * dpo)
{
  upf_session_t *sx;

  sx = upf_session_get_from_dpo (dpo);
  sx->dpo_locks--;
}

/*
static u32
upf_session_dpo_get_urpf (const dpo_id_t * dpo)
{
  upf_session_dpo_t *gpd;

  gpd = upf_session_dpo_get_from_dpo (dpo);

  return (gpd->gpd_sw_if_index);
}
*/

void
upf_session_dpo_add_or_lock (dpo_proto_t dproto, upf_session_t *sx, dpo_id_t * dpo)
{
#if 0
  dpo_id_t parent = DPO_INVALID;

  dpo_copy (&parent, drop_dpo_get (dproto));

  dpo_stack (upf_session_dpo_type, dproto, &sx->dpo, &parent);
#endif
  dpo_set (dpo, upf_session_dpo_type, dproto, upf_session_dpo_get_index (sx));
}

u8 *
format_upf_session_dpo (u8 * s, va_list * ap)
{
  index_t index = va_arg (*ap, index_t);
  upf_session_t *sx = upf_session_dpo_get (index);

  s = format (s, "UPF session: UP SEID: 0x%016" PRIx64 " (@%p)", sx->cp_seid, sx);
  return (s);
}

/**
 * Interpose a session DPO
 */
static void
upf_session_dpo_interpose (const dpo_id_t * original,
			   const dpo_id_t * parent, dpo_id_t * clone)
{
  ASSERT (0);
#if 0
  upf_session_dpo_t *gpd, *gpd_clone;

  gpd_clone = upf_session_dpo_alloc ();
  gpd = upf_session_dpo_get (original->dpoi_index);

  gpd_clone->gpd_proto = gpd->gpd_proto;
  gpd_clone->gpd_sclass = gpd->gpd_sclass;
  gpd_clone->gpd_sw_if_index = gpd->gpd_sw_if_index;

  /*
   * if no interface is provided, grab one from the parent
   * on which we stack
   */
  if (~0 == gpd_clone->gpd_sw_if_index)
    gpd_clone->gpd_sw_if_index = dpo_get_urpf (parent);

  dpo_stack (upf_session_dpo_type,
	     gpd_clone->gpd_proto, &gpd_clone->gpd_dpo, parent);

  dpo_set (clone,
	   upf_session_dpo_type,
	   gpd_clone->gpd_proto, upf_session_dpo_get_index (gpd_clone));
#endif
}

const static dpo_vft_t upf_session_dpo_vft = {
  .dv_lock = upf_session_dpo_lock,
  .dv_unlock = upf_session_dpo_unlock,
  .dv_format = format_upf_session_dpo,
  //.dv_get_urpf = upf_session_dpo_get_urpf,
  .dv_mk_interpose = upf_session_dpo_interpose,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char *const upf_session_dpo_ip4_nodes[] = {
  "upf-ip4-session-dpo",
  NULL,
};

const static char *const upf_session_dpo_ip6_nodes[] = {
  "upf-ip6-session-dpo",
  NULL,
};

const static char *const *const upf_session_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = upf_session_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = upf_session_dpo_ip6_nodes,
};

dpo_type_t
upf_session_dpo_get_type (void)
{
  return (upf_session_dpo_type);
}

static clib_error_t *
upf_session_dpo_module_init (vlib_main_t * vm)
{
  upf_session_dpo_type = dpo_register_new_type (&upf_session_dpo_vft,
						upf_session_dpo_nodes);

  return (NULL);
}

VLIB_INIT_FUNCTION (upf_session_dpo_module_init);
#endif /* CLIB_MARCH_VARIANT */

/* Statistics (not all errors) */
#define foreach_upf_session_dpo_error    \
_(SESSION_DPO, "good packets session_dpo")

static char *upf_session_dpo_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_session_dpo_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_SESSION_DPO_ERROR_##sym,
  foreach_upf_session_dpo_error
#undef _
    UPF_SESSION_DPO_N_ERROR,
} upf_session_dpo_error_t;

typedef enum
{
    UPF_SESSION_DPO_NEXT_DROP,
    UPF_SESSION_DPO_NEXT_FLOW_PROCESS,
    UPF_SESSION_DPO_N_NEXT,
} upf_session_dpo_next_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_session_dpo_trace_t;

static u8 *
format_upf_session_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_session_dpo_trace_t *t = va_arg (*args, upf_session_dpo_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d seid %d \n%U%U",
	      t->session_index, t->cp_seid,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

always_inline uword
upf_session_dpo_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 next = 0;
  u32 sidx = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: dual and maybe quad loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  sidx = vnet_buffer (b)->ip.adj_index[VLIB_TX];
	  gtp_debug ("Session %d (0x%08x)", sidx, sidx);
	  ASSERT (~0 != sidx);

	  vnet_buffer (b)->gtpu.session_index = sidx;
	  vnet_buffer (b)->gtpu.data_offset = 0;
	  vnet_buffer (b)->gtpu.teid = 0;

	  next = UPF_SESSION_DPO_NEXT_FLOW_PROCESS;
	  vnet_buffer (b)->gtpu.flags =
	    is_ip4 ? BUFFER_HAS_IP4_HDR : BUFFER_HAS_IP6_HDR;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_session_t *sess = pool_elt_at_index (gtm->sessions, sidx);
	      upf_session_dpo_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
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

VLIB_NODE_FN (upf_ip4_session_dpo_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return (upf_session_dpo_inline (vm, node, from_frame, 1));
}

VLIB_NODE_FN (upf_ip6_session_dpo_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return (upf_session_dpo_inline (vm, node, from_frame, 0));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_session_dpo_node) = {
  .name = "upf-ip4-session-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_session_dpo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(upf_session_dpo_error_strings),
  .error_strings = upf_session_dpo_error_strings,

  .n_next_nodes = UPF_SESSION_DPO_N_NEXT,
  .next_nodes = {
    [UPF_SESSION_DPO_NEXT_DROP]         = "error-drop",
    [UPF_SESSION_DPO_NEXT_FLOW_PROCESS] = "upf-ip4-flow-process",
  },
};

VLIB_REGISTER_NODE (upf_ip6_session_dpo_node) = {
  .name = "upf-ip6-session-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_session_dpo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(upf_session_dpo_error_strings),
  .error_strings = upf_session_dpo_error_strings,

  .n_next_nodes = UPF_SESSION_DPO_N_NEXT,
  .next_nodes = {
    [UPF_SESSION_DPO_NEXT_DROP]         = "error-drop",
    [UPF_SESSION_DPO_NEXT_FLOW_PROCESS] = "upf-ip6-flow-process",
  },
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */








/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
