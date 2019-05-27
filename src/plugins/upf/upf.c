/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017-2019 Travelping GmbH
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <errno.h>

#include <math.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>

/* Action function shared between message handler and debug CLI */
#include <upf/flowtable.h>
#include <upf/upf_adf.h>

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

int
upf_enable_disable (upf_main_t * sm, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "upf",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

int
vnet_upf_pfcp_endpoint_add_del (ip46_address_t * ip, u32 fib_index, u8 add)
{
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t key;
  upf_pfcp_endpoint_t *ep;
  uword *p;

  key.addr = *ip;
  key.fib_index = fib_index;

  p = mhash_get (&gtm->pfcp_endpoint_index, &key);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->pfcp_endpoints, ep);
      memset (ep, 0, sizeof (*ep));

      ep->key = key;

      mhash_set (&gtm->pfcp_endpoint_index, &ep->key, ep - gtm->pfcp_endpoints, NULL);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ep = pool_elt_at_index (gtm->pfcp_endpoints, p[0]);
      mhash_unset (&gtm->pfcp_endpoint_index, &ep->key, NULL);
      pool_put (gtm->pfcp_endpoints, ep);
    }

  return 0;
}

int
vnet_upf_upip_add_del (ip4_address_t * ip4, ip6_address_t * ip6,
		       u8 * name, u8 intf, u32 teid, u32 mask, u8 add)
{
  upf_main_t *gtm = &upf_main;
  upf_upip_res_t *ip_res;
  upf_upip_res_t res = {
    .ip4 = *ip4,
    .ip6 = *ip6,
    .nwi = ~0,
    .intf = intf,
    .teid = teid,
    .mask = mask
  };
  uword *p;

  if (name)
    {
      p = hash_get_mem (gtm->nwi_index_by_name, name);
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      res.nwi = p[0];
    }

  p = mhash_get (&gtm->upip_res_index, &res);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->upip_res, ip_res);
      memcpy (ip_res, &res, sizeof (res));

      mhash_set (&gtm->upip_res_index, ip_res, ip_res - gtm->upip_res, NULL);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (gtm->upip_res, p[0]);
      mhash_unset (&gtm->upip_res_index, ip_res, NULL);
      pool_put (gtm->upip_res, ip_res);
    }

  return 0;
}

int
vnet_upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto, u32 table_id, u8 add)
{
  u32 fib_index, vrf_fib_index;
  upf_main_t *gtm = &upf_main;

  if (add)
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find_or_create_and_lock (fproto, table_id, FIB_SOURCE_PLUGIN_LOW);

      vec_validate_init_empty (gtm->tdf_ul_table[fproto], vrf_fib_index, ~0);
      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = fib_index;
    }
  else
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (vrf_fib_index >= vec_len(gtm->tdf_ul_table[fproto]))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find (fproto, table_id);
      if (~0 == fib_index)
	return VNET_API_ERROR_NO_SUCH_FIB;

      if (vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) != fib_index)
	return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = ~0;
      fib_table_unlock (fib_index, fproto, FIB_SOURCE_PLUGIN_LOW);

      return (0);
    }

  return 0;
}

static int
upf_tdf_ul_lookup_add_i (u32 tdf_ul_fib_index, const fib_prefix_t * pfx, u32 ue_fib_index)
{
  dpo_id_t dpo = DPO_INVALID;

  /*
   * create a data-path object to perform the source address lookup
   * in the TDF FIB
   */
  lookup_dpo_add_or_lock_w_fib_index (tdf_ul_fib_index,
				      fib_proto_to_dpo (pfx->fp_proto),
				      LOOKUP_UNICAST,
				      LOOKUP_INPUT_SRC_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);

  /*
   * add the entry to the destination FIB that uses the lookup DPO
   */
  fib_table_entry_special_dpo_add (ue_fib_index, pfx,
				   FIB_SOURCE_PLUGIN_LOW,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  /*
   * the DPO is locked by the FIB entry, and we have no further
   * need for it.
   */
   dpo_unlock (&dpo);

  return 0;
}

#if 0
// TODO
static int
upf_tdf_ul_lookup_delete (u32 tdf_ul_fib_index, const fib_prefix_t * pfx)
{
  fib_table_entry_special_remove (tdf_ul_fib_index, pfx, FIB_SOURCE_PLUGIN_LOW);

  return (0);
}
#endif

int
vnet_upf_tdf_ul_enable_disable (fib_protocol_t fproto, u32 sw_if_index, int is_en)
{
  upf_main_t *gtm = &upf_main;
  fib_prefix_t pfx = {
    .fp_proto = fproto,
  };
  u32 fib_index;

  fib_index =
    fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

  if (fib_index >= vec_len(gtm->tdf_ul_table[fproto]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (~0 == vec_elt (gtm->tdf_ul_table[fproto], fib_index))
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (is_en)
    {
      /*
       * now we know which interface the table will serve, we can add the default
       * route to use the table that the interface is bound to.
       */
      upf_tdf_ul_lookup_add_i (vec_elt (gtm->tdf_ul_table[fproto],
					fib_index), &pfx, fib_index);


      /*
	vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 1, NULL, 0);
      */
    }
  else
    {
      // TODO
      /*
	vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				"ip4-unicast" :
				"ip6-unicast"),
			       (FIB_PROTOCOL_IP4 == fproto ?
				"svs-ip4" :
				"svs-ip6"), sw_if_index, 0, NULL, 0);
      */
    }
  return 0;
}

static inline u8 *
format_v4_tunnel_by_key_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  gtpu4_tunnel_key_t *key = (gtpu4_tunnel_key_t *)&v->key;

  s = format (s, "TEID 0x%08x peer %U session idx %u rule idx %u",
	      key->teid, format_ip4_address, &key->dst,
	      v->value & 0xffffffff, v->value >> 32);
  return s;
}

static inline u8 *
format_v6_tunnel_by_key_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_24_8_t *v = va_arg (*args, clib_bihash_kv_24_8_t *);

  s = format (s, "TEID 0x%08x peer %U session idx %u rule idx %u",
	      v->key[2], format_ip6_address, &v->key[0],
	      v->value & 0xffffffff, v->value >> 32);
  return s;
}

static inline u8 *
format_peer_index_by_ip_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_24_8_t *v = va_arg (*args, clib_bihash_kv_24_8_t *);

  s = format (s, "peer %U fib idx idx %u peer idx %u",
	      format_ip46_address, &v->key[0], IP46_TYPE_ANY,
	      v->key[2], v->value);
  return s;
}

static clib_error_t *
upf_test_watch_point_command_fn (vlib_main_t * vm,
			  unformat_input_t * main_input,
			  vlib_cli_command_t * cmd)
{
  load_balance_main.lbm_to_counters.counters = NULL;
  vec_validate (load_balance_main.lbm_to_counters.counters, 1);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_test_watch_point_command, static) =
{
  .path = "upf test watch",
  .short_help =
  "upf test watch",
  .function = upf_test_watch_point_command_fn,
};
/* *INDENT-ON* */

extern int errno;

enum {
	BREAK_EXEC = 0x0,
	BREAK_WRITE = 0x1,
	BREAK_READWRITE = 0x3,
};

enum {
	BREAK_ONE = 0x0,
	BREAK_TWO = 0x1,
	BREAK_FOUR = 0x3,
	BREAK_EIGHT = 0x2,
};

#define ENABLE_BREAKPOINT(x)       (0x1 << ((x) * 2))
#define BREAKPOINT_TYPE(x, type)   ((type) << (16 + ((x) * 4)))
#define BREAKPOINT_WIDTH(x, width) ((width) << (18 + ((x) * 4)))

/*
 * This function fork()s a child that will use
 * ptrace to set a hardware breakpoint for
 * memory r/w at _addr_. When the breakpoint is
 * hit, then _handler_ is invoked in a signal-
 * handling context.
 */
static int
install_breakpoint(void *addr, int bpno, void (*handler)(int)) {
	pid_t child = 0;
	uint32_t bp =
		ENABLE_BREAKPOINT(bpno) |
		BREAKPOINT_TYPE(bpno, BREAK_WRITE) |
		BREAKPOINT_WIDTH(bpno, BREAK_FOUR);
	pid_t parent = getpid();
	int child_status = 0;

	if (!(child = fork()))
	{
		int parent_status = 0;
		printf("in child\n");

		if (ptrace(PTRACE_ATTACH, parent, NULL, NULL))
		{
			printf("attach: %m\n");
			_Exit(1);
		}

		while (!WIFSTOPPED(parent_status))
			waitpid(parent, &parent_status, 0);

		/*
		 * set the breakpoint address.
		 */
		if (ptrace(PTRACE_POKEUSER, parent, offsetof(struct user, u_debugreg[bpno]), addr))
		{
			printf("set breakpoint address: %m\n");
			_exit(1);
		}

		/*
		 * set parameters for when the breakpoint should be triggered.
		 */
		if (ptrace(PTRACE_POKEUSER, parent, offsetof(struct user, u_debugreg[7]), bp))
		{
			printf("set breakpoint condition: %m\n");
			_exit(1);
		}

		if (ptrace(PTRACE_DETACH, parent, NULL, NULL))
			_exit(1);

		_exit(0);
	}

	waitpid(child, &child_status, 0);

	signal(SIGTRAP, handler);

	if (WIFEXITED(child_status) && !WEXITSTATUS(child_status))
		return 1;

	return 0;
}

#if 0
/*
 * This function will disable a breakpoint by
 * invoking install_breakpoint is a 0x0 _addr_
 * and no handler function. See comments above
 * for implementation details.
 */
static int
disable_breakpoint(int bpno)
{
	return install_breakpoint(0x0, bpno, NULL);
}
#endif

void handle_breakpoint(int s)
{
  printf("handler_breakpoint ...\n");
  abort ();
}

static clib_error_t *
upf_arm_watch_point_command_fn (vlib_main_t * vm,
			  unformat_input_t * main_input,
			  vlib_cli_command_t * cmd)
{
  install_breakpoint (&load_balance_main.lbm_to_counters.counters, 0, handle_breakpoint);
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_arm_watch_point_command, static) =
{
  .path = "upf arm watch",
  .short_help =
  "upf arm watch",
  .function = upf_arm_watch_point_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_init (vlib_main_t * vm)
{
  upf_main_t *sm = &upf_main;
  clib_error_t *error;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;

  if ((error =
       vlib_call_init_function (vm, upf_proxy_main_init)))
    return error;

  mhash_init (&sm->pfcp_endpoint_index, sizeof (uword), sizeof (ip46_address_t));
  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  mhash_init (&sm->upip_res_index, sizeof (uword), sizeof (upf_upip_res_t));

  /* initialize the IP/TEID hash's */
  clib_bihash_init_8_8 (&sm->v4_tunnel_by_key,
			"upf_v4_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_8_8 (&sm->v4_tunnel_by_key,
				     format_v4_tunnel_by_key_kvp);
  clib_bihash_init_24_8 (&sm->v6_tunnel_by_key,
			 "upf_v6_tunnel_by_key", UPF_MAPPING_BUCKETS,
			 UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_24_8 (&sm->v6_tunnel_by_key,
				      format_v6_tunnel_by_key_kvp);

  clib_bihash_init_24_8 (&sm->peer_index_by_ip,
			 "upf_peer_index_by_ip", UPF_MAPPING_BUCKETS,
			 UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_24_8 (&sm->peer_index_by_ip,
				      format_peer_index_by_ip_kvp);

  sm->node_index_by_fqdn =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  mhash_init (&sm->node_index_by_ip, sizeof (uword), sizeof (ip46_address_t));

#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  clib_bihash_init_8_8 (&sm->qer_by_id,
			"upf_qer_by_ie", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type (&upf_vft);

  sm->upf_app_by_name = hash_create_vec ( /* initial length */ 32,
					 sizeof (u8), sizeof (uword));

  error = flowtable_init (vm);
  if (error)
    return error;

  return sx_server_main_init (vm);
}

VLIB_INIT_FUNCTION (upf_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (upf, static) =
{
  .arc_name = "device-input",
  .node_name = "upf",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

u8 *
format_upf_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_encap_trace_t *t = va_arg (*args, upf_encap_trace_t *);

  s = format (s, "GTPU encap to upf_session%d teid 0x%08x",
	      t->session_index, t->teid);
  return s;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
