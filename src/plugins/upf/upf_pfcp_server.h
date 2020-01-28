/*
 * Copyright(c) 2017 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UPF_SX_SERVER_H
#define _UPF_SX_SERVER_H

#include <time.h>
#include "upf.h"
#include "pfcp.h"
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

#define PFCP_HB_INTERVAL 10
#define PFCP_SERVER_HB_TIMER 0
#define PFCP_SERVER_T1       1
#define PFCP_SERVER_RESPONSE 2

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  union
  {
    struct
    {
      u32 seq_no;
      u32 fib_index;

      struct
      {
	ip46_address_t address;
	u16 port;
      } rmt;
    };
    u64 request_key[4];
  };

  struct
  {
    ip46_address_t address;
    u16 port;
  } lcl;

  u32 pfcp_endpoint;
  u32 node;
  u32 session_index;

  u32 timer;
  u32 n1;
  u32 t1;
  u8 is_valid_pool_item;

  union
  {
    u8 *data;
    pfcp_header_t *hdr;
  };
} sx_msg_t;

typedef struct
{
  /* Sx Node Id is either IPv4, IPv6 or FQDN */
  u8 *node_id;
} sx_node_t;

typedef struct
{
  u32 seq_no;
  time_t start_time;
  ip46_address_t address;
  f64 now;

  TWT (tw_timer_wheel) timer;
  sx_msg_t *msg_pool;
  u32 * msg_pool_cache;
  u32 * msg_pool_free;
  uword *request_q;
  mhash_t response_q;

  vlib_frame_t * ip_lookup_tx_frames[2];

  vlib_main_t *vlib_main;
} sx_server_main_t;

typedef struct
{
  uword session_idx;
  ip46_address_t ue;
} upf_event_urr_hdr_t;

typedef struct
{
  u32 urr_id;
  u32 trigger;
} upf_event_urr_data_t;

extern sx_server_main_t sx_server_main;

extern vlib_node_registration_t sx4_input_node;
extern vlib_node_registration_t sx6_input_node;

#define UDP_DST_PORT_SX 8805

void upf_pfcp_session_stop_up_inactivity_timer(urr_time_t * t);
void upf_pfcp_session_start_up_inactivity_timer(u32 si, f64 last, urr_time_t * t);

void upf_pfcp_session_stop_urr_time (urr_time_t * t, f64 now);
void upf_pfcp_session_start_stop_urr_time (u32 si, urr_time_t * t, u8 start_it);

u32 upf_pfcp_server_start_timer (u8 type, u32 id, u32 seconds);
void upf_pfcp_server_stop_timer (u32 handle);

int upf_pfcp_send_request (upf_session_t * sx, u8 type,
			   struct pfcp_group *grp);

int upf_pfcp_send_response (sx_msg_t * req, u64 cp_seid, u8 type,
			    struct pfcp_group *grp);

void upf_pfcp_server_session_usage_report (upf_event_urr_data_t * uev);

void upf_pfcp_handle_input (vlib_main_t * vm, vlib_buffer_t * b, int is_ip4);

clib_error_t *sx_server_main_init (vlib_main_t * vm);

void upf_ip_lookup_tx (u32 bi, int is_ip4);

static inline void
init_sx_msg (sx_msg_t * m)
{
  u8 is_valid_pool_item = m->is_valid_pool_item;

  memset (m, 0, sizeof (*m));
  m->is_valid_pool_item = is_valid_pool_item;
  m->pfcp_endpoint = ~0;
  m->node = ~0;
}

static inline void
sx_msg_pool_init (sx_server_main_t * sxsm)
{
  vec_alloc (sxsm->msg_pool_cache, 128);
  vec_alloc (sxsm->msg_pool_free, 128);

}

static inline void
sx_msg_pool_loop_start (sx_server_main_t * sxsm)
{
  /* move enough entries from free to cache,
     so that cache has max 128 entries */
  while (vec_len (sxsm->msg_pool_cache) < 128 &&
	 vec_len (sxsm->msg_pool_free) != 0)
    {
      vec_add1 (sxsm->msg_pool_cache, vec_pop (sxsm->msg_pool_free));
    }

  if (vec_len (sxsm->msg_pool_free) != 0)
    {
      for (int i = 0; i < vec_len (sxsm->msg_pool_free); i++)
	pool_put_index (sxsm->msg_pool, sxsm->msg_pool_free[i]);
      vec_reset_length (sxsm->msg_pool_free);
    }
}

static inline sx_msg_t *
sx_msg_pool_get (sx_server_main_t * sxsm)
{
  sx_msg_t * m;

  if (vec_len (sxsm->msg_pool_cache) != 0)
    {
      u32 index = vec_pop (sxsm->msg_pool_cache);

      m = pool_elt_at_index (sxsm->msg_pool, index);
      init_sx_msg (m);
    }
  else
    {
      pool_get_aligned_zero (sxsm->msg_pool, m, CLIB_CACHE_LINE_BYTES);
    }

  m->is_valid_pool_item = 1;
  return m;
}

static inline sx_msg_t *
sx_msg_pool_add (sx_server_main_t * sxsm, sx_msg_t * m)
{
  sx_msg_t * msg;

  msg = sx_msg_pool_get (sxsm);
  clib_memcpy_fast (msg, m, sizeof(*m));
  msg->is_valid_pool_item = 1;
  return msg;
}

static inline void
sx_msg_pool_put (sx_server_main_t * sxsm, sx_msg_t * m)
{
  ASSERT (m->is_valid_pool_item);

  vec_free (m->data);
  m->is_valid_pool_item = 0;
  vec_add1 (sxsm->msg_pool_free, m - sxsm->msg_pool);
}

static inline int
sx_msg_pool_is_free_index (sx_server_main_t * sxsm, u32 index)
{
  if (!pool_is_free_index (sxsm->msg_pool, index))
    {
      sx_msg_t * m = pool_elt_at_index (sxsm->msg_pool, index);
      return !m->is_valid_pool_item;
    }
  return 0;
}

static inline sx_msg_t *
sx_msg_pool_elt_at_index (sx_server_main_t * sxsm, u32 index)
{
  sx_msg_t * m = pool_elt_at_index (sxsm->msg_pool, index);
  ASSERT (m->is_valid_pool_item);
  return m;
}

static inline u32
sx_msg_get_index (sx_server_main_t * sxsm, sx_msg_t *m )
{
  return m - sxsm->msg_pool;
}

#endif /* _UPF_SX_SERVER_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
