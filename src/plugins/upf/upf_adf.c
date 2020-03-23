/*
 * Copyright (c) 2020 Travelping GmbH
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
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_app_db.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

always_inline int
ip4_address_is_equal_masked (const ip4_address_t * a,
			     const ip4_address_t * b,
			     const ip4_address_t * mask)
{
  gtp_debug ("IP: %U/%U, %U\n",
	     format_ip4_address, a,
	     format_ip4_address, b, format_ip4_address, mask);

  return (a->as_u32 & mask->as_u32) == (b->as_u32 & mask->as_u32);
}

always_inline u8 *
upf_adr_try_tls (u16 port, u8 * p, word length)
{
  struct tls_record_hdr *hdr = (struct tls_record_hdr *) p;
  struct tls_handshake_hdr *hsk = (struct tls_handshake_hdr *) (hdr + 1);
  struct tls_client_hello_hdr *hlo =
    (struct tls_client_hello_hdr *) (hsk + 1);
  u8 *data = (u8 *) (hlo + 1);
  word frgmt_len, hsk_len, len;
  u8 *url = NULL;

  clib_warning ("Length: %d", length);
  if (length < sizeof (*hdr))
    return NULL;

  clib_warning ("HDR: %u, v: %u.%u, Len: %d",
		hdr->type, hdr->major, hdr->minor,
		clib_net_to_host_u16 (hdr->length));
  if (hdr->type != TLS_HANDSHAKE)
    return NULL;

  if (hdr->major != 3 || hdr->minor < 1 || hdr->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now)
     * SSLv2 backward-compatible hello is not supported
     */
    return NULL;

  length -= sizeof (*hdr);
  frgmt_len = clib_net_to_host_u16 (hdr->length);

  if (length < frgmt_len)
    /* TLS fragment is longer that IP payload */
    return NULL;

  hsk_len = hsk->length[0] << 16 | hsk->length[1] << 8 | hsk->length[2];
  clib_warning ("TLS Hello: %u, v: Len: %d", hsk->type, hsk_len);

  if (hsk_len + sizeof (*hsk) < frgmt_len)
    /* Hello is longer that the current fragment */
    return NULL;

  if (hsk->type != TLS_CLIENT_HELLO)
    return NULL;

  clib_warning ("TLS Client Hello: %u.%u", hlo->major, hlo->minor);
  if (hlo->major != 3 || hlo->minor < 1 || hlo->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now) */
    return NULL;

  len = hsk_len - sizeof (*hlo);

  /* Session Id */
  if (len < *data + 1)
    return NULL;
  len -= *data + 1;
  data += *data + 1;

  /* Cipher Suites */
  if (len < clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2)
    return NULL;
  len -= clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2;
  data += clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2;

  /* Compression Methods */
  if (len < *data + 1)
    return NULL;
  len -= *data + 1;
  data += *data + 1;

  /* Extensions */
  if (len < clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2)
    return NULL;
  len = clib_net_to_host_unaligned_mem_u16 ((u16 *) data);
  data += 2;

  while (len > 4)
    {
      u16 ext_type, ext_len, sni_len, name_len;

      ext_type = clib_net_to_host_unaligned_mem_u16 ((u16 *) data);
      ext_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 2));

      gtp_debug ("TLS Hello Extension: %u, %u", ext_type, ext_len);

      if (ext_type != TLS_EXT_SNI)
	goto skip_extension;

      if (ext_len < 5 || ext_len + 4 > len)
	{
	  gtp_debug ("invalid extension len: %u (%u)", ext_len, len);
	  goto skip_extension;
	}

      sni_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 4));
      if (sni_len != ext_len - 2)
	{
	  gtp_debug ("invalid SNI extension len: %u != %u", sni_len,
		     ext_len - 2);
	  goto skip_extension;
	}

      if (*(data + 6) != 0)
	{
	  gtp_debug ("invalid SNI name type: %u", *(data + 6));
	  goto skip_extension;
	}

      name_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 7));
      if (name_len != sni_len - 3)
	{
	  gtp_debug ("invalid server name len: %u != %u", name_len,
		     sni_len - 3);
	  goto skip_extension;
	}

      vec_add (url, "https://", strlen ("https://"));
      vec_add (url, data + 9, name_len);
      if (port != 443)
	url = format (url, ":%u", port);
      vec_add1 (url, '/');

      return url;

    skip_extension:
      len -= ext_len + 4;
      data += ext_len + 4;
    }

  return NULL;
}

always_inline u8 *
upf_adr_try_http (u16 port, u8 * p, word len)
{
  u8 *host;
  word uri_len;
  u8 *eol;
  u8 *s;
  u8 *url = NULL;

  if (!is_http_request (&p, &len))
    /* payload to short, abort ADR scanning for this flow */
    return NULL;

  eol = memchr (p, '\n', len);
  if (!eol)
    /* not EOL found */
    return NULL;

  s = memchr (p, ' ', eol - p);
  if (!s)
    /* HTTP/0.9 - can find the Host Header */
    return NULL;

  uri_len = s - p;

  {
    u64 d0 = *(u64 *) (s + 1);

    if (d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '0') &&
	d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '1'))
      /* not HTTP 1.0 or 1.1 compatible */
      return NULL;
  }

  host = eol + 1;
  len -= (eol - p) + 1;

  while (len > 0)
    {
      if (is_host_header (&host, &len))
	break;
    }

  if (len <= 0)
    return NULL;

  vec_add (url, "http://", strlen ("http://"));
  vec_add (url, host, len);
  if (port != 80)
    url = format (url, ":%u", port);
  vec_add (url, p, uri_len);

  return url;
}

void
upf_application_detection (vlib_main_t * vm, vlib_buffer_t * b,
			   flow_entry_t * flow, struct rules *active,
			   u8 is_ip4)
{
  u32 offs = upf_buffer_opaque (b)->gtpu.data_offset;
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  upf_pdr_t *adr;
  upf_pdr_t *pdr;
  u8 *proto_hdr;
  u16 port = 0;
  u8 *p;
  word len;
  u8 *url;
  u8 src_intf;

  // known PDR.....
  // scan for Application Rules

  if (!(active->flags & PFCP_ADR))
    return;

  if (is_ip4)
    {
      ip4 = (ip4_header_t *) (vlib_buffer_get_current (b) + offs);
      proto_hdr = ip4_next_header (ip4);
      len = clib_net_to_host_u16 (ip4->length) - sizeof (ip4_header_t);
    }
  else
    {
      ip6 = (ip6_header_t *) (vlib_buffer_get_current (b) + offs);
      proto_hdr = ip6_next_header (ip6);
      len = clib_net_to_host_u16 (ip6->payload_length);
    }

  if (flow->key.proto == IP_PROTOCOL_TCP &&
      flow->tcp_state == TCP_F_STATE_ESTABLISHED)
    {
      len -= tcp_header_bytes ((tcp_header_t *) proto_hdr);
      offs = proto_hdr - (u8 *) vlib_buffer_get_current (b) +
	tcp_header_bytes ((tcp_header_t *) proto_hdr);
      port = clib_net_to_host_u16 (((tcp_header_t *) proto_hdr)->dst_port);
    }
  else if (flow->key.proto == IP_PROTOCOL_UDP)
    {
      len -= sizeof (udp_header_t);
      offs =
	proto_hdr - (u8 *) vlib_buffer_get_current (b) +
	sizeof (udp_header_t);
      port = clib_net_to_host_u16 (((udp_header_t *) proto_hdr)->dst_port);
    }
  else
    return;

  if (len < vlib_buffer_length_in_chain (vm, b) - offs || len <= 0)
    /* no or invalid payload */
    return;

  p = vlib_buffer_get_current (b) + offs;
  if (*p == TLS_HANDSHAKE)
    url = upf_adr_try_tls (port, p, len);
  else
    url = upf_adr_try_http (port, p, len);

  if (url == NULL)
    goto out_next_process;

  adf_debug ("URL: %v", url);

  adr = vec_elt_at_index (active->pdr, upf_buffer_opaque (b)->gtpu.pdr_idx);
  adf_debug ("Old PDR: %p %u (idx %u)\n", adr, adr->id,
	     upf_buffer_opaque (b)->gtpu.pdr_idx);
  src_intf = adr->pdi.src_intf;

  /*
   * see 3GPP TS 23.214 Table 5.2.2-1 for valid ADR combinations
   */
  vec_foreach (pdr, active->pdr)
  {
    if (!(pdr->pdi.fields & F_PDI_APPLICATION_ID))
      {
	adf_debug ("skip PDR %u for no ADR\n", pdr->id);
	continue;
      }

    if (pdr->precedence >= adr->precedence)
      {
	adf_debug ("skip PDR %u for lower precedence\n", pdr->id);
	continue;
      }

    if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR))
      {
	if (is_ip4)
	  {
	    const ip4_address_t *addr;

	    if (!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4))
	      {
		adf_debug ("skip PDR %u for no UE IPv4 address\n", pdr->id);
		continue;
	      }
	    addr = (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD) ?
	      &ip4->dst_address : &ip4->src_address;

	    if (!ip4_address_is_equal (&pdr->pdi.ue_addr.ip4, addr))
	      {
		adf_debug
		  ("skip PDR %u for UE IPv4 mismatch, S/D: %u, %U != %U\n",
		   pdr->id, !!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD),
		   format_ip4_address, &pdr->pdi.ue_addr.ip4,
		   format_ip4_address, addr);
		continue;
	      }
	  }
	else
	  {
	    const ip6_address_t *addr;

	    if (!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6))
	      {
		adf_debug ("skip PDR %u for no UE IPv6 address\n", pdr->id);
		continue;
	      }
	    addr = (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD) ?
	      &ip6->dst_address : &ip6->src_address;

	    if (!ip6_address_is_equal_masked (&pdr->pdi.ue_addr.ip6, addr,
					      &ip6_main.fib_masks[64]))
	      {
		adf_debug
		  ("skip PDR %u for UE IPv6 mismatch, S/D: %u, %U != %U\n",
		   pdr->id, !!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD),
		   format_ip6_address, &pdr->pdi.ue_addr.ip6,
		   format_ip6_address, addr);
		continue;
	      }
	  }
      }

    if ((pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	upf_buffer_opaque (b)->gtpu.teid != pdr->pdi.teid.teid)
      {
	adf_debug ("skip PDR %u for TEID type mismatch\n", pdr->id);
	continue;
      }

    if (pdr->pdi.src_intf != src_intf)
      {
	/* must have the same direction as the original SDF that permited the flow */
	adf_debug ("skip PDR %u for Src Intf mismatch, %u != %u\n",
		   pdr->id, pdr->pdi.src_intf, src_intf);
	continue;
      }

    adf_debug ("Scanning %p, db_id %u\n", pdr, pdr->pdi.adr.db_id);
    if (upf_adf_lookup (pdr->pdi.adr.db_id, url, vec_len (url), NULL) == 0)
      adr = pdr;
  }
  upf_buffer_opaque (b)->gtpu.pdr_idx = adr - active->pdr;
  if ((adr->pdi.fields & F_PDI_APPLICATION_ID))
    flow->application_id = adr->pdi.adr.application_id;

  adf_debug ("New PDR: %p %u (idx %u)\n", adr, adr->id,
	     upf_buffer_opaque (b)->gtpu.pdr_idx);

  vec_free (url);

out_next_process:
  flow->next[upf_buffer_opaque (b)->gtpu.is_reverse] = FT_NEXT_PROCESS;
  return;
}

void
upf_get_application_rule (vlib_main_t * vm, vlib_buffer_t * b,
			  flow_entry_t * flow, struct rules *active,
			  u8 is_ip4)
{
  upf_pdr_t *adr;
  upf_pdr_t *pdr;

  adr = vec_elt_at_index (active->pdr, upf_buffer_opaque (b)->gtpu.pdr_idx);
  adf_debug ("Old PDR: %p %u (idx %u)\n", adr, adr->id,
	     upf_buffer_opaque (b)->gtpu.pdr_idx);
  vec_foreach (pdr, active->pdr)
  {
    if ((pdr->pdi.fields & F_PDI_APPLICATION_ID)
	&& (pdr->precedence < adr->precedence)
	&& (pdr->pdi.adr.application_id == flow->application_id))
      adr = pdr;
  }
  upf_buffer_opaque (b)->gtpu.pdr_idx = adr - active->pdr;
  if ((adr->pdi.fields & F_PDI_APPLICATION_ID))
    flow->application_id = adr->pdi.adr.application_id;

  adf_debug ("New PDR: %p %u (idx %u)\n", adr, adr->id,
	     upf_buffer_opaque (b)->gtpu.pdr_idx);

  /* switch return traffic to processing node */
  flow->next[flow->is_reverse ^ FT_REVERSE] = FT_NEXT_PROCESS;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
