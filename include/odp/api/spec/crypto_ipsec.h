/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto IPSec extension
 */

#ifndef ODP_API_CRYPTO_IPSEC_H_
#define ODP_API_CRYPTO_IPSEC_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum odp_ipsec_outhdr_type
 * IPSec tunnel outer header type
 *
 * @enum odp_ipsec_ar_ws
 * IPSec Anti-replay window size
 *
 */

typedef struct odp_ipsec_params {
	uint32_t spi;		 /** SPI value */
	uint32_t seq;		 /** Initial SEQ number */
	enum odp_ipsec_ar_ws ar_ws; /** Anti-replay window size -
					inbound session with authentication */
	odp_bool_t esn;		/** Use extended sequence numbers */
	odp_bool_t auto_iv;	/** Auto IV generation for each operation. */
	uint16_t out_hdr_size;	 /** outer header size - tunnel mode */
	uint8_t *out_hdr;	 /** outer header - tunnel mode */
	enum odp_ipsec_outhdr_type out_hdr_type; /* outer header type -
						    tunnel mode */
	odp_bool_t ip_csum;	/** update/verify ip header checksum */
	odp_bool_t ip_dttl;	/** decrement ttl - tunnel mode encap & decap */
	odp_bool_t remove_outer_hdr; /** remove outer header - tunnel mode decap */
	odp_bool_t copy_dscp;	/** DiffServ Copy - Copy the IPv4 TOS or
				    IPv6 Traffic Class byte from the inner/outer
				    IP header to the outer/inner IP header -
				    tunnel mode encap & decap */
	odp_bool_t copy_df;	/** Copy DF bit - copy the DF bit from
				    the inner IP header to the
				    outer IP header - tunnel mode encap */
	odp_bool_t nat_t;	/** NAT-T encapsulation enabled - tunnel mode */
	odp_bool_t udp_csum;    /** Update/verify UDP csum when NAT-T enabled */

} odp_ipsec_params_t;

/**
 * @enum odp_ipsec_mode:ODP_IPSEC_MODE_TUNNEL
 * IPSec tunnel mode
 *
 * @enum odp_ipsec_mode:ODP_IPSEC_MODE_TRANSPORT
 * IPSec transport mode
 *
 * @enum odp_ipsec_proto
 * IPSec protocol
 */

/**
 * Configure crypto session for IPsec processing
 *
 * Configures a crypto session for IPSec protocol processing.
 * Packets submitted to an IPSec enabled session will have
 * relevant IPSec headers/trailers and tunnel headers
 * added/removed by the crypto implementation.
 * For example, the input packet for an IPSec ESP transport
 * enabled session should be the clear text packet with
 * no ESP headers/trailers prepared in advance for crypto operation.
 * The output packet will have ESP header, IV, trailer and the ESP ICV
 * added by crypto implementation.
 * Depending on the particular capabilities of an implementation and
 * the parameters enabled by application, the application may be
 * partially or completely offloaded from IPSec protocol processing.
 * For example, if an implementation does not support checksum
 * update for IP header after adding ESP header the application
 * should update after crypto IPSec operation.
 *
 * If an implementation does not support a particular set of
 * arguments it should return error.
 *
 * @param session	    Session handle
 * @param ipsec_mode	    IPSec protocol mode
 * @param ipsec_proto	    IPSec protocol
 * @param ipsec_params	    IPSec parameters. Parameters which are not
 *			    relevant for selected protocol & mode are ignored -
 *			    e.g. outer_hdr/size set for ESP transport mode.
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_config_ipsec(odp_crypto_session_t session,
				    enum odp_ipsec_mode ipsec_mode,
				    enum odp_ipsec_proto ipsec_proto,
				    odp_ipsec_params_t *ipsec_params);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
