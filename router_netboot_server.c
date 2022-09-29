// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "router_netboot_server.h"

#include <stdint.h>

#include "compat.h"
#include "flash.h"
#include "proto.h"
#include "router_images.h"

#define NETBOOT_SERVER_IP 3232255489UL /* 192.168.78.1 */
#define NETBOOT_RANGE_MIN 3232255490UL; /* 192.168.78.2 */
#define NETBOOT_RANGE_MAX 3232255742UL; /* 192.168.78.254 */

enum netboot_client_state{
    DHCP_STATE_UNKNOWN,
    DHCP_STATE_DISCOVER,
    DHCP_STATE_OFFER,
    DHCP_STATE_REQUEST,
    DHCP_STATE_ACK,
};

struct netboot_server_priv {
    uint32_t netboot_client_ip;
    enum netboot_client_state netboot_state;
};

static void netboot_server_detect_pre(const struct router_type *router_type,
				   const uint8_t *our_mac)
{
	uint8_t bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct router_netboot_server *netboot_server;

	netboot_server = container_of(router_type, struct router_netboot_server,
				   router_type);

	arp_req_send(our_mac, bcast_mac, htonl(my_ip), htonl(netboot_server->ip));
}

static int netboot_server_detect_main(const struct router_type *router_type,
				   void *priv, const char *packet_buff,
				   int packet_buff_len)
{
	struct netboot_server_priv *server_priv = priv;
	struct router_netboot_server *netboot_server;
	struct ether_arp *arphdr;
	int ret = 0;

	netboot_server = container_of(router_type, struct router_netboot_server,
				   router_type);

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;
	if (arphdr->ea_hdr.ar_op != htons(ARPOP_REPLY))
		goto out;

	if (load_ip_addr(arphdr->arp_spa) != htonl(netboot_server->ip))
		goto out;

	if (server_priv->arp_count < netboot_server->wait_arp_count) {
		server_priv->arp_count++;
		goto out;
	}

	ret = 1;

out:
	return ret;
}

static void netboot_server_detect_post(struct node *node, const char *packet_buff,
				    int packet_buff_len)
{
	struct ether_arp *arphdr;

	if (!len_check(packet_buff_len, sizeof(struct ether_arp), "ARP"))
		goto out;

	arphdr = (struct ether_arp *)packet_buff;

	node->flash_mode = FLASH_MODE_TFTP_SERVER;
	node->his_ip_addr = load_ip_addr(arphdr->arp_spa);
	node->our_ip_addr = load_ip_addr(arphdr->arp_tpa);

out:
	return;
}

const struct router_netboot_server mikrotik = {
	.router_type = {
		.desc = "mikrotik",
		.detect_pre = netboot_server_detect_pre,
		.detect_main = netboot_server_detect_main,
		.detect_post = netboot_server_detect_post,
		.image = &img_mikrotik,
		.image_desc = "mikrotik",
		.priv_size = sizeof(struct netboot_server_priv),
	},
	.server_ip = NETBOOT_SERVER_IP,
    .range_min = NETBOOT_RANGE_MIN,
    .range_max = NETBOOT_RANGE_MAX,
};
