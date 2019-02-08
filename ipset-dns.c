/* ipset-dns: lightweight DNS IPSet forwarding server
 * by Jason A. Donenfeld (zx2c4) <Jason@zx2c4.com>
 *
 * This is a lightweight DNS forwarding server that adds all resolved IPs
 * to a given netfilter ipset. It is designed to be used in conjunction with
 * dnsmasq's upstream server directive.
 *
 * Copyright (C) 2013, 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * DNS parsing code loosely based on uClibc's resolv.c:
 * Copyright (C) 1998 Kenneth Albanowski <kjahds@kjahds.com>, The Silver Hammer Group, Ltd.
 * Copyright (C) 1985, 1993 The Regents of the University of California. All Rights Reserved.
 * This file is licensed under the GPLv2. Please see COPYING for more information.
 *
 * 
 * Usage Example:
 * 
 * In dnsmasq.conf:
 *     server=/c.youtube.com/127.0.0.1#1919
 * Make an ipset:
 *     # ipset -N youtube iphash
 * Start the ipset-dns server:
 *     # ipset-dns youtube "" 1919 8.8.8.8
 * Query a hostname:
 *     # host r4---bru02t12.c.youtube.com
 *     r4---bru02t12.c.youtube.com is an alias for r4.bru02t12.c.youtube.com.
 *     r4.bru02t12.c.youtube.com has address 74.125.216.51
 * Observe that it was added to the ipset:
 *     # ipset -L youtube
 *     Name: youtube
 *     Type: iphash
 *     References: 1
 *     Header: hashsize: 1024 probes: 8 resize: 50
 *     Members:
 *     74.125.216.51
 */   


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#ifndef OLD_IPSET
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>
#endif

struct resolv_header {
	int id;
	int qr, opcode, aa, tc, rd, ra, rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_answer {
	char dotted[256];
	int atype;
	int aclass;
	int ttl;
	int rdlength;
	const unsigned char *rdata;
	int rdoffset;
};

static void decode_header(unsigned char *data, struct resolv_header *h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
}
static int length_question(const unsigned char *data, int maxlen)
{
	const unsigned char *start;
	unsigned int b;

	if (!data)
		return -1;

	start = data;
	for (;;) {
		if (maxlen <= 0)
			return -1;
		b = *data++;
		if (b == 0)
			break;
		if ((b & 0xc0) == 0xc0) {
			/* It's a "compressed" name. */
			++data; /* skip lsb of redirected offset */
			maxlen -= 2;
			break;
		}
		data += b;
		maxlen -= (b + 1); /* account for data++ above */
	}
	/* Up to here we were skipping encoded name */

	/* Account for QTYPE and QCLASS fields */
	if (maxlen < 4)
		return -1;
	return data - start + 2 + 2;
}
static int decode_dotted(const unsigned char *packet, int offset, int packet_len, char *dest, int dest_len)
{
	unsigned int b, total = 0, used = 0;
	int measure = 1;

	if (!packet)
		return -1;

	for (;;) {
		if (offset >= packet_len)
			return -1;
		b = packet[offset++];
		if (b == 0)
			break;

		if (measure)
			++total;

		if ((b & 0xc0) == 0xc0) {
			if (offset >= packet_len)
				return -1;
			if (measure)
				++total;
			/* compressed item, redirect */
			offset = ((b & 0x3f) << 8) | packet[offset];
			measure = 0;
			continue;
		}

		if (used + b + 1 >= dest_len || offset + b >= packet_len)
			return -1;
		memcpy(dest + used, packet + offset, b);
		offset += b;
		used += b;

		if (measure)
			total += b;

		if (packet[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}

	if (measure)
		++total;

	return total;
}
static int decode_answer(const unsigned char *message, int offset, int len, struct resolv_answer *a)
{
	int i;

	i = decode_dotted(message, offset, len, a->dotted, sizeof(a->dotted));
	if (i < 0)
		return i;

	message += offset + i;
	len -= i + RRFIXEDSZ + offset;
	if (len < 0)
		return len;

	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	if (len < a->rdlength)
		return -1;
	return i + RRFIXEDSZ + a->rdlength;
}

static int add_to_ipset(const char *setname, const void *ipaddr, int af)
{
#ifndef OLD_IPSET
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	struct mnl_socket *mnl;
	struct nlattr *nested[2];
	char buffer[256];
	int rc;
	
	rc = 0;

	if (strlen(setname) >= IPSET_MAXNAMELEN) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (af != AF_INET && af != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	nlh = mnl_nlmsg_put_header(buffer);
	nlh->nlmsg_type = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
	nlh->nlmsg_flags = NLM_F_REQUEST;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfg->nfgen_family = af;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);

	mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	mnl_attr_put(nlh, IPSET_ATTR_SETNAME, strlen(setname) + 1, setname);
	nested[0] = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
	nested[1] = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);
	mnl_attr_put(nlh, (af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6)
			| NLA_F_NET_BYTEORDER, (af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)), ipaddr);
	mnl_attr_nest_end(nlh, nested[1]);	
	mnl_attr_nest_end(nlh, nested[0]);

	mnl = mnl_socket_open(NETLINK_NETFILTER);
	if (mnl <= 0)
		return -1;
	if (mnl_socket_bind(mnl, 0, MNL_SOCKET_AUTOPID) < 0) {
		rc = -1;
		goto close;
	}
	if (mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len) < 0) {
		rc = -1;
		goto close;
	}
close:
	mnl_socket_close(mnl);
	return rc;
#else
	int sock, rc;
	socklen_t size;
	struct ip_set_req_adt_get {
		unsigned op;
		unsigned version;
		union {
			char name[32];
			uint16_t index;
		} set;
		char typename[32];
	} req_adt_get;
	struct ip_set_req_adt {
		unsigned op;
		uint16_t index;
		uint32_t ip;
	} req_adt;
	
	rc = 0;
	
	if (strlen(setname) >= sizeof(req_adt_get.set.name)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (af != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
		return -1;
	
	req_adt_get.op = 0x10;
	req_adt_get.version = 3;
	strcpy(req_adt_get.set.name, setname);
	size = sizeof(req_adt_get);
	if (getsockopt(sock, SOL_IP, 83, &req_adt_get, &size) < 0) {
		rc = -1;
		goto close;
	}
	req_adt.op = 0x101;
	req_adt.index = req_adt_get.set.index;
	req_adt.ip = ntohl(*(uint32_t *)ipaddr);
	if (setsockopt(sock, SOL_IP, 83, &req_adt, sizeof(req_adt)) < 0) {
		rc = -1;
		goto close;
	}
close:
	close(sock);
	return rc;
#endif
}

int main(int argc, char *argv[]) 
{
	struct sockaddr_in client_addr, listen_addr, upstream_addr;
	struct resolv_header question_header, answer_header;
	struct resolv_answer answer;
	struct timeval tv;
	char msg[512];
	char ip[INET6_ADDRSTRLEN];
	char *ipset4, *ipset6;
	int listen_sock, upstream_sock;
	int pos, i, size, af;
	socklen_t len;
	size_t received;
	pid_t child;
	char delim[] = ":";
	
	if (argc != 5) {
		fprintf(stderr, "Usage: %s ipv4-ipset ipv6-ipset port upstream\n", argv[0]);
		return 1;
	}

	ipset4 = argv[1];
	ipset6 = argv[2];

	if (!*ipset4 && !*ipset6) {
		fprintf(stderr, "At least one of ipv4-ipset and ipv6-ipset must be provided.\n");
		return 1;
	}

	listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (listen_sock < 0) {
		perror("socket");
		return 1;
	}
	
	char *l_ip_port = strtok(argv[3], delim);
	char *l_port = strtok(NULL, delim);
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	if (l_port != NULL) {
		listen_addr.sin_port = htons(atoi(l_port));
		inet_aton(l_ip_port, &listen_addr.sin_addr);
	} else {
		listen_addr.sin_port = htons(atoi(l_ip_port));
		listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	i = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
		perror("bind");
		return 1;
	}
	
	char *up_ip = strtok(argv[4], delim);
	char *up_port = strtok(NULL, delim);
	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	if (up_port != NULL) {
		upstream_addr.sin_port = htons(atoi(up_port));
	} else {
		upstream_addr.sin_port = htons(53);
	}
	inet_aton(up_ip, &upstream_addr.sin_addr);
	
	/* TODO: Put all of the below code in several forks all listening on the same sock. */

	if (!getenv("NO_DAEMONIZE")) {
		if (daemon(0, 0) < 0) {
			perror("daemon");
			return 1;
		}
	}
	
	upstream_sock = -1;

	for (;;) {
		if (upstream_sock >= 0)
			close(upstream_sock);

		len = sizeof(client_addr);
		received = recvfrom(listen_sock, msg, sizeof(msg), 0, (struct sockaddr *)&client_addr, &len);
		if (received < 0) {
			perror("recvfrom");
			continue;
		}
		if (received < HFIXEDSZ) {
			fprintf(stderr, "Did not receive full DNS header from client.\n");
			continue;
		}

		decode_header(msg, &question_header);

		upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (upstream_sock < 0) {
			perror("socket");
			continue;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if (sendto(upstream_sock, msg, received, 0, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
			perror("sendto");
			continue;
		}
		received = recv(upstream_sock, msg, sizeof(msg), 0);
		if (received < 0) {
			perror("recv");
			continue;
		}
		if (received < HFIXEDSZ) {
			fprintf(stderr, "Did not receive full DNS header from upstream.\n");
			continue;
		}
		close(upstream_sock);
		upstream_sock = -1;

		decode_header(msg, &answer_header);
		if (answer_header.id != question_header.id || !answer_header.qr) {
			fprintf(stderr, "Unsolicited response from upstream.\n");
			continue;
		}
		if (answer_header.rcode || answer_header.ancount <= 0)
			goto send_back;

		pos = HFIXEDSZ;
		for (i = 0; i < answer_header.qdcount; ++i) {
			if (pos >= received || pos < 0)
				goto send_back;
			size = length_question(msg + pos, received - pos);
			if (size < 0)
				goto send_back;
			pos += size;
		}
		for (i = 0; i < answer_header.ancount; ++i) {
			if (pos >= received || pos < 0)
				goto send_back;
			size = decode_answer(msg, pos, received, &answer);
			if (size < 0) {
				if (i && answer_header.tc)
					break;
				goto send_back;
			}
			pos += size;

			if (!(answer.atype == T_A && answer.rdlength == sizeof(struct in_addr)) &&
				!(answer.atype == T_AAAA && answer.rdlength == sizeof(struct in6_addr)))
				continue;
			
			af = answer.atype == T_A ? AF_INET : AF_INET6;

			if (!inet_ntop(af, answer.rdata, ip, sizeof(ip))) {
				perror("inet_ntop");
				continue;
			}

			if ((af == AF_INET && !*ipset4) || (af == AF_INET6 && !*ipset6))
				continue;

			printf("%s: %s\n", answer.dotted, ip);
			if (add_to_ipset((af == AF_INET) ? ipset4 : ipset6, answer.rdata, af) < 0)
				perror("add_to_ipset");
		}
		
	send_back:
		if (sendto(listen_sock, msg, received, 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
			perror("sendto");
	}
	return 0;
}
