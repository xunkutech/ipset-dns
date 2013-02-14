# ipset-dns
#### Jason A. Donenfeld (<Jason@zx2c4.com>)

`ipset-dns` is a lightweight DNS forwarding server that adds all resolved IPs
to a given [netfilter ipset](http://ipset.netfilter.org/). It is designed to be
used in conjunction with [`dnsmasq`](http://www.thekelleys.org.uk/dnsmasq/doc.html)'s
upstream server directive.

Practical use cases include routing over a given gateway traffic for particular
web services or webpages that do not have a priori predictable IP addresses and
instead rely on dizzying arrays of DNS resolutions.

### Why?

Some ISPs throttle connections to services like YouTube. Other times,
you live places where there's no Netflix/Pandora/Hulu, but you've got a VPN.

The problem is, you don't want to route *all* your internet traffic over VPN -- just
for YouTube and Pandora, say. It'd be nice to just whitelist a static IP range,
but some services, like YouTube, have a thousands of caching servers in a modicum
of IP ranges, and it's just too much of a hassle to compile the list beforehand.

So instead, you put `ipset-dns` on your router, and then everyone and every
XBox/PS3/whatever on your wifi network will benefit from the superior
bandwidth and/or geo-availability.

### Usage

    # ipset-dns name-of-ipset listening-port upstream-dns-server

`ipset-dns` binds only to localhost. It will daemonize unless the `NO_DAEMONIZE`
environment variable is set.

### Building

Linux >= 2.6.32:

    $ make

Linux >= 2.6.16 or >= 2.4.36:

    $ make OLD_IPSET=1

### Example

In `dnsmasq.conf`:

	server=/c.youtube.com/127.0.0.1#1919

Make an ipset:

	# ipset -N youtube iphash

Start the `ipset-dns` server:

	# ipset-dns youtube 1919 8.8.8.8

Query a hostname:

	# host r4---bru02t12.c.youtube.com
	r4---bru02t12.c.youtube.com is an alias for r4.bru02t12.c.youtube.com.
	r4.bru02t12.c.youtube.com has address 74.125.216.51

Observe that it was added to the ipset:

	# ipset -L youtube
	Name: youtube
	Type: iphash
	References: 1
	Header: hashsize: 1024 probes: 8 resize: 50
	Members:
	74.125.216.51


### Sample Script

The following script routes youtube and netflix over two different repective
gateways. It assumes you're using `dnsmasq` or similar to manage caching and
selectively using upstream servers:

	server=/c.youtube.com/127.0.0.1#39128
	server=/netflix.com/127.0.0.1#39129

The network interfaces `tun11` and `tun12` are assumed to be OpenVPN tunnels,
though they may be any other kind of interface with a route. These devices are
assumed to have some form of masquerading and IP forwarding turned on already.

The `mangle` `iptables` table is used to set a firewall mark on packets that
match an ipset tended to by `ipset-dns`. A routing table is created and a rule
is entered that sends packets marked by `iptables` to the correct routing table.
Finally, a default route is given to the marked routing table.

Two `ipset-dns` daemons are started, one for each of the routes, using the ports
given by `dnsmasq`. Lastly, `SIGHUP` is sent to `dnsmasq` to flush its cache.

	sets() {
		iptables -t mangle -D PREROUTING -m set --set "$1" dst,src -j MARK --set-mark "$2" 2>/dev/null
		ipset -X "$1" 2>/dev/null
		ipset -N "$1" iphash
		iptables -t mangle -A PREROUTING -m set --set "$1" dst,src -j MARK --set-mark "$2"
	}

	sets youtube 1
	sets netflix 2

	routes() {
		echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
		ip route flush table $1 2>/dev/null
		ip rule del table $1 2>/dev/null
		ip rule add fwmark $1 table $1 priority 1000
		ip route add default via "$(ip route show dev $2 | head -n 1 | cut -d ' ' -f 1)" table $1
	}

	routes 1 tun12
	routes 2 tun11

	killall ipset-dns 2>/dev/null
	ipset-dns youtube 39128 8.8.8.8
	ipset-dns netflix 39129 8.8.8.8

	killall -SIGHUP dnsmasq

### License

* Copyright (C) 2013 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

DNS parsing code loosely based on uClibc's [resolv.c](http://git.uclibc.org/uClibc/tree/libc/inet/resolv.c):

* Copyright (C) 1998 Kenneth Albanowski <kjahds@kjahds.com>, The Silver Hammer Group, Ltd.
* Copyright (C) 1985, 1993 The Regents of the University of California. All Rights Reserved.

This project is licensed under the GPLv2. Please see COPYING for more information.
