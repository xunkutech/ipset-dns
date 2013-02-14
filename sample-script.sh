#!/bin/sh
set -x

# Inside of dnsmasq.conf we have:
#
#     server=/c.youtube.com/127.0.0.1#39128
#     server=/netflix.com/127.0.0.1#39129
#
# The devices tun11 and tun12 are OpenVPN tun network interfaces.
#
# This script routes youtube videos over tun12 and netflix over tun11.

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

killall -SIGHUP dnsmasq # Clear dnsmasq's cache
