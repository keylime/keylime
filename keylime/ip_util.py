"""Utilities for IP/IPV6 addresses"""

from ipaddress import IPv6Address, ip_address
from typing import Optional


def bracketize_ipv6(ipaddr: Optional[str]) -> Optional[str]:
    """Surround an IPv6 address with '[]'"""
    if ipaddr:
        try:
            if isinstance(ip_address(ipaddr), IPv6Address):
                return "[" + ipaddr + "]"
        except Exception:
            pass
    return ipaddr
