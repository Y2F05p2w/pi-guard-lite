from __future__ import annotations

import ipaddress
from functools import lru_cache

import yaml

from app.common.config import PROJECT_ROOT


WHITELIST_FILE = PROJECT_ROOT / "config" / "whitelist.yaml"


@lru_cache(maxsize=1)
def load_whitelist() -> dict:
    if not WHITELIST_FILE.exists():
        return {"ips": [], "cidrs": [], "domains": []}
    with WHITELIST_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    whitelist = data.get("whitelist", {})
    whitelist.setdefault("ips", [])
    whitelist.setdefault("cidrs", [])
    whitelist.setdefault("domains", [])
    return whitelist


def is_ip_whitelisted(ip: str | None) -> bool:
    if not ip:
        return False
    whitelist = load_whitelist()
    if ip in whitelist["ips"]:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for raw_cidr in whitelist["cidrs"]:
        try:
            if ip_obj in ipaddress.ip_network(raw_cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_domain_whitelisted(domain: str | None) -> bool:
    if not domain:
        return False
    whitelist = load_whitelist()
    domain = domain.lower()
    for item in whitelist["domains"]:
        item = item.lower()
        if domain == item or domain.endswith(f".{item}"):
            return True
    return False
