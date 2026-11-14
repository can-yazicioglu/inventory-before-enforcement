# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Pure functions of the recorder: pseudonyms, peer labels, record transformation, leak check.

Nothing in this module touches the network or the disk, so every rule that decides what leaves
the site can be read and tested in one place.
"""
import base64
import functools
import hashlib
import hmac
import ipaddress
import os
import re

DEFAULT_LOCAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                      "100.64.0.0/10", "fc00::/7", "fe80::/10")

# Well-known group addresses become fixed words, so no address literal reaches the output.
GROUP_LABELS = {
    "224.0.0.1": "allnodes", "ff02::1": "allnodes", "224.0.0.2": "allrouters", "ff02::2": "allrouters",
    "224.0.0.22": "igmp", "ff02::16": "mld", "224.0.0.251": "mdns", "ff02::fb": "mdns",
    "224.0.0.252": "llmnr", "ff02::1:3": "llmnr", "239.255.255.250": "ssdp", "ff02::c": "ssdp",
    "ff05::c": "ssdp", "ff02::1:2": "dhcp6", "224.0.1.129": "ptp", "224.0.0.9": "rip",
}
_SOLICITED = ipaddress.ip_network("ff02::1:ff00:0/104")

PORT_CATEGORY = {("udp", 53): "dns", ("tcp", 53): "dns", ("udp", 123): "time", ("udp", 67): "dhcp",
                 ("udp", 68): "dhcp", ("tcp", 853): "dns", ("udp", 5353): "mdns"}

_B32 = re.compile(r"^[a-z2-7]+$")


class Pseudonymiser:
    """Keyed, one-way, stable pseudonyms. The key never leaves the site."""

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self._key = key
        self._memo = {}

    def tok(self, kind: str, value: str, n: int = 10) -> str:
        k = (kind, value, n)
        t = self._memo.get(k)
        if t is None:
            if len(self._memo) > 500000:
                self._memo.clear()
            d = hmac.new(self._key, f"{kind}|{value}".encode(), hashlib.sha256).digest()
            t = self._memo[k] = base64.b32encode(d).decode().lower()[:n]
        return t

    def device(self, mac: str) -> str:
        return "d" + self.tok("dev", norm_mac(mac))

    def device_by_ip(self, ip: str) -> str:
        return "i" + self.tok("ip", str(_ip(ip)))

    def wan_host(self, ip: str) -> str:
        return "h" + self.tok("wanhost", str(_ip(ip)))

    def wan_net(self, ip: str) -> str:
        return "n" + self.tok("wannet", _net_of(ip))

    def domain(self, registrable: str) -> str:
        return "m" + self.tok("dom", registrable.lower().rstrip("."))

    def group(self, addr: str) -> str:
        return "g" + self.tok("group", str(_ip(addr)), 8)


def new_key() -> bytes:
    return os.urandom(32)


@functools.lru_cache(maxsize=200000)
def _ip(ip: str):
    return ipaddress.ip_address(ip)


@functools.lru_cache(maxsize=200000)
def _net_of(ip: str) -> str:
    a = _ip(ip)
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False))


@functools.lru_cache(maxsize=200000)
def norm_mac(mac: str) -> str:
    m = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(m) != 12:
        raise ValueError(f"not a MAC address: {mac!r}")
    return m


def is_group_mac(mac: str) -> bool:
    try:
        return bool(int(norm_mac(mac)[:2], 16) & 1)
    except ValueError:
        return False


class Scope:
    """Decides whether an address is local, remote, multicast or broadcast."""

    def __init__(self, local_nets=DEFAULT_LOCAL_NETS):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in local_nets]
        self._memo = {}

    def is_local_ip(self, ip: str) -> bool:
        v = self._memo.get(ip)
        if v is None:
            if len(self._memo) > 500000:
                self._memo.clear()
            a = _ip(ip)
            v = self._memo[ip] = a.is_unspecified or any(a.version == n.version and a in n for n in self.nets)
        return v

    def of(self, ip: str, mac: str = "", gateways=frozenset()) -> str:
        """lan | wan | mcast | bcast.

        An address outside the configured local networks still counts as local when the frame
        carries the MAC address of an ordinary device (not a known gateway). This covers sites
        that use public IPv4 space or global IPv6 addresses inside.
        """
        a = _ip(ip)
        if a.is_multicast:
            return "mcast"
        if a.version == 4 and (str(a) == "255.255.255.255" or (mac and norm_mac(mac) == "f" * 12)):
            return "bcast"
        if self.is_local_ip(ip):
            return "lan"
        if mac and not is_group_mac(mac) and norm_mac(mac) not in gateways:
            return "lan"
        return "wan"


def group_label(ip: str, pz: Pseudonymiser) -> str:
    a = _ip(ip)
    if str(a) == "255.255.255.255" or not a.is_multicast:
        return "bcast"
    if a.version == 6 and a in _SOLICITED:
        return "mcast:sn"          # solicited-node groups carry MAC bits, collapse them
    return "mcast:" + GROUP_LABELS.get(str(a), "o" + pz.group(str(a)))


class PublicSuffix:
    """Registrable domain (public suffix plus one label) from a vendored public suffix list."""

    def __init__(self, path: str):
        self.rules, self.exceptions, self.wild = set(), set(), set()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                line = line.split()[0]
                if not line.isascii():
                    try:
                        line = line.encode("idna").decode()
                    except UnicodeError:
                        continue
                if line.startswith("!"):
                    self.exceptions.add(line[1:])
                elif line.startswith("*."):
                    self.wild.add(line[2:])
                else:
                    self.rules.add(line)

    def registrable(self, name: str):
        name = (name or "").lower().rstrip(".")
        if not name or name.replace(".", "").isdigit() or ":" in name:
            return None
        labels = name.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exceptions:
                return cand
            parent = ".".join(labels[i + 1:])
            if cand in self.rules or (parent and parent in self.wild):
                return ".".join(labels[i - 1:]) if i > 0 else None
        return ".".join(labels[-2:]) if len(labels) >= 2 else None


class Categoriser:
    """Maps a registrable domain or a port to a coarse service type. Rules: 'suffix,category' lines."""

    def __init__(self, rule_lines=()):
        self.rules = {}
        for line in rule_lines:
            line = line.strip()
            if line and not line.startswith("#") and "," in line:
                suffix, cat = [x.strip().lower() for x in line.split(",")[:2]]
                if not re.fullmatch(r"[a-z_]{2,24}", cat):
                    raise ValueError(f"bad category {cat!r}")
                self.rules[suffix] = cat

    def category(self, domain, proto: str, port):
        d = (domain or "").lower()
        while d:
            if d in self.rules:
                return self.rules[d]
            d = d.partition(".")[2]
        return PORT_CATEGORY.get((proto, port), "other" if domain else "unknown")


# ---------------------------------------------------------------- record transformation

def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def established(rec: dict) -> bool:
    """True if the responder took part: TCP handshake answered, or any responder packet otherwise."""
    if rec.get("proto") == "tcp":
        return "h" in (rec.get("history") or "")
    return _int(rec.get("resp_pkts")) > 0 or _int(rec.get("resp_bytes")) > 0


def transform(rec: dict, pz: Pseudonymiser, scope: Scope, gateways: set, wan_tokens: bool,
              ip2dom: dict, psl: PublicSuffix, cat: Categoriser, iface: int = 0):
    """Turn one Zeek conn record into an anonymised record, or (None, reason) if it is dropped.

    Local endpoints are named by the pseudonym of their MAC address. If the frame came through a
    router (gateway MAC) the IP address is used instead and the record says so in 'ib'.
    Remote endpoints are never named: they get a service type and, only when wan_tokens is on,
    one-way tokens for the host, its /24 (or /48) and its registrable domain.
    """
    try:
        oh, rh = rec["id.orig_h"], rec["id.resp_h"]
        omac, rmac = rec.get("orig_l2_addr") or "", rec.get("resp_l2_addr") or ""
        os_, rs_ = scope.of(oh, omac, gateways), scope.of(rh, rmac, gateways)
    except (KeyError, ValueError):
        return None, "malformed"
    if os_ in ("mcast", "bcast"):
        return None, "group_source"
    if os_ == "wan" and rs_ != "lan":
        return None, "no_local_endpoint"
    proto = str(rec.get("proto") or "").lower()
    if not re.fullmatch(r"[a-z0-9_]{2,20}", proto):
        return None, "malformed"
    op, rp = _int(rec.get("id.orig_p"), -1), _int(rec.get("id.resp_p"), -1)
    out = {"ts": int(float(rec.get("ts", 0))), "dur": round(float(rec.get("duration") or 0), 3),
           "proto": proto, "op": op, "rp": rp, "os": os_, "rs": rs_,
           "st": _word(rec.get("conn_state"), 8), "hist": _word(rec.get("history"), 32, r"[A-Za-z^]"),
           "svc": _word(rec.get("service"), 24, r"[a-z0-9_,\-]"),
           "ob": _int(rec.get("orig_bytes")), "rb": _int(rec.get("resp_bytes")),
           "opk": _int(rec.get("orig_pkts")), "rpk": _int(rec.get("resp_pkts")),
           "est": established(rec), "vlan": _int(rec.get("vlan"), -1), "if": iface, "ib": "",
           "ipp": _int(rec.get("ip_proto"), -1)}

    def local(ip, mac, side):
        if mac and not is_group_mac(mac) and norm_mac(mac) not in gateways:
            return pz.device(mac)
        out["ib"] += side            # identity based on IP for this side
        return pz.device_by_ip(ip)

    out["o"] = local(oh, omac, "o") if os_ == "lan" else "wan"
    if rs_ == "lan":
        out["r"] = local(rh, rmac, "r")
    elif rs_ == "wan":
        out["r"] = "wan"
    else:
        out["r"] = group_label(rh, pz)
    if "wan" in (os_, rs_):
        wip = rh if rs_ == "wan" else oh
        dom = ip2dom.get(wip)
        reg = psl.registrable(dom) if dom else None
        out["wc"] = cat.category(reg, proto, rp)
        if wan_tokens:
            out["wh"], out["wn"] = pz.wan_host(wip), pz.wan_net(wip)
            out["wd"] = pz.domain(reg) if reg else ""
    return out, None


def _word(v, maxlen, charset=r"[A-Za-z0-9]"):
    s = str(v or "")
    return s[:maxlen] if re.fullmatch(charset + "*", s[:maxlen]) else ""


# ---------------------------------------------------------------- leak check

_LEAK_PATTERNS = (
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("mac", re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")),
    ("ipv6", re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}(?![0-9a-f:])|::[0-9a-f]{1,4}|[0-9a-f]{1,4}::")),
)
_ALLOWED = {
    "proto": re.compile(r"[a-z0-9_]{2,20}"), "os": re.compile(r"lan|wan"), "rs": re.compile(r"lan|wan|mcast|bcast"),
    "o": re.compile(r"wan|[di][a-z2-7]{10}"),
    "r": re.compile(r"wan|bcast|[di][a-z2-7]{10}|mcast:(?:[a-z0-9]{2,12}|og[a-z2-7]{8})"),
    "st": re.compile(r"[A-Za-z0-9]{0,8}"), "hist": re.compile(r"[A-Za-z^]{0,32}"),
    "svc": re.compile(r"[a-z0-9_,\-]{0,24}"), "ib": re.compile(r"o?r?"),
    "wc": re.compile(r"[a-z_]{2,24}"), "wh": re.compile(r"h[a-z2-7]{10}"), "wn": re.compile(r"n[a-z2-7]{10}"),
    "wd": re.compile(r"(?:m[a-z2-7]{10})?"),
}
_NUMERIC = {"ts", "dur", "op", "rp", "ob", "rb", "opk", "rpk", "vlan", "if", "ipp"}


def leak_check(record: dict):
    """Return None if the record is safe to write, else a short reason. Unknown fields are refused."""
    for k, v in record.items():
        if k in _NUMERIC:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                return f"field {k} is not numeric"
        elif k == "est":
            if not isinstance(v, bool):
                return "field est is not boolean"
        elif k in _ALLOWED:
            if not isinstance(v, str) or not _ALLOWED[k].fullmatch(v):
                return f"field {k} has an unexpected value"
        else:
            return f"unexpected field {k}"
    return None


def scan_text(text: str):
    """Last line of defence: refuse any output text that contains something shaped like an address."""
    for name, pat in _LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            return f"{name} pattern at offset {m.start()}"
    return None
