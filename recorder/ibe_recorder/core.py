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
import math
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
# The service types a remote host can carry. A service type is a word that leaves the site, so the list is
# closed: rules, built in or from the key stick, can only assign domains to these words.
CATEGORIES = ("dns", "time", "dhcp", "mdns", "os_update", "remote_access", "vendor_cloud", "connectivity_check",
              "other", "unknown")

_B32 = re.compile(r"^[a-z2-7]+$")

# What Zeek can write into these fields. Anything else is not copied.
PROTOCOLS = ("tcp", "udp", "icmp", "unknown_transport")
CONN_STATES = ("S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")
HISTORY_LETTERS = "SHADFRCGTWIQX"             # and their lower case forms, and ^ (Zeek: base/protocols/conn/main.zeek)
SERVICES = frozenset("""dns ssl dtls quic http ftp ftp-data ssh smtp pop3 imap irc irc-data dhcp ntp snmp smb
    dce_rpc gssapi krb krb_tcp ntlm rdp rfb sip syslog ldap ldap_tcp ldap_udp mysql postgresql modbus dnp3 mqtt
    radius socks teredo ayiya gtpv1 vxlan geneve xmpp websocket ncp tftp netbios redis ssdp mdns""".split())
_HIST = "[" + HISTORY_LETTERS + HISTORY_LETTERS.lower() + "^]"
MAX_COUNT = 2 ** 53                            # exact in every JSON reader, far above any real counter


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


def nets_problem(local_nets):
    """Why a list of local networks cannot be used, or None. A network wider than the widest private range
    (10.0.0.0/8, fc00::/7) is refused: it would turn remote hosts into local ones, and a local host is named
    by a token of its address in every record, which for remote hosts needs the site's written permission."""
    for n in local_nets:
        net = ipaddress.ip_network(n, strict=False)        # ValueError if it is not a network
        if net.prefixlen < (8 if net.version == 4 else 7):
            return "a local network is wider than /8 (IPv4) or /7 (IPv6)"
    return None


def public_nets(local_nets):
    """How many of the local networks lie outside the private, link-local and shared ranges."""
    return sum(1 for n in local_nets
               if not any(ipaddress.ip_network(n, strict=False).subnet_of(d) for d in map(ipaddress.ip_network, DEFAULT_LOCAL_NETS)
                          if d.version == ipaddress.ip_network(n, strict=False).version))


def nets_within(nets, allowed):
    """True if every network of the first list lies inside a network of the second: a list from the key
    stick can then only narrow the list of the configuration."""
    allowed = [ipaddress.ip_network(a, strict=False) for a in allowed]
    return all(any(n.version == a.version and n.subnet_of(a) for a in allowed)
               for n in (ipaddress.ip_network(x, strict=False) for x in nets))


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

    def of(self, ip: str, mac: str = "", *, on_link: bool = False) -> str:
        """lan | wan | mcast | bcast.

        An address outside the configured local networks is remote, whatever MAC address the frame
        carries: a frame on its way to the internet carries the MAC address of a router, and a
        router is not always known as one. The one exception is decided by the caller (on_link, see
        transform): the frame carries the very MAC address that answers for the address on the
        mirrored network. This covers sites that use public IPv4 space or global IPv6 addresses inside.
        """
        a = _ip(ip)
        if a.is_multicast:
            return "mcast"
        if a.version == 4 and (str(a) == "255.255.255.255" or (mac and norm_mac(mac) == "f" * 12)):
            return "bcast"
        if self.is_local_ip(ip) or on_link:
            return "lan"
        return "wan"


@functools.lru_cache(maxsize=200000)
def _norm_ip(ip: str) -> str:
    return str(_ip(ip))


def _finite(t) -> bool:
    """A number that a float can hold. A whole number of 400 digits is a number in JSON, and is not one here."""
    try:
        return isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(t)
    except OverflowError:
        return False


class Neighbours:
    """Which MAC address answers for which IP address on the local link, as the devices tell each
    other in ARP and IPv6 neighbour discovery (zeek/ibe.zeek, neigh.log).

    Used where a frame does not carry the MAC address of the device itself: a frame that reached
    the capture port through a router carries the router's. The table holds real addresses. It is
    kept on the key stick and never leaves the site.

    table: {ip: [[mac, first seen, last seen], ...]}, oldest owner first.
    """
    KEEP = 4                    # owners remembered per address
    CAP = 50000                 # addresses
    FORGET_S = 35 * 86400       # an address not seen for this long is forgotten

    def __init__(self, table=None):
        self.table = {}
        for ip, owners in (table.items() if isinstance(table, dict) else ()):
            good = []
            for e in owners if isinstance(owners, list) else ():
                if isinstance(e, list) and len(e) == 3 and isinstance(e[0], str) and re.fullmatch(r"[0-9a-f]{12}", e[0]) \
                        and all(_finite(t) for t in e[1:]):
                    good.append([e[0], float(e[1]), float(e[2])])
            try:
                if good and isinstance(ip, str) and _norm_ip(ip) == ip:
                    self.table[ip] = sorted(good, key=lambda e: e[1])[-self.KEEP:]
            except ValueError:
                continue

    def see(self, ts, ip, mac) -> bool:
        """One sighting. Returns False if it is not a usable pair of a unicast address and a device MAC."""
        if not isinstance(ip, str) or not isinstance(mac, str) or isinstance(ts, bool):
            return False
        try:
            ts = float(ts)
            a = _ip(ip)
            m = norm_mac(mac)
        except (ValueError, TypeError, OverflowError):
            return False
        if not (0 < ts < 1e11) or a.is_multicast or a.is_unspecified or a.is_loopback \
                or str(a) == "255.255.255.255" or is_group_mac(m) or m == "0" * 12:
            return False
        owners = self.table.setdefault(str(a), [])
        if owners and owners[-1][0] == m:
            owners[-1][1], owners[-1][2] = min(owners[-1][1], ts), max(owners[-1][2], ts)
        else:
            owners.append([m, ts, ts])
            owners.sort(key=lambda e: e[1])
            del owners[:-self.KEEP]
        return True

    def _entry(self, ip, ts):
        owners = self.table.get(ip)
        if owners is None:
            try:
                owners = self.table.get(_norm_ip(ip))
            except (ValueError, TypeError):
                return None
        if not owners:
            return None
        best = owners[0]            # before the first sighting: the first owner known
        for e in owners:
            if e[1] <= ts + 1:
                best = e
        return best

    def at(self, ip, ts):
        """The MAC address (12 hex digits) that answered for this address at that time, or None."""
        e = self._entry(ip, ts)
        return e[0] if e else None

    def live_at(self, ip, ts, within=3600):
        """As at(), but only if that MAC address was seen with the address around that time."""
        e = self._entry(ip, ts)
        return e[0] if e and e[1] <= ts + 1 and e[2] >= ts - within else None

    def owned_by(self, ip, mac) -> bool:
        """True if this MAC address ever answered for the address."""
        e = self.table.get(ip) or []
        return any(x[0] == mac for x in e)

    def dump(self, now):
        """The table to store: old addresses forgotten, the most recently seen kept if there are too many."""
        live = {ip: v for ip, v in self.table.items() if v and v[-1][2] >= now - self.FORGET_S}
        if len(live) > self.CAP:
            keep = sorted(live, key=lambda ip: live[ip][-1][2])[-self.CAP:]
            live = {ip: live[ip] for ip in keep}
        return live


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
        if not isinstance(name, str):
            return None
        name = name.lower().rstrip(".")
        if not name or len(name) > 253 or name.replace(".", "").isdigit() or ":" in name:
            return None                    # longer than any DNS name: not a name, and costly to take apart
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
                if cat not in CATEGORIES:
                    raise ValueError("a category that is not one of the built-in ones")
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
    except (TypeError, ValueError, OverflowError):
        return default


def read_history(text):
    """Zeek's history letters, each in the final direction of the record.

    A capital letter is a packet of the originator, a small one of the responder. Zeek turns a record round
    when it learns that the other side opened the connection (it saw the SYN-ACK before the SYN) and marks
    the place with '^'. The letters before the mark keep the case of the old direction, so they are turned
    here: 'Hs^R' (a SYN-ACK, the SYN of the other side, the turn, a reset) is read as 'hS^R'. A record that
    Zeek turned before its first letter ('^d') reads the same.
    """
    if not isinstance(text, str):
        return text
    out = ""
    for c in text:
        out = (out.swapcase() if c == "^" else out) + c
    return out


def established(rec: dict, is_open: bool = False) -> bool:
    """True if the responder took part in the connection.

    TCP: the responder sent a SYN-ACK, an acknowledgement, data or a FIN (Zeek history letters
    h, a, d, f). A reset alone is a refusal. Other protocols: any packet or byte from the responder.
    A report about a connection that is still open counts the packets since the previous report,
    so there the responder must also have sent a packet in that interval.
    """
    answered = _int(rec.get("resp_pkts")) > 0 or _int(rec.get("resp_bytes")) > 0
    if is_open:
        # packets only: the bytes of a report include those of a packet that is held back for the next report
        answered = _int(rec.get("resp_pkts")) > 0
    if rec.get("proto") == "tcp":
        took_part = any(c in "hadf" for c in str(read_history(rec.get("history")) or ""))
        return took_part and (answered or not is_open)
    return answered


def transform(rec: dict, pz: Pseudonymiser, scope: Scope, gateways: set, wan_tokens: bool,
              ip2dom: dict, psl: PublicSuffix, cat: Categoriser, iface: int = 0, is_open: bool = False,
              neigh: "Neighbours | None" = None):
    """Turn one Zeek conn record into an anonymised record, or (None, reason) if it is dropped.

    is_open marks a report about a connection that is still open (see zeek/ibe.zeek): its time is
    that of the last packet and its counts cover the time since the previous report.

    Local endpoints are named by the pseudonym of their MAC address. If the frame came through a
    router (gateway MAC) the device is named by the MAC address that answers for its IP address on
    the local link (neigh), and only if none is known by the IP address: the record then says so
    in 'ib'. Remote endpoints are never named: they get a service type and, only when wan_tokens
    is on, one-way tokens for the host, its /24 (or /48) and its registrable domain.
    """
    try:
        oh, rh = rec["id.orig_h"], rec["id.resp_h"]
        omac, rmac = rec.get("orig_l2_addr") or "", rec.get("resp_l2_addr") or ""
        if not all(isinstance(x, str) for x in (oh, rh, omac, rmac)):
            raise ValueError("type")
        for mac in (omac, rmac):
            if mac:
                norm_mac(mac)
        ts, dur = float(rec["ts"]), float(rec.get("duration") or 0)
        if not (0 < ts < 1e11 and math.isfinite(dur)):          # 1e11 is the year 5138, also excludes inf and nan
            raise ValueError("time")

        def side_scope(ip, mac):
            # An address outside the local networks is a device of the site only on the evidence of this
            # very frame: it carries the MAC address that answers for the address on the mirrored network,
            # and that MAC address is not a router. An entry in the neighbour table alone names nobody. A
            # remote host reaches the capture port through a router, whatever the table (which is kept on
            # the key stick, and which any device can add to with an ARP frame) says about its address.
            m = norm_mac(mac) if mac and not is_group_mac(mac) else None
            return scope.of(ip, mac, on_link=bool(m and neigh is not None and m not in gateways
                                                  and neigh.at(ip, ts) == m))
        os_, rs_ = side_scope(oh, omac), side_scope(rh, rmac)
        if os_ in ("mcast", "bcast") and rs_ == "lan":
            # A group address never sends. Zeek has turned the record around (a datagram that left one of
            # its "likely server ports" for a group): the sender is the device it calls the responder.
            rec = _turned(rec)
            oh, rh, omac, rmac, os_, rs_ = rh, oh, rmac, omac, rs_, os_
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        return None, "malformed"
    if os_ in ("mcast", "bcast"):
        return None, "group_source"
    if os_ == "wan" and rs_ != "lan":
        return None, "no_local_endpoint"
    proto = str(rec.get("proto") or "").lower()
    if proto not in PROTOCOLS:
        return None, "malformed"
    op, rp = _port(rec.get("id.orig_p")), _port(rec.get("id.resp_p"))
    out = {"ts": int(ts), "dur": round(dur, 3),
           "proto": proto, "op": op, "rp": rp, "os": os_, "rs": rs_,
           "st": rec.get("conn_state") if rec.get("conn_state") in CONN_STATES else "",
           "hist": _word(read_history(rec.get("history")), 32, _HIST), "svc": _services(rec.get("service")),
           "ob": _count(rec.get("orig_bytes")), "rb": _count(rec.get("resp_bytes")),
           "opk": _count(rec.get("orig_pkts")), "rpk": _count(rec.get("resp_pkts")),
           "est": established(rec, is_open), "vlan": _ranged(rec.get("vlan"), 0, 4095), "if": iface, "ib": "",
           "ipp": _ranged(rec.get("ip_proto"), 0, 255)}
    if not 0 <= dur < 4e8:
        out["dur"] = 0.0
    if is_open:
        out["open"] = True

    def local(ip, mac, side):
        if mac and not is_group_mac(mac) and norm_mac(mac) not in gateways:
            return pz.device(mac)        # the frame itself carries the device's MAC address
        owner = neigh.at(ip, ts) if neigh is not None else None
        if owner:
            return pz.device(owner)      # through a router, but the device is known on a mirrored network
        out["ib"] += side                # identity based on IP for this side
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


def _turned(rec):
    """The same record with its two ends exchanged."""
    out = dict(rec)
    for a, b in (("id.orig_h", "id.resp_h"), ("id.orig_p", "id.resp_p"), ("orig_l2_addr", "resp_l2_addr"),
                 ("orig_bytes", "resp_bytes"), ("orig_pkts", "resp_pkts")):
        out[a], out[b] = rec.get(b), rec.get(a)
    if isinstance(rec.get("history"), str):
        out["history"] = rec["history"].replace("^", "").swapcase()
    return out


def _ranged(v, lo, hi, default=-1):
    v = _int(v, default) if not isinstance(v, bool) else default
    return v if lo <= v <= hi else default


def _port(v):
    return _ranged(v, 0, 65535)


def _count(v):
    return _ranged(v, 0, MAX_COUNT, 0)


def _services(v):
    """Zeek's service names, comma separated. A name Zeek does not have is left out, and so is a name
    that no longer fits into 24 characters: half a name would not be a name."""
    out = ""
    for x in str(v or "").split(","):
        if x in SERVICES and x not in out.split(",") and len(out) + len(x) + bool(out) <= 24:
            out += ("," if out else "") + x
    return out


def _word(v, maxlen, charset=r"[A-Za-z0-9]"):
    s = str(v or "")
    return s[:maxlen] if re.fullmatch(charset + "*", s[:maxlen]) else ""


# ---------------------------------------------------------------- leak check

_LEAK_PATTERNS = (
    # no dot in the look-around: an address at the end of a sentence ("... 192.168.1.20.") is an address too
    ("ipv4", re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")),
    ("mac", re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")),
    ("ipv6", re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}(?![0-9a-f:])|::[0-9a-f]{1,4}|[0-9a-f]{1,4}::")),
)
_ALLOWED = {
    "proto": re.compile("|".join(PROTOCOLS)), "os": re.compile(r"lan|wan"), "rs": re.compile(r"lan|wan|mcast|bcast"),
    "o": re.compile(r"wan|[di][a-z2-7]{10}"),
    "r": re.compile(r"wan|bcast|[di][a-z2-7]{10}|mcast:(?:%s|sn|og[a-z2-7]{8})" % "|".join(sorted(set(GROUP_LABELS.values())))),
    "st": re.compile("|".join(CONN_STATES) + "|"), "hist": re.compile(_HIST + "{0,32}"),
    "svc": re.compile(r"(?:(?:%s)(?:,(?!$)|$))*" % "|".join(sorted(SERVICES, key=len, reverse=True))), "ib": re.compile(r"o?r?"),
    "wc": re.compile("|".join(CATEGORIES)), "wh": re.compile(r"h[a-z2-7]{10}"), "wn": re.compile(r"n[a-z2-7]{10}"),
    "wd": re.compile(r"(?:m[a-z2-7]{10})?"),
}
# the range transform() gives each number. Only the duration has a fraction.
_NUMERIC = {"ts": (1, 10 ** 11), "dur": (0, 4e8), "op": (-1, 65535), "rp": (-1, 65535), "ob": (0, MAX_COUNT),
            "rb": (0, MAX_COUNT), "opk": (0, MAX_COUNT), "rpk": (0, MAX_COUNT), "vlan": (-1, 4095), "if": (0, 255),
            "ipp": (-1, 255)}


def leak_check(record: dict, categories=None):
    """Return None if the record is safe to write, else a short reason. Unknown fields are refused.
    categories: the service types that may be written (wc). Without it any lower-case word passes."""
    for k, v in record.items():
        if k in _NUMERIC:
            lo, hi = _NUMERIC[k]
            if isinstance(v, bool) or not isinstance(v, (int, float) if k == "dur" else int) or not lo <= v <= hi:
                return f"field {k} is not numeric or out of range"
        elif k == "wc" and categories is not None and v not in categories:
            return f"field {k} has an unexpected value"
        elif k in ("est", "open"):
            if not isinstance(v, bool):
                return f"field {k} is not boolean"
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
