# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
#
# Zeek configuration of the recorder. Run in bare mode, one process per capture interface:
#   zeek -b -C -i <interface> ibe.zeek
# Only connection metadata, DNS answers and TLS server names are logged, in JSON, to the
# working directory, which must be a RAM disk. Logs rotate every hour. No packet contents,
# no HTTP, no files, no notices are written.
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load policy/protocols/conn/mac-logging
@load policy/protocols/conn/vlan-logging
@load policy/misc/capture-loss
@load policy/misc/stats
@load policy/tuning/json-logs

redef Log::default_rotation_interval = 1 hr;
redef LogAscii::use_json = T;
# a log left open by a crash or a restart is rotated at the next start instead of being overwritten
redef LogAscii::enable_leftover_log_rotation = T;
redef CaptureLoss::watch_interval = 15 mins;
redef Stats::report_interval = 5 mins;

# Zeek forgets a silent TCP connection after 5 minutes and a silent UDP flow after 1 minute. When
# packets flow again it starts a new record in the middle of the conversation, and whoever speaks
# first then looks like the side that opened it. A day covers the keep-alive interval of common
# operating systems (2 hours), 2 minutes is the idle gap used for the public data sets.
redef tcp_inactivity_timeout = 1 day;
redef udp_inactivity_timeout = 2 mins;
# the DNS analyzer has a timeout of its own for flows on its ports (10 seconds by default)
redef dns_session_timeout = 2 mins;

# Zeek runs at most this many due timers per packet (300 by default). The hourly reports below are all
# due at the same moment and must all be written before the next packet is counted.
redef max_timer_expires = 100000000;

module IBE;

export {
    redef enum Log::ID += { OPEN_LOG, NEIGH_LOG };

    ## A connection that stays open is reported at every multiple of this interval on the clock in
    ## which it carried packets. With one hour and a time zone a whole number of hours from UTC, the
    ## packets of one report lie in one local day.
    const open_interval = 1 hr &redef;

    ## Most connections are gone within minutes. A first look after this time drops them, so that
    ## a port scan does not leave millions of pending checks in memory for an hour.
    const open_first_look = 5 mins &redef;

    ## How many TCP flows that never got going may be kept for the one day timeout: flows in which one
    ## side never spoke (a stray packet, an unanswered keep-alive, a scan with ACK or FIN packets) or the
    ## originator sent one packet only (a connection attempt from a made-up address that the server
    ## answered). A few are harmless, a million are not: beyond this number they get Zeek's own five minutes.
    const max_one_sided = 50000 &redef;

    ## How many addresses the neighbour log remembers at a time.
    const max_neighbours = 100000 &redef;

    ## One report about a connection that is still open, or about the last hours of one that just
    ## ended. Field names follow conn.log. The packet and byte counts cover the time since the
    ## previous report, not the whole connection.
    type OpenInfo: record {
        ts: time &log;                         ##< time of the last packet seen
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;
        ip_proto: count &log &optional;
        service: string &log &optional;
        duration: interval &log;               ##< age of the connection at the last packet
        history: string &log &optional;        ##< history letters of the whole connection so far
        orig_pkts: count &log;
        resp_pkts: count &log;
        orig_bytes: count &log;
        resp_bytes: count &log;
        orig_l2_addr: string &log &optional;
        resp_l2_addr: string &log &optional;
        vlan: int &log &optional;
    };

    ## Which MAC address answers for which IP address on the local link, as the devices tell each
    ## other (ARP, IPv6 neighbour discovery). Stays in RAM and on the key stick: the anonymiser uses
    ## it to name a device by its MAC address when a frame reached the capture port through a router.
    type NeighInfo: record {
        ts: time &log;
        ip: addr &log;
        mac: string &log;
    };

    global poll: event(id: conn_id, uid: string, first_look: bool);
}

redef record connection += {
    # what the previous report of this connection counted
    ibe_opk: count &default=0;
    ibe_rpk: count &default=0;
    ibe_ob: count &default=0;
    ibe_rb: count &default=0;
    ibe_one: bool &default=F;                  # counted in one_sided
    ibe_looked: bool &default=F;               # the first look has taken place
};

global one_sided = 0;

const keep: set[Log::ID] = { Conn::LOG, DNS::LOG, SSL::LOG, CaptureLoss::LOG, Stats::LOG, OPEN_LOG, NEIGH_LOG } &redef;

# Veto every write to any other log stream, whatever script created it and whenever.
hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id !in keep )
        break;
    }

event zeek_init()
    {
    Log::create_stream(OPEN_LOG, [$columns=OpenInfo, $path="open_conn"]);
    Log::create_stream(NEIGH_LOG, [$columns=NeighInfo, $path="neigh"]);
    }

# Zeek opens tunnels (IPv6 or IPv4 in IPv4, GRE, Teredo, AYIYA, VXLAN, Geneve, GTP) and logs the connections
# inside them, with the inner addresses and without MAC addresses. The device that keeps the tunnel then
# has no record of its own for protocols 4, 41 and 47, and the inner addresses look like devices. The
# recorder wants the flow of the device: the tunnel as one flow without ports, as in the public data.
# (Zeek prints one line per changed mapping when it starts.)
event zeek_init() &priority=-5
    {
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 4, PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 41, PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 47, PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT);
    local udp_tunnels: set[AllAnalyzers::Tag] = { PacketAnalyzer::ANALYZER_TEREDO, PacketAnalyzer::ANALYZER_AYIYA,
        PacketAnalyzer::ANALYZER_VXLAN, PacketAnalyzer::ANALYZER_GENEVE, PacketAnalyzer::ANALYZER_GTPV1 };
    for ( a in udp_tunnels )
        Analyzer::disable_analyzer(a);
    }

function grown(now: count, before: count): count
    {
    return now > before ? now - before : 0;
    }

# the number of the clock interval a time lies in
function slot(t: time): double
    {
    return floor(time_to_double(t) / interval_to_double(open_interval));
    }

# held_o, held_r: packets already counted that belong to the interval that just began (see poll)
function report(c: connection, held_o: count, held_r: count)
    {
    if ( ! c$orig?$num_pkts || ! c$resp?$num_pkts )
        return;
    local now_o = grown(c$orig$num_pkts, held_o);
    local now_r = grown(c$resp$num_pkts, held_r);
    local opk = grown(now_o, c$ibe_opk);
    local rpk = grown(now_r, c$ibe_rpk);
    if ( opk + rpk == 0 )
        return;                                # silent since the last report
    local last = c$start_time + c$duration;
    if ( held_o + held_r > 0 )
        {
        # the last packet before the full hour: its exact time is gone, any time in that hour will do
        last = double_to_time(slot(last) * interval_to_double(open_interval) - 0.001);
        if ( last < c$start_time )
            last = c$start_time;
        }
    local info = OpenInfo($ts=last, $uid=c$uid, $id=c$id,
                          $proto=get_port_transport_proto(c$id$resp_p), $duration=last - c$start_time,
                          $orig_pkts=opk, $resp_pkts=rpk,
                          $orig_bytes=grown(c$orig$size, c$ibe_ob), $resp_bytes=grown(c$resp$size, c$ibe_rb));
    c$ibe_opk = now_o;
    c$ibe_rpk = now_r;
    c$ibe_ob = c$orig$size;
    c$ibe_rb = c$resp$size;
    if ( c$id$proto != 65535 )
        info$ip_proto = c$id$proto;
    if ( |c$service| > 0 )
        info$service = to_lower(join_string_set(c$service, ","));
    if ( c$history != "" )
        info$history = c$history;
    if ( c$orig?$l2_addr )
        info$orig_l2_addr = c$orig$l2_addr;
    if ( c$resp?$l2_addr )
        info$resp_l2_addr = c$resp$l2_addr;
    if ( c?$vlan )
        info$vlan = c$vlan;
    Log::write(OPEN_LOG, info);
    }

# Reports are written on the clock (every full hour), not so many hours after the connection began.
# The packets one report covers then lie in one clock hour and so in one local day.
function to_next_report(): interval
    {
    local step = interval_to_double(open_interval);
    local wait = (slot(network_time()) + 1.0) * step - time_to_double(network_time());
    return double_to_interval(wait > 0.0 ? wait : step);
    }

function first_look_after(): interval
    {
    return open_first_look < open_interval ? open_first_look : open_interval;
    }

# Zeek 8.0 finds a flow without ports (ICMP) under one order of its two addresses only.
function findable(id: conn_id): conn_id
    {
    if ( connection_exists(id) )
        return id;
    local back = copy(id);
    back$orig_h = id$resp_h;
    back$orig_p = id$resp_p;
    back$resp_h = id$orig_h;
    back$resp_p = id$orig_p;
    return back;
    }

event IBE::poll(id: conn_id, uid: string, first_look: bool)
    {
    if ( zeek_is_terminating() || ! connection_exists(id) )
        return;
    local c = lookup_connection(id);           # also refreshes the counters
    if ( c$uid != uid )
        return;                                # a later connection with the same addresses has its own poll
    if ( first_look )
        {
        c$ibe_looked = T;
        if ( get_port_transport_proto(c$id$resp_p) == tcp && c$orig?$num_pkts && c$resp?$num_pkts
                  && ( c$orig$num_pkts < 2 || c$resp$num_pkts == 0 ) )
            {
            if ( one_sided >= max_one_sided )
                set_inactivity_timeout(id, 5 mins);
            else
                {
                c$ibe_one = T;
                ++one_sided;
                }
            }
        }
    else
        {
        # The clock is moved over the full hour by a packet, and that packet is counted before this
        # check runs. If it is a packet of this connection it is the only one that belongs to the
        # hour that just began: it is left for the next report.
        local held_o = 0;
        local held_r = 0;
        if ( slot(c$start_time + c$duration) == slot(network_time()) )
            {
            local h = get_current_packet_header();
            local src = c$id$resp_h;
            if ( h?$ip )
                src = h$ip$src;
            else if ( h?$ip6 )
                src = h$ip6$src;
            else if ( c$resp?$num_pkts && grown(c$resp$num_pkts, c$ibe_rpk) == 0 )
                src = c$id$orig_h;
            if ( src == c$id$orig_h )
                held_o = 1;
            else
                held_r = 1;
            }
        report(c, held_o, held_r);
        }
    # A connection that began just before a full hour was reported first. Its first look is still due.
    local look_in = c$start_time + first_look_after() - network_time();
    if ( ! c$ibe_looked && look_in < to_next_report() )
        schedule (look_in > 0 secs ? look_in : 0 secs) { IBE::poll(id, uid, T) };
    else
        schedule to_next_report() { IBE::poll(id, uid, F) };
    }

event new_connection(c: connection)
    {
    # Packets from the unspecified address (DHCP, IPv6 duplicate address detection) have the same
    # addresses and ports whichever device sends them. Such a record is ended at once, so that the
    # next sender gets a record of its own with its own MAC address.
    if ( c$id$orig_h == 0.0.0.0 || c$id$orig_h == [::] )
        {
        set_inactivity_timeout(findable(c$id), 1 msec);
        return;
        }
    # a first look after a few minutes, or the report on the clock if that comes first
    local look = first_look_after();
    local wait = to_next_report();
    if ( wait <= look )
        schedule wait { IBE::poll(findable(c$id), c$uid, F) };
    else
        schedule look { IBE::poll(findable(c$id), c$uid, T) };
    }

# The finished record is stamped with the start of the connection. If its last packet lies in a later
# clock interval, a last report says so, and which side sent packets since the previous report.
event connection_state_remove(c: connection)
    {
    if ( c$ibe_one && one_sided > 0 )
        --one_sided;
    if ( slot(c$start_time + c$duration) > slot(c$start_time) )
        report(c, 0, 0);
    }

# ---- who is where on the local link

global neigh_seen: table[addr] of string &create_expire=10 mins;

function neighbour(ip: addr, mac: string)
    {
    if ( ip == 0.0.0.0 || ip == [::] )
        return;                                # a probe for an address the sender does not have yet
    if ( ip in neigh_seen )
        {
        if ( neigh_seen[ip] == mac )
            return;                            # written within the last ten minutes
        }
    else if ( |neigh_seen| >= max_neighbours )
        return;
    neigh_seen[ip] = mac;
    Log::write(NEIGH_LOG, NeighInfo($ts=network_time(), $ip=ip, $mac=mac));
    }

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    if ( mac_src == SHA )
        neighbour(SPA, SHA);
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    if ( mac_src == SHA )
        neighbour(SPA, SHA);
    }

# Neighbour discovery never crosses a router (hop limit 255), so the source MAC address of the
# frame is the sender's own. An advertisement also names the address it speaks for.
function nd_sender(tgt: addr, advert: bool)
    {
    local h = get_current_packet_header();
    if ( ! h?$ip6 || h$ip6$hlim != 255 || ! h$l2?$src )
        return;
    neighbour(h$ip6$src, h$l2$src);
    if ( advert )
        neighbour(tgt, h$l2$src);
    }

event icmp_neighbor_solicitation(c: connection, info: icmp_info, tgt: addr, options: icmp6_nd_options)
    {
    nd_sender(tgt, F);
    }

event icmp_neighbor_advertisement(c: connection, info: icmp_info, router: bool, solicited: bool,
                                  override: bool, tgt: addr, options: icmp6_nd_options)
    {
    nd_sender(tgt, T);
    }
