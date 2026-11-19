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

module IBE;

export {
    redef enum Log::ID += { OPEN_LOG };

    ## A connection that stays open is reported once per interval in which it carried packets.
    const open_interval = 1 hr &redef;

    ## Most connections are gone within minutes. A first look after this time drops them, so that
    ## a port scan does not leave millions of pending checks in memory for an hour.
    const open_first_look = 5 mins &redef;

    ## One report about a connection that is still open. Field names follow conn.log. The packet
    ## and byte counts cover the time since the previous report, not the whole connection.
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

    global poll: event(id: conn_id, uid: string, first_look: bool);
}

# what the previous report of this connection counted
redef record connection += {
    ibe_opk: count &default=0;
    ibe_rpk: count &default=0;
    ibe_ob: count &default=0;
    ibe_rb: count &default=0;
};

const keep: set[Log::ID] = { Conn::LOG, DNS::LOG, SSL::LOG, CaptureLoss::LOG, Stats::LOG, OPEN_LOG } &redef;

# Veto every write to any other log stream, whatever script created it and whenever.
hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id !in keep )
        break;
    }

event zeek_init()
    {
    Log::create_stream(OPEN_LOG, [$columns=OpenInfo, $path="open_conn"]);
    }

function grown(now: count, before: count): count
    {
    return now > before ? now - before : 0;
    }

function report(c: connection)
    {
    if ( ! c$orig?$num_pkts || ! c$resp?$num_pkts )
        return;
    local opk = grown(c$orig$num_pkts, c$ibe_opk);
    local rpk = grown(c$resp$num_pkts, c$ibe_rpk);
    if ( opk + rpk == 0 )
        return;                                # silent since the last report
    local info = OpenInfo($ts=c$start_time + c$duration, $uid=c$uid, $id=c$id,
                          $proto=get_port_transport_proto(c$id$resp_p), $duration=c$duration,
                          $orig_pkts=opk, $resp_pkts=rpk,
                          $orig_bytes=grown(c$orig$size, c$ibe_ob), $resp_bytes=grown(c$resp$size, c$ibe_rb));
    c$ibe_opk = c$orig$num_pkts;
    c$ibe_rpk = c$resp$num_pkts;
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

function first_look_after(): interval
    {
    return open_first_look < open_interval ? open_first_look : open_interval;
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
        # the first report is due one interval after the connection started, however late this look ran
        local due = c$start_time + open_interval;
        local wait = due > network_time() ? due - network_time() : 0 secs;
        schedule wait { IBE::poll(id, uid, F) };
        return;
        }
    report(c);
    schedule open_interval { IBE::poll(id, uid, F) };
    }

event new_connection(c: connection)
    {
    schedule first_look_after() { IBE::poll(c$id, c$uid, T) };
    }
