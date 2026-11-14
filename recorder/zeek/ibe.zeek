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

const ibe_keep: set[Log::ID] = { Conn::LOG, DNS::LOG, SSL::LOG, CaptureLoss::LOG, Stats::LOG } &redef;

# Veto every write to any other log stream, whatever script created it and whenever.
hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id !in ibe_keep )
        break;
    }
