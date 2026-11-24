# Inventory before enforcement

How long must a network be watched before per-device allowlists can be switched on?

Devices that cannot run security software (printers, IP phones, cameras, medical devices and the
vendor-managed PCs that drive them) can still be protected from the network side: the gateway allows
each device only the connections it is known to need. The list of needed connections has to be learned
from passive observation, and the open question is when to stop observing. Stop too early and the
allowlist blocks legitimate traffic. Wait too long and the device stays unprotected.

This repository holds the code of a study that answers the question with a statistical stopping
rule and tests it on public traces and at clinical sites.

| Part | What it is |
|---|---|
| [`recorder/`](recorder/) | On-device anonymising recorder. It watches a mirror port, keeps connection metadata only, replaces every device identity by a keyed pseudonym before anything is written to disk, and stops by itself at the permitted number of recording days |
| [`analysis/`](analysis/) | The frozen analysis: flow types, the Good-Turing estimate of tomorrow's unseen flow types, the stopping rule GT-C, the evaluation, and an independent re-implementation used as a cross-check |
| [`docs/`](docs/) | The method as frozen before the clinical data exists, the site setup guide, the data sources, the platform selection |
| [`paper/`](paper/) | Figure scripts and drafts |

## The idea in five lines

1. A **flow type** is one allowlist rule: transport / role / service port @ peer.
2. Each device is observed per active local day. After T days, Q1(T) flow types have been seen on exactly one day.
3. If days are exchangeable, the expected number of new flow types tomorrow is no larger than the expected value of Q1(T)/T (Good-Turing).
4. **GT-C** adds a 95 percent margin and a drift correction: enforce on the first day T ≥ 7 on which the bound U(T) falls below the tolerated rate ε of new flow types per day.
5. The rule is judged by what happens next: the share of devices whose alert-day rate in the following 14 active days exceeds ε.

The full definitions, the parameters and the three expectations written down in advance are in
[`docs/method.md`](docs/method.md).

## Status

- Method and metrics are frozen. Changes are only made as dated notes in `docs/method.md`.
- The analysis runs on five public data sources (see [`docs/data.md`](docs/data.md)). Every stored table was reproduced from scratch and checked by a second implementation written from the method text alone.
- The recorder is implemented and tested end to end on real traffic (see below). Recording at clinical sites starts only after ethics approval.

## Quick check

```bash
pip install duckdb pandas numpy scipy pyarrow
python3 -m unittest discover -s recorder/tests -p 'test_*.py'      # recorder rules, installer
python3 -m unittest discover -s analysis/tests -p 'test_*.py'      # outage rule, roles, hourly reports
```

With Zeek 8.0 installed:

```bash
python3 recorder/tests/scenarios.py --work /tmp/ibe-scenarios
python3 recorder/tests/e2e.py --pcap capture.pcap --work /tmp/ibe-e2e      # any capture of less than a day
```

`scenarios.py` builds a capture by hand with one case for every situation that a connection log
gets wrong unless it is handled on purpose (a connection open for 50 hours, one that never closes,
one picked up in the middle with the server speaking first, 20 minutes of silence, a slow answer,
refusals, midnight, three devices asking for an address at once, a ping that runs for days, a device
that is switched off, two VLANs joined by a router, tunnels, an answer that comes after the client
has given up, a name server that never answers, two capture ports that see the same flow
differently) and checks that the chain gives exactly the flow types written down beforehand for
every device and day.

`e2e.py` replays a real capture as 30 identical days through Zeek, the recorder, the adapter and
the analysis, and checks answers that are known in advance: nothing identifying leaves the
recorder, every record is accounted for, two mirror ports give the same records as one, the flow
types equal those of a second implementation of the same rules, and GT-C stops on day 10 for ε = 0.3 on every device.

## Privacy by construction

The recorder is built so that the researchers never hold identifying data.

- Raw logs exist only in RAM and are deleted every hour, whether or not the hour could be written. The recorder refuses to record if its log directory is not a RAM disk or if any swap could move memory to a disk.
- Local devices are named by HMAC-SHA256 pseudonyms. The key is created on site, lives on a USB stick that stays there, and is never copied. Pulling the stick stops the recording.
- Remote hosts are never named. They carry a coarse service type and, only where the site's written permission covers it, one-way tokens.
- No packet contents, URLs or user names are kept. Names of hosts are read on site only, to derive a service type and to refuse the name of a computer that is typed where a brand or model belongs. The brand and model text itself is exported as a keyed code only, and the site sends the short list of products by hand after reading it. Names stay in RAM or on the key stick and are never written into a record.
- Every record passes a field whitelist, and every output file passes a scan for anything shaped like an address.
- Capture ports cannot transmit: a kernel rule drops every outgoing frame.
- Recording starts only after the ethics approval reference has been entered on site, and stops by itself after the permitted number of days.

Details and the tests behind each statement: [`recorder/README.md`](recorder/README.md).

## Licence and citation

Code: Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The bundled Public Suffix
List is under the Mozilla Public License 2.0. Third-party datasets are not redistributed here.

If you use this code, please cite it as described in [`CITATION.cff`](CITATION.cff).
