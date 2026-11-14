# The method, frozen on 11 November 2026

Purpose: fix the method and the primary metrics before new data (UNSW 2025, HVAC, clinical sites)
is seen. Those data are the validation set. Nothing below is changed after looking at them. If a
change becomes necessary it is added here as a dated note and stated in the paper.

This file is the English text of the project's freeze record. The clinical sites are called Site A
and Site B. Site A is a private eye medical centre in Türkiye.

## Data preparation

- **Flow type**: transport / role / service port @ peer. Service ports 32768 and above form one class.
- **Role**: in connection logs (Zeek, clinical sites) the side that opens the connection. In flow exports: port fan-out, then a port below 1024, then equal ports, then the recorded initiator, then the lower port.
- **Participation filter**: an inbound service counts on a day only if the device sent data to that peer on that day (in Zeek data: the connection was established).
- **LAN peer identity**: MAC address or device pseudonym. WAN peer according to the level.
- **Primary level of detail**: svc (LAN peer fixed, WAN free). Secondary: port and net.
- **Sampling unit**: a local day on which the device is active. The first and the last, partial, day are dropped.

Levels of detail of the peer label:

| Level | Peer label |
|---|---|
| proto | scope only (wan, lan, mcast, bcast), service port dropped |
| port | scope only |
| svc | LAN peer identity, any WAN host |
| dom | LAN peer identity, WAN registered domain when known |
| net | LAN peer identity, WAN /24 (IPv4) or /48 (IPv6) |
| host | exact peer |

## Estimate and rule

- **Rate estimate**: Q1(T)/T, where Q1(T) is the number of flow types seen on exactly one of the first T days.
- **GT-C**: U(T) = χ²(0.95 quantile, 2(Q1+1) degrees of freedom)/(2T) + the positive part of the mean of the last 14 prediction errors N(t) − Q1(t−1)/(t−1), if at least 3 errors exist. N(t) is the number of new flow types on day t.
- **Rule**: enforce on the first day with T ≥ 7 and U(T) ≤ ε.
- **Primary target**: ε = 0.3 per day. Secondary: 1.0 and 0.1.

## Metrics

- **Primary**: the share of learning episodes in which the alert-day rate over the 14 active days after enforcement exceeds ε. 95 percent interval by cluster bootstrap over devices. An alert day is a day with at least one flow type that is not on the allowlist.
- **Secondary**: the share in which the rate of new flow types exceeds ε, the share of learning episodes that reach enforcement, the median enforcement day, the median calibration ratio per device, the Kaplan-Meier certification curve.
- **Comparison**: fixed 7, 14, 21 and 28 days, the quiet streak (3/ε days without a new type), the discovery rate of the last 14 days.
- **Learning episodes**: day 0 for every device and, if the trace is long enough, a new start every 21 days.

## Expectations written in advance

1. In the control network (HVAC) and the clinical data the calibration ratio is about 1 or below (little drift).
2. The alert-day exceedance share of GT-C stays below 10 percent.
3. Fixed windows are clearly worse at the net level.

If these do not hold, the paper reports them as they are.

## Dated notes

**11 November 2026, validation on UNSW 2025 and HVAC.** Estimate, rule and metrics unchanged. The
data formats required three adaptations: (1) UNSW 2025 has no payload length, so the participation
filter uses a proxy (bytes the device sent within its first 10 packets, for TCP more than 132 bytes).
(2) LAN peer identity is the IP address in UNSW 2025. (3) HVAC lasts 7 days, so a 6-hour unit was
used and that part counts as exploratory. The note recorded at the time that all three expectations
held. The audit of 12 November corrected this for expectation 1 on HVAC (point 3 below).
Expectations 1, 2 and 3 remain open for the clinical data.

**12 November 2026, third audit.** Estimate, rule, primary metric and the three expectations unchanged.

1. *Implementation fix.* In the 12-home data the payload sent by the device is now read relative to the record's `device` field. Before, records opened from outside read the payload of the other side. The definition of the participation filter is the same, the code was made to follow it. Effect on results at most 0.007.
2. *Explicit definition of calibration.* The earlier definition was ambiguous and contained a smoothing term of 0.5. Valid definition: first learning episode of every device, T ≥ 7, ratio = total realised new types / total Q1(T)/T. Two numbers are reported together: the pooled ratio (with a cluster bootstrap interval over devices) and the per-device median over devices with a positive estimate. No smoothing. The number of completely silent devices is stated separately. Expectation 1 is tested with this definition in the clinical data.
3. *Expectation 1 on HVAC corrected.* With the 6-hour unit the pooled ratio is 1.89 (port), 2.47 (svc), 1.08 (net), so it did not hold. With a 1-hour unit it is 0.93 to 1.03. The earlier "median 1.00" was an artefact of the smoothing. Expectations 2 and 3 held on all three validation sets.
4. *Secondary analyses registered before the clinical data.* The primary metric (next 14 active days, alert-day exceedance) stays. In addition: (a) the same metrics with the next 7 active days, (b) a sensitivity analysis with weekdays only, (c) the exceedance of fixed 14 days among the devices GT-C certifies and among those it rejects (discrimination), (d) comparison with a quiet-streak rule tuned to certify the same share as GT-C, (e) calibration and coverage of the alert-day estimate D(T)/T and of the distribution-free bound. D(T) is the number of the first T days that carry a type seen on no other day. These were added after looking at the public data, so they are exploratory there and pre-registered for the clinical data.
5. *The svcx sensitivity level* is for public data only (LAN peers that are not catalogued devices and IPv6 solicited-node groups collapse to one class each). The primary level stays svc. At clinical sites the peer identity is the MAC pseudonym.

**14 November 2026, definitions for clinical sites (before any clinical data).** Estimate, rule, primary metric and the three expectations unchanged. These notes fix how the method is applied on site.

1. *Local day.* The local time of the site (Site A: Europe/Istanbul).
2. *Working days.* Site A works six days a week (Monday to Friday full days, Saturday half day). The definition of an active day is unchanged: a local day on which the device produces traffic. For devices that are always on, Sunday is an active day too. The weekday sensitivity analysis of 12 November is reported with two definitions: Monday to Friday, and Monday to Saturday.
3. *Outage days.* A day on which the recorder was down for more than one hour in total inside working hours is a partial day and is dropped (an extension of the rule for the first and last partial day).
4. *Analysis groups.* The site's IT officer classifies the devices before recording starts.
   - Primary group: agentless and fully visible devices. Agentless: embedded devices (IP phone, printer, storage, recorder, camera, medical device) and medical device PCs on which the institution installs no security software because the vendor manages them. Fully visible: all traffic of the device with other devices passes a mirrored port. A PC connected behind an IP phone, and that phone, count as fully visible.
   - Secondary group: general purpose devices (PC, server, virtual machine).
   - Reported separately: partially visible devices (behind an unmanaged switch). They are evaluated only with the traffic that passes a mirrored port and do not enter the primary result.
   - Expectations 1, 2 and 3 are tested in the primary group. The result over all devices is reported as well.
5. *Device identity.* The pseudonym of the MAC address, produced on the recorder. Virtual machines are separate devices.
6. *Remote peer identity.* The net, dom and host levels need irreversible pseudonyms of the remote /24 network, the domain and the address. They are produced only if the site's written permission covers them explicitly. If it does not, only the proto, port and svc levels are computed at that site, expectation 3 cannot be tested there, and the paper says so.
7. *Recording quality.* For every site the coverage (devices seen / inventory) and the packet loss rate are reported.
8. *Choice of department in a large institution.* Conditions: all ports, or the VLAN, of the selected devices can be mirrored. The IT department can provide the device inventory (type, brand, model). No planned change within 8 weeks. The scope contains both imaging and laboratory devices. Among the options that satisfy these, the one with the most agentless devices is taken. The choice, the departments ruled out and the reasons are written down before recording starts.
9. *Continuous recording and interim data.* At Site A recording runs without a break for up to 16 weeks. The first version of the paper is written with the interim data at the end of week 8 and states the cut-off date. The same analysis is repeated with the full data and both are reported. The method is not changed after looking at the interim data.
10. *Minimum of k days (sensitivity analysis).* The primary rule is unchanged: a flow type enters the allowlist if it was seen (after the participation filter) on at least one day of the learning period. In addition, the allowlist size and the alert-day rate after enforcement are reported when the list is built only from types seen on at least 2 and at least 3 different days. Purpose: to measure the price of protection against one-off or malicious traffic that slipped into the learning period. Exploratory on public data, pre-registered for clinical data.

**14 November 2026, how the recorder implements the definitions above (before any clinical data).**
No parameter changes. These are the operational forms of terms already fixed.

1. *Role.* The originator of the Zeek connection record. Service port: the responder port.
2. *Established.* TCP: the responder answered the handshake (Zeek history contains `h`). Other protocols: at least one packet or byte from the responder.
3. *Protocols without ports* (ICMP, ICMPv6, IGMP and others) are one service per peer, keyed by the IP protocol number, as in the public data.
4. *Two capture ports.* A connection recorded on both ports within 2 seconds with the same addresses and ports is counted once. The copy that names more endpoints by their own MAC address is kept.
5. *Outage measurement.* The recorder writes a capture report every 5 minutes for every capture port. A moment counts as recorded if every port has a report with at least one packet covering it. Working hours are set per site before recording starts (Site A: Monday to Friday 08:00 to 17:00, Saturday 08:00 to 13:30).
6. *Remote peers without permission for pseudonyms.* The remote peer is labelled by a coarse service type only. The svc level does not use it.
7. *Recording limit.* The recorder stops by itself after the permitted number of recording days and drops records of any later day.
8. *Group addresses.* Addresses must not leave the site, so the recorder names well-known multicast groups by a fixed word, gives every other group a keyed pseudonym, and collapses IPv6 solicited-node groups into one class (their addresses embed bits of the target's address). In the public data each group address is its own peer. The difference can only lower the number of flow types at a clinical site and applies to every rule alike.
