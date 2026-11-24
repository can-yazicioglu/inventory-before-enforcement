# Method section, working draft (19 November 2026, corrected after the audit of 24 November 2026)

Status: draft for the paper. Definitions follow `docs/method.md`, which is frozen. Numbers are not
quoted here. They come from `paper/figures/results_tables.md`, which is generated from the stored tables.

## 1. Setting and threat model

We consider devices that cannot run endpoint security software: embedded devices (IP phones,
printers, cameras, recorders, storage, medical devices) and vendor-managed PCs that drive medical
devices. We call them *agentless*. The defender controls a gateway or switch through which the
device's traffic passes and wants to enforce, per device, an allowlist of connections. Everything
outside the list raises an alert and is later blocked. The adversary is any party that makes the
device open or accept a connection it does not normally have: a compromised device reaching out, or
a compromised neighbour reaching in. We do not address attacks that stay inside allowed connections.

The allowlist is learned by passive observation only. No probe is sent and no device is touched.
The question of this paper is when the observation may stop.

## 2. Flow types

A **flow type** is one allowlist rule: *transport / role / service port @ peer*.

- *Role* is `out` if the device opens the connection and `in` if it accepts it. Connection logs
  record the originator. Flow exports do not, so there the role is inferred: port fan-out over the
  device's trace, then a port below 1024, then equal ports (`sym`), then the recorded initiator, then
  the lower port. A connection log knows the originator only if it saw the connection being opened.
  A TCP record without the opening SYN and without the answering SYN-ACK was picked up in the middle
  of a conversation, and a UDP record whose first packet came from a service port is the answer to
  a question the log does not hold. The roles of both are inferred like those of a flow export, and
  they count for a device only if the device sent a packet in them.
- *Service port* is the responder's port. Ports 32768 and above form one class, because they are
  ephemeral on common systems.
- Protocols without ports (ICMP, ICMPv6, IGMP, tunnels and others) are one service per peer.
- *Peer* depends on the level of detail (Table 1). A LAN peer is always a stable device identity
  (MAC address or its pseudonym), never an IP address when a MAC address is available. A frame that
  crosses a router carries the router's MAC address. At clinical sites the device behind it is then
  named by the MAC address that answers for its IP address in ARP or IPv6 neighbour discovery on the
  mirrored networks.

Table 1. Levels of detail.

| Level | LAN peer | WAN peer | Use |
|---|---|---|---|
| proto | scope only | scope only | coarsest baseline |
| port | scope only | scope only | secondary |
| **svc** | device identity | any | **primary** |
| dom | device identity | registered domain if known | where names are available |
| net | device identity | /24 (IPv4) or /48 (IPv6) | secondary |
| host | device identity | address | finest baseline |

**Participation filter.** An inbound service counts on a day only if the device took part on that
day with that peer: it sent payload (flow exports) or it answered with anything but a reset
(connection logs). Scans and floods that the device does not answer are not device behaviour and
must not be learned. Without the filter they would enter the allowlist as rules that admit the scanner.
Protocols without ports have no inbound role. At clinical sites their records count for the
answering side only if it sent a packet, and an ICMP error message, which is a refusal like a reset,
counts for nobody. In the public data they count for both sides.

**Presence on a day.** A flow type is present for a device on a day if a connection of that type
starts on that day, or if the device sends a packet on that day in a connection of that type that
is already open. The second half matters for the devices we study: a connection that a device keeps
open for weeks would otherwise count once, on the day it was opened, or never, if it was opened
before the observation began. Presence is measured to the clock hour.

**Sampling unit.** The unit is a local calendar day on which the device is active. The first and
the last active day of every device are partial and are dropped, as is any day on which the recorder
was down for more than one hour inside working hours. A device enters the analysis if at least 10
full active days remain.

## 3. How many new flow types tomorrow?

Fix a device. Let 𝒮 be the countable set of flow types and X_{j,t} ∈ {0,1} indicate that type j is
observed on day t. Write X_t = (X_{j,t})_{j∈𝒮} for the observation of day t,
C_j(T) = Σ_{t≤T} X_{j,t}, Q_k(T) = |{j : C_j(T) = k}| for the number of types seen on exactly k of
the first T days, and N(T+1) = |{j : C_j(T) = 0, X_{j,T+1} = 1}| for the number of types that are
new on day T+1. N(T+1) is exactly the number of distinct allowlist violations that enforcement after
day T would produce on day T+1.

**Assumption E (exchangeable days).** The joint law of (X_1, …, X_{T+1}) is invariant under
permutations of the days, and E[Σ_j X_{j,1}] < ∞. T is a constant: the statements of this section
are for a number of days fixed in advance, not for a day chosen by looking at the data.

Nothing is assumed about the types: they may be dependent, heavy-tailed and infinitely many.
Proposition 1 and its corollaries are sums of expectations over types, which is why dependence
between types does not matter for them. Proposition 2 and the prediction bound use the joint
exchangeability of the days.

**Proposition 1.** Under E, E[N(T+1)] = E[Q_1(T+1)] / (T+1).

The estimate Q_1/T goes back to Turing and Good (Good 1953), who gave it for samples of
individuals. Robbins (1968) showed that the share of outcomes seen exactly once among n+1
observations is an unbiased estimate of the expected probability that observation n+1 is new. For
incidence data, where one sampling unit records the presence of many species at once, Chao and
Colwell (2017) use Q_1/T as the expected number of new species in one more unit, and Ayed and
co-authors (2019) prove the identity for independent features. These results assume independent
sampling units. Proposition 1 states the same identity for exchangeable days. Its proof is the
leave-one-out argument, which needs symmetry only. We do not claim it as new.

*Proof.* For t ≤ T+1 let A_t be the number of types observed on day t and on no other of the T+1
days. Then Q_1(T+1) = Σ_t A_t and N(T+1) = A_{T+1}. Each A_t is the same function of the day sequence
after day t is moved to the last position, so E[A_t] = E[A_{T+1}] by exchangeability. Summing over t
gives E[Q_1(T+1)] = (T+1) E[N(T+1)]. ∎

**Corollary 1 (the estimate is conservative on average).** Under E and for T ≥ 1,
E[Q_1(T)/T] ≥ E[N(T+1)]. The gap is 2 E[Q_2(T+1)] / (T(T+1)). On a single path N(T+1) can exceed
Q_1(T)/T.

*Proof.* Proposition 1 at length T gives E[Q_1(T)]/T = E[N(T)]. Let M be the number of types observed
on day T+1 and on none of the days 1, …, T−1. Then M ≥ N(T+1), and swapping days T and T+1 shows
E[M] = E[N(T)]. ∎

**Corollary 2 (any additive cost).** Let w_{j,t} ≥ 0 be a cost attached to type j on day t (for
example the number of records that would be blocked) such that the days with their costs are
exchangeable. Then the expected cost of the types new on day T+1 equals 1/(T+1) times the expected
total cost of the types seen on exactly one day, each counted on its day.

**Corollary 3 (recent window).** Let 1 ≤ W ≤ T and suppose the joint law of the T+1 days is
invariant under permutations of the last W+1 days, the first T−W days being held fixed. Let
R_W(T+1) be the number of types seen on exactly one of the days 1, …, T+1, that day being one of
the last W+1, and R_W(T) the number of types seen on exactly one of the days 1, …, T, that day
being one of the last W. Then E[N(T+1)] = E[R_W(T+1)]/(W+1) ≤ E[R_W(T)]/W.

**Proposition 2 (alert days).** An alert day is a day with at least one new type. Let D(T) be the
number of the first T days that carry a type seen on no other of these days. Under E,
P[N(T+1) ≥ 1] = E[D(T+1)]/(T+1) ≤ E[D(T)]/T.

*Proof.* Let B_t indicate that day t carries a type seen on no other of the T+1 days. Then
D(T+1) = Σ_t B_t and B_{T+1} is the indicator of an alert on day T+1. Exchangeability gives the
identity as in Proposition 1, and the inequality follows as in Corollary 1. ∎

The estimate D(T)/T is not new. It is the generalized sample coverage estimator of Ma and Chao
(1993) for observations that belong to several classes at once, and Lee and Böhme (2026) use it as
the discovery probability in software testing. The identity is the leave-one-out argument for the
event that tomorrow is not covered by what was seen so far. The same argument bounds the expected
violation probability in scenario optimisation (Calafiore and Campi 2005) and is the validity
argument of conformal prediction (Vovk, Gammerman and Shafer 2005). What we add is the exact
finite-sample form for exchangeable days.

Because a later day can only remove uniqueness from earlier days, D(T+1) ≤ D(T) + 1 on every
path, so the observable (D(T)+1)/(T+1) is never below D(T+1)/(T+1). In expectation this is weaker
than E[D(T)]/T by (T − E[D(T)])/(T(T+1)). We use D(T)/T as the estimate and mention the other form
because it holds path by path and is never zero.

**Proposition 3 (prediction bound).** Let u_t be the number of types seen on day t and on no other
of the first T days, and u_(1) ≤ … ≤ u_(T) their ordered values. Under E,
P[N(T+1) ≤ u_(k)] ≥ k/(T+1) for every k ≤ T. With k = ⌈(1−α)(T+1)⌉ this is an upper prediction
bound at level 1−α if T ≥ 1/α − 1. For smaller T the bound is infinite. The probability refers to
the T+1 days jointly, not to the next day given the first T.

*Proof.* Let u'_t be the number of types unique to day t among all T+1 days. These counts are
exchangeable and u'_{T+1} = N(T+1), so N(T+1) is at most the k-th smallest of all T+1 counts with
probability at least k/(T+1). For k ≤ T this is the event that N(T+1) is at most the k-th smallest
of u'_1, …, u'_T. Finally u'_t ≤ u_t for t ≤ T, because a later day can only remove uniqueness. ∎

The first two steps are the standard argument for exchangeable scores (Vovk, Gammerman and Shafer
2005). The third is specific to this problem. We evaluate the bound at α = 0.1, where it needs
T ≥ 9. Operators count alert days, not types, so the primary metric of this paper is stated in
alert days.

**Rule of three.** If no type has been seen exactly once (Q_1 = 0), the first term of the rule
below equals χ²_{0.95}(2)/(2T) = 2.996/T, the rule of three (Hanley and Lippman-Hand 1983). The term
cannot be smaller and the second term is not negative. GT-C therefore cannot certify 0.1 new types
per day before day 30, nor 0.3 before day 10, whatever the device does. This is a property of
GT-C, not a general limit.

## 4. The stopping rule GT-C

The point estimate of the next-day rate is Q_1(T)/T. GT-C adds two terms:

U(T) = χ²_{0.95}(2(Q_1(T)+1)) / (2T) + [ mean of the last 14 residuals N(t) − Q_1(t−1)/(t−1) ]₊ .

χ²_{0.95}(k) is the 0.95 quantile of the chi-square distribution with k degrees of freedom. The
first term is the one-sided upper 95 percent limit of a Poisson mean given the count Q_1(T)
(Garwood 1936), divided by T. It is nominal in three respects. Q_1(T) is not a Poisson count: types
that appear together make it over-dispersed, and the limit then covers the expected rate less often
than 95 percent of the time. The limit refers to a T fixed in advance, while the rule looks every
day, so the 95 percent does not carry over to the stopping day. And it bounds an expected rate,
while the evaluation looks at the realised rate of 14 days, which scatters around its expectation.
We therefore treat 0.95 and ε as constants of a decision rule and report its realised error rates.
We do not claim a confidence level at the stopping day.

The second term is a one-step-ahead correction for drift. It is the positive part of the mean of
the last 14 prediction errors N(t) − Q_1(t−1)/(t−1), with errors counted from day 3 on, used once
at least three errors exist. It reduces certification when recent prediction errors are positive.
It does not remove the effect of drift.

**Rule.** Enforce on the first day T ≥ 7 with U(T) ≤ ε. The primary target is ε = 0.3 new flow types
per day, with 1.0 and 0.1 as secondary targets. The floor T ≥ 7 binds only for ε = 1.0: the first
term alone forces T ≥ 10 for ε = 0.3 and T ≥ 30 for ε = 0.1. A learning episode starts on the first
full day of every device and again every 21 days, as long as at least 21 further days remain.

## 5. Building the allowlist: the complete list of rules

1. Identify each device by its MAC address (clinical sites: by the pseudonym the recorder derives from it, also when a frame arrives through a router). A virtual machine is its own device. Routers are not devices.
2. Keep connection metadata only: time, transport, ports, sides, bytes, state.
3. Assign the role and the service port (Section 2). Collapse service ports of 32768 and above.
4. Label the peer at the chosen level (Table 1). Well-known multicast groups are named. IPv6 solicited-node groups form one class, because their addresses embed bits of the target's address.
5. Apply the participation filter per device, day, service and peer.
6. Count each flow type once per active local day: on the day a connection starts and on every later day on which the device still sends packets in it. Drop partial days.
7. Each day compute Q_1(T) and U(T). Stop at the first T ≥ 7 with U(T) ≤ ε.
8. The allowlist is the set of flow types seen on at least one day of the learning period. As a sensitivity analysis the list is also built from types seen on at least two and at least three different days.
9. After enforcement a connection outside the list raises an alert. Blocking follows after a grace period (alert, then block).
10. Fixed observation windows of 7, 14, 21 and 28 days, the quiet streak (3/ε days without a new type) and the recent discovery rate (types first seen in the last 14 days, per day) are the comparison rules. They use the same flow types and the same filter.

## 6. Evaluation

For every learning episode that a rule enforces at day T we look at the next 14 active days. An
**alert day** is a day on which the device uses at least one flow type that it has never used
before, neither in the learning period nor on an earlier day after enforcement. This counts the
days on which the operator has to decide about something new, and it assumes that every alert is
resolved on the day it is raised. Under the stricter reading, in which the allowlist stays as it
was on the enforcement day, a new type alerts on every day on which it is used. Assumption E
predicts the stricter number: every later day then has the same probability E[D(T+1)]/(T+1) of
carrying a type outside the list.

The **primary metric** is the share of enforced episodes whose alert-day rate in that horizon
exceeds ε. With ε = 0.3 and 14 days this means at least five alert days. Intervals are percentile
intervals of a bootstrap that resamples devices with all their episodes. When no enforced episode
exceeds the target this interval collapses to a point, so every row also states the number of
devices behind it and the exact upper limit for that number of devices (Clopper and Pearson 1934).
GT-C bounds the expected number of new types per day, and a day with any number of new types is
one alert day. The alert-day rate therefore never exceeds the type rate, and we report the
exceedance of both. For ε = 1.0 only the type-rate metric is informative, because an alert-day
rate cannot exceed 1.

An episode counts as enforced only if the rule fires at least 14 active days before the end of the
trace. Episodes that are enforced later cannot be evaluated and are counted as not enforced. The
share of devices certified by day T is therefore read from the Kaplan-Meier curve, and the
exceedance refers to the episodes that are enforced early. We also report the median enforcement
day and the per-device calibration ratio (realised new types over predicted, first episode, T ≥ 7,
no smoothing).

Three expectations were written down before the validation data and the clinical data were seen
(`docs/method.md`): calibration near or below 1 in control and clinical networks, GT-C exceedance
below 10 percent, and fixed windows clearly worse at the net level. They are reported as they turn
out.

All stored tables were reproduced from scratch. The enforcement days and the two exceedance shares
of GT-C, of the chi-square limit alone, of the quiet streak and of the fixed windows were also
recomputed for the 14-day horizon at the port, svc and net levels by a second program that uses
sets and loops instead of matrices (`analysis/indep.py`). It starts from the same table of flow
types per device and day and follows the same conventions, so it checks the computation of the rule
and of the outcomes, not the preparation of the data. The preparation of the UNSW 2016 data was
repeated separately (`analysis/indep_unsw.py`). Intervals, calibration, the certification curves
and the other tables were not recomputed independently.

## 7. Recording at clinical sites

Recording at a site uses a purpose-built recorder (`recorder/`). It listens on switch mirror ports
(incoming traffic of every port, so each frame is seen once), runs one Zeek process per port and
keeps raw logs in memory only. Once an hour it turns the connection log into anonymised records and
deletes the raw logs. Six measures make the connection log say what an enforcement point would
see. A connection that stays open is reported at every full hour in which it carries packets, and
once more when it ends, and which side sent on which day is taken from these reports, not from the
record written at the end. A silent TCP connection is kept for a day and a
silent UDP flow for two minutes, so that a conversation is not cut into pieces whose first speaker
is mistaken for the opener. A record whose opener was not seen is marked, so that its roles are
inferred and not taken at face value. Packets that every device sends from the same address (a DHCP
request) get one record per sender. A device that is reached through a router is named by its
own MAC address, which the recorder learns from ARP and neighbour discovery and keeps at the site.
And a tunnel is recorded as one flow of the device that keeps it, without looking inside.
Local devices are named by HMAC-SHA256 pseudonyms of their MAC addresses. The
key is generated on the device at the site, lives on a removable stick that stays with the site's IT
officer and is never available to the researchers. Remote hosts are never named: they carry a
coarse service type and, where the site's written permission covers it, one-way tokens of the
address, its network and its registrable domain. Records pass a field whitelist and a scan for
address shapes before they are written. The recorder cannot transmit on its capture ports, starts
only after an approval reference has been entered on site, does not record while any swap to disk
is active, and stops by itself after the permitted number of recording days. Before use the recorder
was reviewed in three rounds from the code alone, each time once for what can leave the site and once
for what is measured. Every case these reviews found is now part of the tests.

The chain from packets to the stopping rule was verified in two ways (`recorder/README.md`). A public
capture was replayed as identical days, where the correct answers are known in advance. And a
hand-made capture with one case for every situation above (a connection open for 50 hours, one that
never closes, one picked up in the middle with the server speaking first, silence, a slow answer,
refusals, midnight, three devices asking for an address at once, a ping that runs for days, a
device that is switched off, two VLANs joined by a router, tunnels) was run through the whole chain
and gave exactly the flow types written down beforehand, for every device and day.

## 8. Platform selection

The recorder and the enforcement gateway share one hardware design: a Raspberry Pi 5 (quad-core
Cortex-A76, 8 GB) with a dual-port RTL8125 Ethernet adapter on its single PCIe 2.0 lane. We required
at least two non-USB capture ports, a battery-backed clock for offline operation, hardware AES for
encrypted storage, the ability to disable all radios, a documented production lifetime, and a cost
low enough for a small clinic. Microcontrollers were excluded because they cannot run a Linux network
stack or Zeek. FPGA platforms such as NetFPGA SUME target 10 Gb/s and above and would add cost and
development effort without benefit at the 1 Gb/s links we study. The earlier Raspberry Pi 4 offers
neither an accessible PCIe lane nor an on-board clock. Fanless x86 appliances with four Intel I226
ports are the more capable recorder and remain our scale-up path for larger hospital networks, at
roughly twice the cost. In the kernel series of the Raspberry Pi used here (6.12) neither the
on-board Ethernet driver (macb) nor the RTL8125 driver (r8169) supports native XDP, so the
enforcement cost we report is that of the portable nftables kernel path and is a conservative upper
bound relative to accelerated data planes.

## Open points before submission

- "roughly twice the cost" in Section 8 must be rechecked against current prices.
- Section 7 will get the measured loss and throughput on the actual device.
- Related work and the results text are separate files and are not drafted yet.
- XDP support for the on-board driver (macb) was under review upstream in 2026 (netdev, "net: macb: Add XDP support and page pool integration", version 6 of 23 March 2026). State the kernel version in the paper and recheck before submission.
- The share of records whose opener was not seen, the number of hourly reports, the number of records named through the neighbour table and the number of records still named by IP address at each site belong in the results (they show how much the recorder's measures matter in a real network).
- The public data keep four behaviours that the recorder no longer has (notes of 19 November 2026 in `docs/method.md`): one flow for all senders of a DHCP request within two minutes, a flow type for a device that received a packet of a protocol without ports and did not answer, a flow type for a device that sent an ICMP error message, and no hourly reports. State them as limits of the public data.
- Report the results of the primary group by device type and once without IP phones (registered on 19 November 2026): phones choose the ports of every call anew.
- Full bibliographic entries go into the reference list: Good 1953, Robbins 1968, Chao and Colwell 2017, Ayed and co-authors 2019, Ma and Chao 1993, Lee and Böhme 2026, Calafiore and Campi 2005, Vovk, Gammerman and Shafer 2005, Garwood 1936, Hanley and Lippman-Hand 1983, Clopper and Pearson 1934. The originals of Robbins 1968 and Ma and Chao 1993 were not read in the audit of 24 November 2026 and must be read before submission.
- Decision pending (24 November 2026): report the alert-day rate under a list that is never updated as a registered secondary metric (`analysis/fixed_list.py`). On the public data GT-C then exceeds the target in 0 to 30 percent of the enforced episodes, not in 0 to 5 percent. Its advantage over a fixed 14-day window then remains at the net level only (0.000 against 0.783 in the homes, 0.300 against 0.671 in UNSW 2016). At the port and svc levels of the homes GT-C is then worse than the fixed window (0.067 against 0.037 and 0.156 against 0.124). The two rules do not enforce the same episodes, so this comparison is not paired.
- Conventions that the results text must state: role labels use the whole trace (hindsight, the first-week variant is the check), the comparison with the matched quiet streak tunes its length afterwards and uses the type-rate metric, and `GT-max(conf)` is a variant in the stored tables that the text does not use.
- Two registered sensitivity analyses have no code yet (lists built from types seen on at least two or three days, weekdays only). They must be implemented before the clinical data arrive.
- The public UNSW traces violate assumption E in part: realised alert days over D(T)/T is above 1 there. Say that the margin and the drift term, not the propositions, carry the rule on those data.
- The exceedance shares of GT-C rest on few devices in several cells (6 to 32 devices in the UNSW traces). Give the number of devices and the exact limit in every row.
- IEEE TDSC allows 12 formatted pages including references, and up to 18 against a fee. Plan supplementary material from the start. Computers & Security does not consider submissions with AI or ML as a significant component: say in one plain sentence that no model is trained, and avoid the words learning, training, prequential and conformal where plain words exist.
