# Data sources

No dataset is redistributed in this repository. The scripts expect the files under the directory
named by the environment variable `IBE_DATA` (default `data/`).

| Name in the code | Source | What is used | Size after preparation | Local time zone |
|---|---|---|---|---|
| `unsw` | UNSW-IoTraffic. Wannigama, Sivanathan and Habibi Gharakheili, "Descriptor: UNSW IoT Traffic Data with Packets, Flows, and Protocols (UNSW-IoTraffic)", IEEE Data Descriptions, 2025, doi:10.1109/IEEEDATA.2025.3602010. Data: Dryad, doi:10.5061/dryad.w0vt4b94b (CC0) | flow files, TLS and HTTP attributes | 27 devices, 178 recording days, 4.9 million records | Australia/Sydney |
| `homes` | Residential traces of 12 homes. Pashamokhtari, Okui, Nakahara, Kubota, Batista and Habibi Gharakheili, "Dynamic Inference From IoT Traffic Flows Under Concept Drifts in Residential ISP Networks", IEEE Internet of Things Journal 10(17), 2023, doi:10.1109/JIOT.2023.3265012 | flow records and the device catalogue | 286 devices of 24 models, about 5 weeks, 23.8 million records | Asia/Tokyo |
| `unsw25v1`, `unsw25v2` | UNSW 2025 flow archives DATA2025v1 and DATA2025v2. Sivanathan and Habibi Gharakheili, "IoT network traffic flow datasets and encoder models for IoT device behavioral representation learning", Dryad, 2026, doi:10.5061/dryad.7h44j1098 | flow records, one file per local day | 36 devices over 85 recording days (22,051,704 flows) and 35 devices over 240 recording days (22,328,711 flows) | Australia/Sydney |
| `hvac` | Building automation (HVAC) control network trace. Kabasele Ndonda and Sadre, "A Public Network Trace of a Control and Automation System", arXiv:1908.02118, 2019. Data: https://github.com/gkabasele/HVAC_Traces | flows derived from the packet trace | 37 internal nodes, 7 days, 126,104 flows | Europe/Brussels |
| `cic` | CICIoMT2024. Dadkhah, Neto, Ferreira, Molokwu, Sadeghi and Ghorbani, "CICIoMT2024: A benchmark dataset for multi-protocol security assessment in IoMT", Internet of Things 28, 101351, 2024, doi:10.1016/j.iot.2024.101351 | packet captures (idle, active, benign, power-on, user interaction, reconnaissance) of the seven Wi-Fi devices | used for the evaluation of device states and reconnaissance, and for the recorder tests | n/a |
| `servtrace19`, `servtrace22` | IoT-ServTrace. Azizi, Okui, Nakahara, Kubota and Habibi Gharakheili, "Backend-Service Fingerprints: Lightweight and Interpretable Identification of Household IoTs", IFIP Networking 2026. Data: https://github.com/shay-fi/IoT-ServTrace (MIT) | time, transport and port of each flow to a service outside the home network | 19 devices from June 2019 to October 2020 (15.5 million flows) and 52 devices over 2022 (34.3 million flows). Port level only: no remote address and no direction | Asia/Tokyo |

Full bibliographic references of all sources are given in the paper. The first and the last
calendar day of every device are dropped, and all timestamps are UTC in the prepared files.

Recording days. The UNSW 2016 trace has 178 recording days in 204 calendar days, and 22 of them cover
less than 20 hours. Every day file of UNSW 2025 runs up to two minutes past local midnight. A record
is therefore never placed on a later local day than its file (correction of 24 November 2026, see
`method.md`). Three of the 85 recording days of the first release and two of the 240 of the second
cover less than 20 hours (`analysis/facts.py`, section 8).

Clinical data are not public. What may be published from a site is fixed by that site's written
permission and the ethics approval.
