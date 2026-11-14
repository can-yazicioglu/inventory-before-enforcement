# Data sources

No dataset is redistributed in this repository. The scripts expect the files under the directory
named by the environment variable `IBE_DATA` (default `data/`).

| Name in the code | Source | What is used | Size after preparation | Local time zone |
|---|---|---|---|---|
| `unsw` | UNSW-IoTraffic. Wannigama, Sivanathan and Habibi Gharakheili, "Descriptor: UNSW IoT Traffic Data with Packets, Flows, and Protocols (UNSW-IoTraffic)", IEEE Data Descriptions, 2025, doi:10.1109/IEEEDATA.2025.3602010. Data: Dryad, doi:10.5061/dryad.w0vt4b94b (CC0) | flow files, TLS and HTTP attributes | 27 devices, 178 recording days, 4.9 million records | Australia/Sydney |
| `homes` | Residential traces of 12 homes (Pashamokhtari and co-authors) | flow records and the device catalogue | 286 devices of 24 models, about 5 weeks, 23.8 million records | Asia/Tokyo |
| `unsw25v1`, `unsw25v2` | UNSW 2025 flow archives, two releases | flow records | 36 devices over 85 days (22,051,704 flows) and 35 devices over 240 days (22,328,711 flows) | Australia/Sydney |
| `hvac` | Building automation (HVAC) control network trace | flows derived from the packet trace | 37 internal nodes, 7 days, 126,104 flows | Europe/Brussels |
| `cic` | CICIoMT2024 | packet captures (idle, active, benign, reconnaissance, power) | used for the attack-side evaluation and for the recorder tests | n/a |

Full bibliographic references of all sources are given in the paper. The first and the last
calendar day of every device are dropped, and all timestamps are UTC in the prepared files.

Clinical data are not public. What may be published from a site is fixed by that site's written
permission and the ethics approval.
