# RCTF 2026


## Services

| Service                                              | Category     | Vulns                                                                                                                                                                          | Solves | FB Time                            | Authors        |
| ---------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ---------------------------------- | -------------- |
| [battlebots_revenge](/services/battlebots_revenge/)  | pwn          | rw via integer overflow; memfd_create + writev + execve via fsop                                                                                                               | 4      | 1:37 - s4d_kittens                 | @FlexMaster420 |
| [pipeline](/services/pipeline)                       | infra        | blind ssrf; unauthenticated push to internal docker registry                                                                                                                   | 8      | 2:37 - s4d_kittens                 | @Fragoler2     |
| [possibly_maybe](/services/possibly_maybe/)          | pwn          | bounds-check elision + slow pointer chase -> speculative OOB read of neighbor row's key; leaked bit read via amplifying tree-PLRU eviction timer (rdtscp via rand) -> key leak | 1      | 5:22 - s4d_kittens                 | @FlexMaster420 |
| [xingyuan](/services/xingyuan/)                      | web          | predictable token, SQL injection, SSRF                                                                                                                                         | 18     | 1:02 - masquadd, s4d_kittens       | @gcc_makar     |


## Infrastructure
- DevOps and RCTF platform: @gcc_makar, @FlexMaster420
- Checksystem: [ForcAD](https://github.com/pomo-mondreganto/ForcAD)
- VPS: [kaf42](https://kaf42.mephi.ru/)
