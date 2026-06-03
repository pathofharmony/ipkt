# Protocol parity matrix

**ipkt** is an independent implementation of Windows protocol specifications
(MS-*, RFCs). This matrix tracks implemented areas and test coverage; it is not a
compatibility guarantee against any third-party product.

## Legend

| Symbol | Meaning |
| ------ | ------- |
| ✅ | Implemented with automated tests |
| 🟡 | MVP / subset (wire formats, no full end-to-end tool) |
| ❌ | Not implemented |

## Phase 1 — `ipkt-ntlm` (MS-NLMP)

| Area | Status | Tests |
| ---- | ------ | ----- |
| NTLMv1 / NTLMv2 crypto | ✅ | MS-NLMP §4.2 vectors |
| NTLMSSP Type 1/2/3 | ✅ | round-trip + handshake |
| MIC, KEY_EXCH, AV pairs | ✅ | integration |
| Channel bindings, anonymous | ✅ | `channel_bindings` tests |

## Phase 2 — `ipkt-smb` (MS-SMB2)

| Area | Status | Tests |
| ---- | ------ | ----- |
| SMB2 header, NetBIOS framing | ✅ | unit |
| NEGOTIATE, SESSION_SETUP + NTLM | ✅ | unit |
| TREE_CONNECT, CREATE, READ, WRITE, CLOSE | ✅ | pack/round-trip |
| Async TCP client | 🟡 | `SmbClient` (live e2e TBD) |
| SMB2 signing (HMAC-SHA256) | 🟡 | `signing` tests |
| NTLM RC4 sealing helpers | 🟡 | `sealing` tests |
| Named pipe + RPC BIND/SAMR/DRSU | 🟡 | `SmbRpcTransport` + CLI |
| SMB3 encryption transform (AES-128-GCM) | 🟡 | `encryption` test |
| NEGOTIATE encryption + preauth caps | 🟡 | `packets` test |
| Preauth integrity SHA-512 helper | 🟡 | `encryption` test |
| Full SMB 3.1.1 signing KDF chain | ❌ | planned |

## Phase 3 — `ipkt-kerberos` (RFC 4120)

| Area | Status | Tests |
| ---- | ------ | ----- |
| Minimal DER codec | ✅ | AS-REQ encode/decode |
| AS-REQ / TGS-REQ builders | ✅ | unit |
| AS-REP subset encode/decode | ✅ | `as_rep` test |
| AES256-CTS-HMAC-SHA1-96 + PBKDF2/DK | ✅ | `aes_cts` test |
| PA-ENC-TIMESTAMP (real AES) | ✅ | `pa_data` test |
| UDP KDC AS-REQ/REP (`feature kdc`) | 🟡 | CLI `kerberos-as-exchange` |
| TGS-REQ/REP + session key + AP-REQ/AP-REP (`feature kdc`) | ✅ | `ap_req` test |
| AES256 + RC4-HMAC etypes, `KerberosSessionKey` | ✅ | `rc4_hmac` test |
| PA-PAC-REQUEST on TGS | ✅ | `pa_data` |
| PAC decode + HMAC-MD5 checksum verify (types 6/7) | ✅ | `pac` test |
| PAC credential info KVNO (buffer type 2) | ✅ | `pac` parse |
| KRB-ERROR decode + KDC client mapping | ✅ | `krb_error` test |
| DES / 3DES / des-cbc-crc (etypes 1/3/7) | ✅ | `des_crypto` + RFC3961 CRC vectors |
| Live AD TGS + PAC (`IPKT_AD_*`, `--ignored`) | 🟡 | `tests/live_ad.rs` |

## Phase 4 — `ipkt-dcerpc` (MS-RPCE)

| Area | Status | Tests |
| ---- | ------ | ----- |
| RPC header, BIND, REQUEST | ✅ | unit |
| BIND_ACK / RESPONSE / FAULT parse | ✅ | `parse` test |
| UUID | ✅ | unit |
| Auth trailers, fragmentation | 🟡 | partial |

## Phase 5 — `ipkt-rpc` (MS-SAMR / MS-DRSR subset)

| Area | Status | Tests |
| ---- | ------ | ----- |
| NDR writer (unicode, u32) | ✅ | via SAMR stub |
| SamrConnect request + response parse | ✅ | `samr` + `samr_parse` |
| SamrEnumerateUsersInDomain (MVP parse) | 🟡 | `samr` test |
| DRSBind / GetNCChanges V8 + MakeAttid | 🟡 | `drsr` / `prefix_table` tests |
| DRSCrackNames + single-user EXOP_REPL_OBJ | 🟡 | CLI `--target-user` |
| DRS decrypt (session key + DES/RID) | 🟡 | `drsr_crypto` test |
| GetNCChanges ENTINF scan + repl pages | 🟡 | `repl-export --drsu` (live AD) |
| REPLENTINFLIST + `DRS_MSG_GETCHGREPLY_V6` NDR | ✅ | `replentinf` test |
| PEK list parse + `remove_rc4_pek_layer` | ✅ | `drsr_crypto` test |
| USN / invocation from reply body (not scan) | ✅ | `replentinf` test |

## Phase 6 — `ipkt-ldap` (RFC 4511)

| Area | Status | Tests |
| ---- | ------ | ----- |
| BER subset, BIND, SEARCH encode | ✅ | unit |
| Async TCP client (simple bind) | 🟡 | `client` feature + CLI |
| SASL bind (mechanism + creds BER) | 🟡 | `sasl` test |
| GSSAPI + SPNEGO NegTokenInit (first leg) | 🟡 | `spnego` test |
| Kerberos AP-REQ in NegTokenInit + `bind_kerberos` | ✅ | `spnego` test |
| KDC TGS + AP-REQ/AP-REP + `bind_kerberos_exchange` | ✅ | `ap_req` + CLI `--kerberos` |
| `NegTokenTarg` parse + mutual AP-REP from challenge | ✅ | `ap_req` / `spnego_targ` |

## Phase 7 — `ipkt-wmi` (MS-DCOM)

| Area | Status | Tests |
| ---- | ------ | ----- |
| ORPC this/that | ✅ | unit |
| RemoteActivation stub + WMI CLSID | 🟡 | `dcom` test |
| DCOM activation, IWbemServices | ❌ | planned |

## Phase 15 — Spec-complete DRS reply + full Kerberos LDAP

| Area | Status | Tests |
| ---- | ------ | ----- |
| `replentinf.rs` ENTINF/ATTR NDR | ✅ | `replentinf` |
| `KdcClient::ldap_tokens` | ✅ | CLI `--kerberos` |

## Phase 14 — DCSync depth + LDAP Kerberos

| Area | Status | Tests |
| ---- | ------ | ----- |
| `DrsUsnVector` on subsequent GetNCChanges | 🟡 | `drsr` request |
| Reply USN + invocation carry-over | 🟡 | `repl-export` |
| `ldap-search --gss-ap-req` | 🟡 | CLI |

## Phase 8–14 — `ipkt-cli`

| Area | Status | Tests |
| ---- | ------ | ----- |
| `info`, `ntlm-handshake`, `ntlm-hash` | ✅ | build |
| `smb-negotiate`, `rpc-bind-samr`, `rpc-samr-connect` | 🟡 | live server |
| `kerberos-as-req`, `kerberos-as-exchange`, `ldap-search` | 🟡 | encode / live |
| `repl-export` (SAMR + DRSUAPI hash path) | 🟡 | live AD + `--drsu` |
| psexec, smbclient | ❌ | planned |

## Legal

See [`NOTICE`](../NOTICE).
