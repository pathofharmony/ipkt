# ipkt

![Social preview](.github/social-preview.png)

Memory-safe Rust toolkit for Windows network protocols, built from public
specifications ([MS-NLMP], [MS-SMB2], [RFC 4120], [MS-RPCE], [MS-DRSR], …).

[MS-NLMP]: https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp
[MS-SMB2]: https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/
[RFC 4120]: https://www.rfc-editor.org/rfc/rfc4120
[MS-RPCE]: https://learn.microsoft.com/openspecs/windows_protocols/ms-rpce/

## Crates

| Crate | Role |
| ----- | ---- |
| `ipkt-core` | `Pack` / `Unpack`, `ByteReader` / `ByteWriter` |
| `ipkt-ntlm` | NTLMv1/v2, NTLMSSP, MIC, channel bindings |
| `ipkt-smb` | SMB2/3 client, signing, encryption, RPC transport |
| `ipkt-kerberos` | Kerberos v5, KDC client (`feature kdc`) |
| `ipkt-dcerpc` | DCE/RPC PDUs |
| `ipkt-rpc` | SAMR, DRSUAPI (replication, PEK, REPLENTINF) |
| `ipkt-ldap` | LDAP + SASL GSSAPI / Kerberos |
| `ipkt-wmi` | ORPC / DCOM activation stub |
| `ipkt-cli` | `ipkt` binary |

Coverage notes: [`docs/PARITY.md`](docs/PARITY.md).

## Build

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## CLI examples

```bash
cargo run -p ipkt-cli -- info
cargo run -p ipkt-cli -- ntlm-hash --password 'S3cr3t!'
cargo run -p ipkt-cli -- smb-negotiate 192.0.2.1
cargo run -p ipkt-cli -- kerberos-as-exchange KDC --realm REALM --user U --password P
cargo run -p ipkt-cli -- repl-export DC --domain D --user U --password P --drsu
cargo run -p ipkt-cli -- ldap-search ldap.example.com --kerberos --kdc dc.example.com \
  --krb-realm EXAMPLE.COM --krb-user U --krb-password '…' --bind-dn '' --password ''
```

Live AD tests (optional):

```bash
IPKT_AD_REALM=LAB.EXAMPLE IPKT_AD_USER=alice IPKT_AD_PASSWORD='***' IPKT_AD_KDC=dc.lab.example \
  cargo test -p ipkt-kerberos --features kdc live_ad -- --ignored --nocapture
```

## Library

```rust
use ipkt::core::Pack;
use ipkt::ntlm::{Credentials, NtlmClient};

let client = NtlmClient::new(Credentials::new("CONTOSO", "alice", "secret"));
let bytes = client.negotiate().pack();
```

Feature `full` on the `ipkt` meta-crate enables all optional crates.

## License

MIT OR Apache-2.0 — see `LICENSE-MIT` and `LICENSE-APACHE`.
