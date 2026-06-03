mod repl_export;

use clap::{Parser, Subcommand};
use ipkt::core::Pack;
use ipkt::kerberos::{
    build_pa_enc_timestamp, encode_as_req, encode_pa_enc_timestamp, AsReq, KdcReqBody, PrincipalName,
    Realm, ETYPE_AES256_CTS_HMAC_SHA1_96,
};
use ipkt::kerberos::KdcClient;
use ipkt::ldap::{gssapi_kerberos_credentials, LdapClient, SearchRequest};
use ipkt::ntlm::{channel_bindings_hash, crypto::ntowf_v1, Credentials, NtlmClient};
use ipkt::smb::SmbClient;

#[derive(Parser)]
#[command(
    name = "ipkt",
    version,
    about = "Windows protocol toolkit (independent implementation)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    
    NtlmHandshake {
        #[arg(long, default_value = "CONTOSO")]
        domain: String,
        #[arg(long, default_value = "alice")]
        user: String,
        #[arg(long, default_value = "password")]
        password: String,
    },
    
    NtlmHash {
        #[arg(long)]
        password: Option<String>,
        #[arg(long, help = "16-byte NT hash as hex (pass-the-hash input)")]
        nt_hash: Option<String>,
        #[arg(long, help = "TLS cert SHA-256 hex for channel-bindings MD5")]
        cert_sha256: Option<String>,
    },
    
    SmbNegotiate {
        host: String,
        #[arg(long, default_value_t = 445)]
        port: u16,
    },
    
    RpcBindSamr {
        host: String,
        #[arg(long, default_value_t = 445)]
        port: u16,
        #[arg(long, default_value = "CONTOSO")]
        domain: String,
        #[arg(long, default_value = "Administrator")]
        user: String,
        #[arg(long)]
        password: String,
    },
    
    RpcSamrConnect {
        host: String,
        #[arg(long, default_value_t = 445)]
        port: u16,
        #[arg(long, default_value = "CONTOSO")]
        domain: String,
        #[arg(long, default_value = "Administrator")]
        user: String,
        #[arg(long)]
        password: String,
    },
    
    KerberosAsReq {
        #[arg(long, default_value = "EXAMPLE.COM")]
        realm: String,
        #[arg(long, default_value = "alice")]
        user: String,
        #[arg(long)]
        password: Option<String>,
    },
    
    KerberosAsExchange {
        kdc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        #[arg(long, default_value = "EXAMPLE.COM")]
        realm: String,
        #[arg(long, default_value = "alice")]
        user: String,
        #[arg(long)]
        password: String,
    },
    
    #[command(name = "repl-export")]
    ReplExport {
        host: String,
        #[arg(long, default_value_t = 445)]
        port: u16,
        #[arg(long, default_value = "CONTOSO")]
        domain: String,
        #[arg(long, default_value = "Administrator")]
        user: String,
        #[arg(long)]
        password: String,
        #[arg(long, help = "Attempt DRSUAPI DCSync (needs DA)")]
        drsu: bool,
        #[arg(long, help = "Only this account (DOMAIN\\\\user or user); uses DRSCrackNames + EXOP_REPL_OBJ")]
        target_user: Option<String>,
    },
    
    LdapSearch {
        host: String,
        #[arg(long, default_value_t = 389)]
        port: u16,
        #[arg(long, default_value = "cn=admin,dc=example,dc=com")]
        bind_dn: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "dc=example,dc=com")]
        base: String,
        #[arg(long, default_value = "(objectClass=*)")]
        filter: String,
        #[arg(
            long,
            help = "Kerberos AP-REQ DER as hex for SASL GSSAPI bind (instead of simple bind)"
        )]
        gss_ap_req: Option<String>,
        #[arg(long, help = "Full Kerberos LDAP bind (AS+TGS+AP-REQ/AP-REP); needs --kdc --realm --user --password")]
        kerberos: bool,
        #[arg(long, help = "KDC host for --kerberos")]
        kdc: Option<String>,
        #[arg(long, help = "Kerberos realm for --kerberos")]
        krb_realm: Option<String>,
        #[arg(long, help = "Kerberos user for --kerberos")]
        krb_user: Option<String>,
        #[arg(long, help = "Kerberos password for --kerberos")]
        krb_password: Option<String>,
        #[arg(long, default_value_t = 88)]
        kdc_port: u16,
    },
    
    Info,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::NtlmHandshake {
            domain,
            user,
            password,
        } => {
            let client = NtlmClient::new(Credentials::new(&domain, &user, &password))
                .with_client_challenge([0x42; 8])
                .with_exported_session_key([0x77; 16]);
            let negotiate = client.negotiate();
            let negotiate_bytes = negotiate.pack();
            println!("NEGOTIATE: {} bytes", negotiate_bytes.len());
            println!("OK — use `cargo run -p ipkt --example ntlm_handshake` for full demo");
        }
        Commands::NtlmHash {
            password,
            nt_hash,
            cert_sha256,
        } => {
            let mut did_something = false;
            if let Some(ref pw) = password {
                let hash = ntowf_v1(pw);
                println!("NT: {}", hex::encode(hash));
                did_something = true;
            }
            if let Some(ref hex_hash) = nt_hash {
                let bytes = hex::decode(hex_hash.trim())?;
                if bytes.len() != 16 {
                    return Err("NT hash must be 16 bytes (32 hex chars)".into());
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                println!("NT (hex input): {}", hex::encode(arr));
                did_something = true;
            }
            if let Some(ref cert) = cert_sha256 {
                let digest = hex::decode(cert.trim())?;
                let cb = channel_bindings_hash(&digest);
                println!("MsvAvChannelBindings MD5: {}", hex::encode(cb));
                did_something = true;
            }
            if !did_something {
                return Err("provide --password, --nt-hash, and/or --cert-sha256".into());
            }
        }
        Commands::SmbNegotiate { host, port } => {
            let mut client = SmbClient::connect(&host, port).await?;
            let dialect = client.negotiate().await?;
            println!("host: {host}:{port}");
            println!("dialect: {:?}", dialect);
            println!("signing enabled: {}", client.signing_enabled());
        }
        Commands::RpcBindSamr {
            host,
            port,
            domain,
            user,
            password,
        } => {
            let mut client = SmbClient::connect(&host, port).await?;
            client
                .authenticate_ntlm(Credentials::new(&domain, &user, &password))
                .await?;
            let mut transport = ipkt::smb::SmbRpcTransport::connect_samr(&mut client, &host).await?;
            let resp = transport.bind_samr(&mut client).await?;
            println!("SAMR BIND response: {} bytes", resp.len());
        }
        Commands::RpcSamrConnect {
            host,
            port,
            domain,
            user,
            password,
        } => {
            let mut client = SmbClient::connect(&host, port).await?;
            client
                .authenticate_ntlm(Credentials::new(&domain, &user, &password))
                .await?;
            let mut transport = ipkt::smb::SmbRpcTransport::connect_samr(&mut client, &host).await?;
            transport.bind_samr(&mut client).await?;
            let connect = transport.samr_connect(&mut client, 0x000F003F).await?;
            println!(
                "SamrConnect status={:#x} handle={}",
                connect.status,
                hex::encode(connect.server_handle)
            );
        }
        Commands::KerberosAsExchange {
            kdc,
            port,
            realm,
            user,
            password,
        } => {
            let client = ipkt::kerberos::KdcClient::new(&kdc, port);
            let ex = client.as_exchange(&realm, &user, &password).await?;
            println!(
                "AS-REP: {} bytes ticket, enc_part {} bytes",
                ex.as_rep.ticket.len(),
                ex.as_rep.enc_part.len()
            );
            println!(
                "session key: etype={} len={}",
                ex.session_key.etype,
                ex.session_key.key.len()
            );
        }
        Commands::KerberosAsReq {
            realm,
            user,
            password,
        } => {
            let body = KdcReqBody {
                kdc_options: 0,
                cname: PrincipalName::new(1, vec![user.clone()]),
                realm: Realm::new(&realm),
                sname: None,
                nonce: 0x11223344,
                etype: vec![ETYPE_AES256_CTS_HMAC_SHA1_96],
            };
            let req = AsReq {
                pvno: 5,
                msg_type: 10,
                req_body: body,
            };
            let der = encode_as_req(&req)?;
            println!("AS-REQ: {} bytes", der.len());
            println!("hex: {}…", hex::encode(&der[..der.len().min(32)]));
            if let Some(pw) = password {
                let pa = build_pa_enc_timestamp(&pw, &realm, &user, 1_000_000, 0)?;
                let pa_der = encode_pa_enc_timestamp(&pa);
                println!("PA-ENC-TIMESTAMP: {} bytes", pa_der.len());
            }
        }
        Commands::ReplExport {
            host,
            port,
            domain,
            user,
            password,
            drsu,
            target_user,
        } => {
            repl_export::run_repl_export(repl_export::ReplExportOptions {
                host,
                port,
                domain,
                user,
                password,
                try_drsu: drsu,
                target_user,
            })
            .await?;
        }
        Commands::LdapSearch {
            host,
            port,
            bind_dn,
            password,
            base,
            filter,
            gss_ap_req,
            kerberos,
            kdc,
            krb_realm,
            krb_user,
            krb_password,
            kdc_port,
        } => {
            let mut ldap = LdapClient::connect(&host, port).await?;
            let bind = if kerberos {
                let kdc_host = kdc.as_deref().ok_or("--kdc required with --kerberos")?;
                let realm = krb_realm.as_deref().ok_or("--krb-realm required with --kerberos")?;
                let user = krb_user.as_deref().ok_or("--krb-user required with --kerberos")?;
                let pw = krb_password.as_deref().ok_or("--krb-password required with --kerberos")?;
                println!("[*] Kerberos AS+TGS for ldap/{host} via {kdc_host}:{kdc_port}");
                let kdc_client = KdcClient::new(kdc_host, kdc_port);
                let tokens = kdc_client.ldap_tokens(realm, user, pw, &host).await?;
                println!(
                    "[*] AP-REQ {} bytes, service key etype={} — SASL GSSAPI exchange",
                    tokens.ap_req.len(),
                    tokens.service_session_key.etype
                );
                let sk = tokens.service_session_key.clone();
                ldap.bind_kerberos_exchange(&bind_dn, &tokens.ap_req, move |server_creds| {
                    ipkt::kerberos::ap_rep_for_ldap_bind(&sk, server_creds)
                        .map_err(|e| e.to_string())
                })
                .await?
            } else if let Some(hex) = gss_ap_req {
                let ap_req = hex::decode(hex.trim())?;
                println!(
                    "[*] SASL GSSAPI/Kerberos init (SPNEGO {} bytes)",
                    gssapi_kerberos_credentials(&ap_req).len()
                );
                ldap.bind_kerberos(&bind_dn, &ap_req).await?
            } else {
                ldap.bind_simple(&bind_dn, password).await?
            };
            println!("bind resultCode={}", bind.result_code);
            let search = SearchRequest {
                base_object: base,
                filter,
                scope: 2,
            };
            let resp = ldap.search(search).await?;
            println!("search response: {} bytes", resp.len());
        }
        Commands::Info => {
            println!("ipkt {}", env!("CARGO_PKG_VERSION"));
            println!("  ipkt-core     binary (de)serialization");
            println!("  ipkt-ntlm     NTLM / NTLMSSP");
            println!("  ipkt-smb      SMB2/3 signing, encryption, RPC");
            println!("  ipkt-kerberos AES-CTS, KDC AS/TGS, AP-REQ/AP-REP, LDAP GSSAPI");
            println!("  ipkt-dcerpc   DCE/RPC");
            println!("  ipkt-rpc      SAMR + DRSUAPI");
            println!("  ipkt-ldap     LDAP GSSAPI bind");
            println!("  ipkt-wmi      ORPC + DCOM stub");
            println!("  CLI           repl-export, kerberos-as-exchange, ldap-search, …");
        }
    }
    Ok(())
}
