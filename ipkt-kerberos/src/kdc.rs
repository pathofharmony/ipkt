use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::ap_req::{encode_ap_req, encode_pa_tgs_req, ldap_service_principal};
use crate::enc_kdc::{
    extract_and_verify_pac_from_tgs_rep, session_key_from_as_rep, session_key_from_tgs_rep,
};
use crate::krb_error::try_decode_krb_error;
use crate::pac::Pac;
use crate::messages::{
    decode_as_rep, decode_tgs_rep, encode_as_req_with_padata, encode_tgs_req_with_padata, AsRep,
    AsReq, KdcReqBody, TgsReq,
};
use crate::pa_data::{build_pa_enc_timestamp, encode_pa_enc_timestamp, encode_pa_pac_request};
use crate::session_key::{default_enctype_list, KerberosSessionKey};
use crate::types::{PrincipalName, Realm};
use crate::Result;


#[derive(Debug, Clone)]
pub struct AsExchange {
    pub as_rep: AsRep,
    pub session_key: KerberosSessionKey,
}


#[derive(Debug, Clone)]
pub struct TgsExchange {
    pub tgs_rep: crate::messages::TgsRep,
    pub service_session_key: KerberosSessionKey,
    pub ticket: Vec<u8>,
    
    pub pac: Option<Pac>,
}


#[derive(Debug, Clone)]
pub struct LdapKerberosTokens {
    pub ap_req: Vec<u8>,
    pub service_session_key: KerberosSessionKey,
}


pub struct KdcClient {
    kdc_addr: String,
}

impl KdcClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            kdc_addr: format!("{host}:{port}"),
        }
    }

    pub async fn as_exchange(
        &self,
        realm: &str,
        user: &str,
        password: &str,
    ) -> Result<AsExchange> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let pa = build_pa_enc_timestamp(password, realm, user, now.as_secs(), now.subsec_micros())?;
        let pa_der = encode_pa_enc_timestamp(&pa);
        let body = KdcReqBody {
            kdc_options: 0x4080_0000,
            cname: PrincipalName::new(1, vec![user.into()]),
            realm: Realm::new(realm),
            sname: None,
            nonce: 0xAABB_CCDD,
            etype: default_enctype_list(),
        };
        let req = AsReq {
            pvno: 5,
            msg_type: 10,
            req_body: body,
        };
        let padata = encode_pa_data_sequence(&[&pa_der]);
        let der = encode_as_req_with_padata(&req, Some(&padata))?;
        let resp = self.send_recv(&der).await?;
        check_kdc_error(&resp)?;
        let as_rep = decode_as_rep(&resp)?;
        let session_key = session_key_from_as_rep(password, realm, user, &as_rep.enc_part)?;
        Ok(AsExchange {
            as_rep,
            session_key,
        })
    }

    pub async fn tgs_exchange(
        &self,
        realm: &str,
        user: &str,
        tgt: &AsExchange,
        service: &PrincipalName,
    ) -> Result<TgsExchange> {
        let ap_req = encode_ap_req(
            &tgt.as_rep.ticket,
            &tgt.session_key,
            realm,
            &PrincipalName::new(1, vec![user.into()]),
            service,
        )?;
        let pa_tgs = encode_pa_tgs_req(&ap_req);
        let pa_pac = encode_pa_pac_request();
        let padata = encode_pa_data_sequence(&[&pa_tgs, &pa_pac]);
        let body = KdcReqBody {
            kdc_options: 0x4080_0000,
            cname: PrincipalName::new(1, vec![user.into()]),
            realm: Realm::new(realm),
            sname: Some(service.clone()),
            nonce: 0xCCDD_EEFF,
            etype: default_enctype_list(),
        };
        let req = TgsReq {
            pvno: 5,
            msg_type: 12,
            req_body: body,
        };
        let der = encode_tgs_req_with_padata(&req, Some(&padata))?;
        let resp = self.send_recv(&der).await?;
        check_kdc_error(&resp)?;
        let tgs_rep = decode_tgs_rep(&resp)?;
        let service_session_key =
            session_key_from_tgs_rep(&tgt.session_key, &tgs_rep.enc_part)?;
        let pac = extract_and_verify_pac_from_tgs_rep(
            &tgt.session_key,
            &tgs_rep.enc_part,
            &service_session_key,
        )?;
        Ok(TgsExchange {
            ticket: tgs_rep.ticket.clone(),
            tgs_rep,
            service_session_key,
            pac,
        })
    }

    pub async fn ldap_tokens(
        &self,
        realm: &str,
        user: &str,
        password: &str,
        ldap_host: &str,
    ) -> Result<LdapKerberosTokens> {
        let tgt = self.as_exchange(realm, user, password).await?;
        let service = ldap_service_principal(ldap_host, realm);
        let tgs = self.tgs_exchange(realm, user, &tgt, &service).await?;
        let ap_req = encode_ap_req(
            &tgs.ticket,
            &tgs.service_session_key,
            realm,
            &PrincipalName::new(1, vec![user.into()]),
            &service,
        )?;
        Ok(LdapKerberosTokens {
            ap_req,
            service_session_key: tgs.service_session_key,
        })
    }

    async fn send_recv(&self, req: &[u8]) -> Result<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        sock.connect(&self.kdc_addr)
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        sock.send(req)
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        let mut buf = vec![0u8; 64 * 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sock.recv(&mut buf),
        )
        .await
        .map_err(|_| crate::Error::Transport("KDC timeout".into()))?
        .map_err(|e| crate::Error::Transport(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn check_kdc_error(resp: &[u8]) -> Result<()> {
    if let Some(err) = try_decode_krb_error(resp) {
        return Err(err.into());
    }
    Ok(())
}

fn encode_pa_data_sequence(entries: &[&[u8]]) -> Vec<u8> {
    use crate::asn1::encode_sequence;
    let payload: Vec<u8> = entries.iter().copied().flatten().copied().collect();
    encode_sequence(&payload)
}
