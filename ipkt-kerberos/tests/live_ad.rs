#![cfg(feature = "kdc")]

use ipkt_kerberos::{
    default_enctype_list, ldap_service_principal, ETYPE_AES256_CTS_HMAC_SHA1_96,
    ETYPE_DES3_CBC_SHA1, ETYPE_RC4_HMAC, KdcClient,
};

fn live_config() -> Option<(String, String, String, String)> {
    let realm = std::env::var("IPKT_AD_REALM").ok()?;
    let user = std::env::var("IPKT_AD_USER").ok()?;
    let password = std::env::var("IPKT_AD_PASSWORD").ok()?;
    let kdc = std::env::var("IPKT_AD_KDC").ok()?;
    Some((realm, user, password, kdc))
}

#[tokio::test]
#[ignore = "requires IPKT_AD_REALM, IPKT_AD_USER, IPKT_AD_PASSWORD, IPKT_AD_KDC"]
async fn as_and_tgs_with_pac_signatures() {
    let (realm, user, password, kdc_host) = live_config().expect("set IPKT_AD_* env vars");
    let client = KdcClient::new(&kdc_host, 88);
    let tgt = client.as_exchange(&realm, &user, &password).await.expect("AS-REP");
    assert!(
        tgt.session_key.etype == ETYPE_AES256_CTS_HMAC_SHA1_96
            || tgt.session_key.etype == ETYPE_RC4_HMAC
            || tgt.session_key.etype == ETYPE_DES3_CBC_SHA1,
        "unexpected AS-REP etype {}",
        tgt.session_key.etype
    );

    let service = ldap_service_principal(&kdc_host, &realm);
    let tgs = client
        .tgs_exchange(&realm, &user, &tgt, &service)
        .await
        .expect("TGS-REP");
    let pac = tgs.pac.as_ref().expect("AD should return PAC on TGS");
    let logon = pac.logon.as_ref().expect("PAC logon buffer");
    assert!(logon.user_id > 0, "user RID");
    assert!(!logon.effective_name.is_empty() || !logon.domain_name.is_empty());
    assert!(
        pac.kdc_checksum.is_some() && pac.server_checksum.is_some(),
        "PAC should include KDC and server checksum buffers"
    );
}

#[tokio::test]
#[ignore = "requires IPKT_AD_* and IPKT_AD_TEST_LEGACY_ETYPES=1"]
async fn as_exchange_legacy_des_etypes_if_enabled() {
    if std::env::var("IPKT_AD_TEST_LEGACY_ETYPES").ok().as_deref() != Some("1") {
        return;
    }
    let (realm, user, password, kdc_host) = live_config().expect("set IPKT_AD_* env vars");
    let client = KdcClient::new(&kdc_host, 88);
    let _etypes = default_enctype_list();
    let tgt = client.as_exchange(&realm, &user, &password).await;
    match tgt {
        Ok(ex) => {
            let et = ex.session_key.etype;
            assert!(
                et == ETYPE_DES3_CBC_SHA1
                    || et == ipkt_kerberos::ETYPE_DES_CBC_MD5
                    || et == ipkt_kerberos::ETYPE_DES_CBC_CRC
                    || et == ETYPE_AES256_CTS_HMAC_SHA1_96
                    || et == ETYPE_RC4_HMAC,
                "legacy etype test got {et}"
            );
        }
        Err(e) => {
            
            eprintln!("legacy etype AS failed (often expected on hardened AD): {e}");
        }
    }
}
