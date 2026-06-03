#![allow(missing_docs)]
use ipkt_wmi::{OrpcThis, RemoteActivation, WMI_CLSID};

#[test]
fn remote_activation_packs_orpc_and_clsid() {
    let req = RemoteActivation {
        orpc: OrpcThis {
            flags: 1,
            cid: 0x42,
        },
        class_id: WMI_CLSID,
    };
    let bytes = req.pack();
    assert!(bytes.len() >= 24);
}
