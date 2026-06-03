#![allow(missing_docs)]
use ipkt_core::{Pack, Unpack};
use ipkt_wmi::{OrpcThat, OrpcThis};

#[test]
fn orpc_this_round_trips() {
    let v = OrpcThis {
        flags: 1,
        cid: 0x42,
    };
    assert_eq!(OrpcThis::unpack(&v.pack()).unwrap(), v);
}

#[test]
fn orpc_that_round_trips() {
    let v = OrpcThat::default();
    assert_eq!(OrpcThat::unpack(&v.pack()).unwrap(), v);
}
