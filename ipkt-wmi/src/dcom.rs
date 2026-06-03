use ipkt_core::{ByteWriter, Pack};

use crate::OrpcThis;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteActivation {
    
    pub orpc: OrpcThis,
    
    pub class_id: [u8; 16],
}

impl RemoteActivation {
    
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut w = ByteWriter::new();
        self.orpc.pack_into(&mut w);
        w.write_bytes(&self.class_id);
        w.into_vec()
    }
}


pub const WMI_CLSID: [u8; 16] = [
    0x11, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11, 0x8F, 0x89, 0x00, 0xAA, 0x00, 0x4B, 0x2E,
    0x24,
];
