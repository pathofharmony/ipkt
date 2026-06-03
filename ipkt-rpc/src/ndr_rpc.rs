use ipkt_core::ByteWriter;

pub const NTDSAPI_CLIENT_GUID: [u8; 16] = [
    0x1a, 0x20, 0x4d, 0xe2, 0xd6, 0x4f, 0xd1, 0x11, 0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d,
];

#[derive(Debug, Default)]
pub struct NdrRpcEncoder {
    buf: ByteWriter,
    next_ref: u32,
}

impl NdrRpcEncoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: ByteWriter::new(),
            next_ref: 0x0002_0000,
        }
    }

    fn alloc_ref(&mut self) -> u32 {
        let id = self.next_ref;
        self.next_ref = self.next_ref.saturating_add(4);
        id
    }

    fn align(&mut self, n: usize) {
        let pad = (n - (self.buf.len() % n)) % n;
        for _ in 0..pad {
            self.buf.write_u8(0);
        }
    }

    fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.write_u32_le(v);
    }

    fn write_ptr(&mut self, referent: u32) {
        self.write_u32(referent);
    }

    fn write_uuid(&mut self, guid: [u8; 16]) {
        self.align(4);
        self.buf.write_bytes(&guid);
    }

    fn write_rpc_unicode(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().chain([0]).collect();
        let max = (units.len().saturating_sub(1)) as u32;
        self.write_u32(max);
        self.write_u32(0);
        self.write_u32(max);
        self.align(2);
        for u in units {
            self.buf.write_u16_le(u);
        }
    }

    fn write_dsname_deferred(&mut self, dn: &str) {
        let units: Vec<u16> = dn.encode_utf16().chain([0]).collect();
        let name_len = (units.len().saturating_sub(1)) as u32;
        let struct_len = 28 + 4 + (name_len as usize) * 2;
        self.write_u32(struct_len as u32);
        self.write_u32(0);
        self.write_uuid([0u8; 16]);
        self.write_u32(0);
        for _ in 0..28 {
            self.buf.write_u8(0);
        }
        self.write_u32(name_len);
        self.write_rpc_unicode(dn);
    }

    fn take(&mut self) -> Vec<u8> {
        let out = std::mem::replace(&mut self.buf, ByteWriter::new()).into_vec();
        self.next_ref = 0x0002_0000;
        out
    }

    pub fn drs_bind(mut self) -> Vec<u8> {
        let ext_ref = self.alloc_ref();
        let uuid_ref = self.alloc_ref();
        self.write_ptr(uuid_ref);
        self.write_ptr(ext_ref);
        self.write_uuid(NTDSAPI_CLIENT_GUID);
        let cb = 48u32;
        self.write_u32(cb);
        let flags =
            0x0040_0000u32 | 0x0080_0000 | 0x0100_0000 | 0x0200_0000 | 0x0400_0000 | 0x0000_8000;
        self.write_u32(flags);
        self.write_uuid([0u8; 16]);
        self.write_u32(0);
        self.write_uuid([0u8; 16]);
        self.write_uuid([0u8; 16]);
        self.write_u32(0);
        self.write_u32(0);
        self.take()
    }

    pub fn drs_domain_controller_info(mut self, drs_handle: &[u8; 20], domain: &str) -> Vec<u8> {
        self.write_drs_handle(drs_handle);
        self.write_u32(1);
        self.write_u32(1);
        let domain_ref = self.alloc_ref();
        self.write_ptr(domain_ref);
        self.write_rpc_unicode(domain);
        self.write_u32(2);
        self.take()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn drs_get_nc_changes_v8(
        mut self,
        drs_handle: &[u8; 20],
        dsa_guid: [u8; 16],
        invocation_id: [u8; 16],
        nc_dn: &str,
        partial_attrs: &[u32],
        ul_flags: u32,
        c_max_objects: u32,
        ul_extended_op: u32,
        usnvec: Option<(u32, u32, u32)>,
    ) -> Vec<u8> {
        self.write_drs_handle(drs_handle);
        self.write_u32(8);
        self.write_u32(8);

        self.write_uuid(dsa_guid);
        self.write_uuid(invocation_id);

        let nc_ref = self.alloc_ref();
        self.write_ptr(nc_ref);
        self.write_dsname_deferred(nc_dn);

        if let Some((obj, reserved, prop)) = usnvec {
            self.write_u32(obj);
            self.write_u32(reserved);
            self.write_u32(prop);
        } else {
            self.write_u32(0);
            self.write_u32(0);
            self.write_u32(0);
        }

        self.write_ptr(0);

        self.write_u32(ul_flags);
        self.write_u32(c_max_objects);
        self.write_u32(0);
        self.write_u32(ul_extended_op);
        self.write_u32(0);
        self.write_u32(0);

        let pattr_ref = self.alloc_ref();
        self.write_ptr(pattr_ref);
        self.write_partial_attr_vector(partial_attrs);

        self.write_ptr(0);
        self.write_u32(0);
        self.write_ptr(0);

        self.take()
    }

    fn write_drs_handle(&mut self, handle: &[u8; 20]) {
        self.align(4);
        self.buf.write_bytes(handle);
    }

    fn write_partial_attr_vector(&mut self, attrs: &[u32]) {
        self.write_u32(1);
        self.write_u32(0);
        self.write_u32(attrs.len() as u32);
        let attrs_ref = self.alloc_ref();
        self.write_ptr(attrs_ref);
        self.write_u32(attrs.len() as u32);
        self.write_u32(0);
        self.write_u32(attrs.len() as u32);
        self.align(4);
        for &a in attrs {
            self.write_u32(a);
        }
    }

    pub fn drs_crack_names_v1(
        mut self,
        drs_handle: &[u8; 20],
        name: &str,
        format_offered: u32,
        format_desired: u32,
    ) -> Vec<u8> {
        const DS_NT4_ACCOUNT_NAME: u32 = 2;
        const DS_UNIQUE_ID_NAME: u32 = 6;
        let offered = if format_offered != 0 {
            format_offered
        } else {
            DS_NT4_ACCOUNT_NAME
        };
        let desired = if format_desired != 0 {
            format_desired
        } else {
            DS_UNIQUE_ID_NAME
        };
        self.write_drs_handle(drs_handle);
        self.write_u32(1);
        self.write_u32(1);
        self.write_u32(0);
        self.write_u32(0);
        self.write_u32(0);
        self.write_u32(offered);
        self.write_u32(desired);
        self.write_u32(1);
        let names_ptr = self.alloc_ref();
        self.write_ptr(names_ptr);
        let name_ptr = self.alloc_ref();
        self.write_ptr(name_ptr);
        self.write_rpc_unicode(name);
        self.take()
    }
}
