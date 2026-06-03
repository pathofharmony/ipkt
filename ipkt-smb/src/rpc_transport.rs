use ipkt_dcerpc::{
    parse_rpc_pdu, BindPdu, ParsedRpcPdu, PduType, RequestPdu, RpcHeader, RpcMessage, Uuid,
};
use ipkt_rpc::{
    drs_bind_request, drs_crack_names_request, drs_domain_controller_info_request,
    drs_get_nc_changes_request, drsu_bind_uuids, parse_samr_connect_response, samr_connect_request,
    SamrConnectResponse,
};

use crate::client::SmbClient;
use crate::error::Result;
use crate::pipe::{ipc_unc, pipe_create_path, paths};
use ipkt_rpc::samr_bind_uuids;


pub struct SmbRpcTransport {
    file_id: [u8; 16],
    pipe_name: String,
    call_id: u32,
}

impl SmbRpcTransport {
    
    pub async fn connect_drsu(client: &mut SmbClient, host: &str) -> Result<Self> {
        Self::connect_pipe(client, host, "drsuapi").await
    }

    
    pub async fn drs_bind(&mut self, client: &mut SmbClient) -> Result<Vec<u8>> {
        let (a, b) = drsu_bind_uuids().map_err(|e| crate::Error::Transport(e.to_string()))?;
        self.bind(client, a, b).await?;
        client
            .pipe_transact(self.file_id, drs_bind_request().pack())
            .await
    }

    
    pub async fn drs_domain_controller_info(
        &mut self,
        client: &mut SmbClient,
        drs_handle: &[u8; 20],
        domain: &str,
    ) -> Result<Vec<u8>> {
        client
            .pipe_transact(
                self.file_id,
                drs_domain_controller_info_request(drs_handle, domain).pack(),
            )
            .await
    }

    
    pub async fn drs_crack_names(
        &mut self,
        client: &mut SmbClient,
        drs_handle: &[u8; 20],
        name: &str,
    ) -> Result<Vec<u8>> {
        client
            .pipe_transact(
                self.file_id,
                drs_crack_names_request(drs_handle, name, 0, 0).pack(),
            )
            .await
    }

    
    #[allow(clippy::too_many_arguments)]
    pub async fn drs_get_nc_changes(
        &mut self,
        client: &mut SmbClient,
        drs_handle: &[u8; 20],
        dsa_guid: [u8; 16],
        invocation_id: [u8; 16],
        nc_dn: &str,
        c_max_objects: u32,
        extended_op: u32,
        usnvec: Option<ipkt_rpc::DrsUsnVector>,
    ) -> Result<Vec<u8>> {
        client
            .pipe_transact(
                self.file_id,
                drs_get_nc_changes_request(
                    drs_handle,
                    dsa_guid,
                    invocation_id,
                    nc_dn,
                    c_max_objects,
                    extended_op,
                    usnvec,
                )
                .pack(),
            )
            .await
    }

    
    pub async fn connect_samr(client: &mut SmbClient, host: &str) -> Result<Self> {
        Self::connect_pipe(client, host, paths::SAMR).await
    }

    
    pub async fn connect_pipe(
        client: &mut SmbClient,
        host: &str,
        pipe: &str,
    ) -> Result<Self> {
        client.tree_connect(&ipc_unc(host)).await?;
        let path = pipe_create_path(pipe);
        let file_id = client.create(&path).await?;
        Ok(Self {
            file_id,
            pipe_name: pipe.to_string(),
            call_id: 0,
        })
    }

    
    pub async fn bind(
        &mut self,
        client: &mut SmbClient,
        abstract_syntax: Uuid,
        transfer_syntax: Uuid,
    ) -> Result<Vec<u8>> {
        let pdu = BindPdu {
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group: 0,
            context_id: 0,
            abstract_syntax,
            transfer_syntax,
        };
        let msg = RpcMessage {
            header: RpcHeader::new(PduType::Bind, self.call_id),
            body: pdu,
        };
        self.call_id += 1;
        client.pipe_transact(self.file_id, msg.pack()).await
    }

    
    pub async fn bind_samr(&mut self, client: &mut SmbClient) -> Result<Vec<u8>> {
        let (abstract_syntax, transfer_syntax) = samr_bind_uuids()
            .map_err(|e| crate::Error::Transport(e.to_string()))?;
        self.bind(client, abstract_syntax, transfer_syntax).await
    }

    
    pub async fn request(&mut self, client: &mut SmbClient, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>> {
        let body = RequestPdu {
            alloc_hint: stub.len() as u32,
            context_id: 0,
            opnum,
            stub,
        };
        let msg = RpcMessage {
            header: RpcHeader::new(PduType::Request, self.call_id),
            body,
        };
        self.call_id += 1;
        client.pipe_transact(self.file_id, msg.pack()).await
    }

    
    #[must_use]
    pub fn file_id(&self) -> [u8; 16] {
        self.file_id
    }

    
    pub async fn samr_connect(
        &mut self,
        client: &mut SmbClient,
        access_mask: u32,
    ) -> Result<SamrConnectResponse> {
        let msg = samr_connect_request(None, access_mask);
        let raw = client.pipe_transact(self.file_id, msg.pack()).await?;
        let (_hdr, parsed) = parse_rpc_pdu(&raw).map_err(|e| crate::Error::Transport(e.to_string()))?;
        let stub = match parsed {
            ParsedRpcPdu::Response(r) => r.stub,
            ParsedRpcPdu::Fault(f) => {
                return Err(crate::Error::Transport(format!("RPC fault {:#x}", f.status)));
            }
            other => {
                return Err(crate::Error::Transport(format!(
                    "unexpected RPC pdu {other:?}"
                )));
            }
        };
        parse_samr_connect_response(&stub)
            .ok_or_else(|| crate::Error::Transport("invalid SamrConnect stub".into()))
    }

    
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}
