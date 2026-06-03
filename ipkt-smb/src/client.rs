use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use ipkt_core::Pack;
use ipkt_ntlm::Credentials;

use crate::commands::{
    CloseRequest, CloseResponse, CreateRequest, CreateResponse, Dialect, NegotiateRequest,
    NegotiateResponse, ReadRequest, ReadResponse, SessionSetupResponse, TreeConnectRequest,
    TreeConnectResponse, WriteRequest, WriteResponse,
};
use crate::encryption::{decrypt_message, encrypt_message, SMB2_TRANSFORM_PROTOCOL_ID};
use crate::error::{Error, Result};
use crate::header::{Smb2Command, Smb2Header, SMB2_HEADER_SIZE};
use crate::packet::{NetbiosSessionMessage, Smb2Packet};
use crate::session::NtlmSessionSetup;
use crate::session_keys::SmbSessionKeys;
use crate::signing::{self, set_signed_flag, sign_message};

pub struct SmbClient {
    stream: TcpStream,
    message_id: AtomicU64,
    session_id: u64,
    tree_id: u32,
    dialect: Dialect,
    signing_enabled: bool,
    encryption_enabled: bool,
    encryption_key: Option<[u8; 16]>,
    session_keys: Option<SmbSessionKeys>,
}

impl SmbClient {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{host}:{port}");
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut client = Self {
            stream,
            message_id: AtomicU64::new(0),
            session_id: 0,
            tree_id: 0,
            dialect: Dialect::Smb302,
            signing_enabled: false,
            encryption_enabled: false,
            encryption_key: None,
            session_keys: None,
        };
        client.negotiate().await?;
        Ok(client)
    }

    fn next_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::SeqCst)
    }

    fn maybe_sign(&self, command: Smb2Command, raw: &mut [u8]) {
        if command == Smb2Command::Negotiate || command == Smb2Command::SessionSetup {
            return;
        }
        let Some(keys) = &self.session_keys else {
            return;
        };
        let Some(signing_key) = keys.signing_key else {
            return;
        };
        if !self.signing_enabled {
            return;
        }
        set_signed_flag(raw);
        sign_message(&signing_key, raw);
    }

    async fn send_recv_raw<B: Pack>(
        &mut self,
        command: Smb2Command,
        body: B,
        payload: Vec<u8>,
        session_id: u64,
        tree_id: u32,
    ) -> Result<Vec<u8>> {
        let header = Smb2Header::request(command, self.next_id(), session_id, tree_id);
        let packet = Smb2Packet {
            header,
            body,
            payload,
        };
        let mut raw = packet.pack();
        self.maybe_sign(command, &mut raw);
        let payload = if self.should_encrypt(command) {
            let enc_key = self
                .encryption_key
                .ok_or(Error::Transport("encryption enabled without key".into()))?;
            encrypt_message(&enc_key, self.session_id, &raw)?
        } else {
            raw
        };
        let framed = NetbiosSessionMessage::wrap(payload);
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let total_len =
            ((len_buf[1] as usize) << 16) | ((len_buf[2] as usize) << 8) | (len_buf[3] as usize);
        let mut buf = vec![0u8; 4 + total_len];
        buf[..4].copy_from_slice(&len_buf);
        self.stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let (nb, _) = NetbiosSessionMessage::unwrap(&buf)?;
        let smb_payload = if nb.payload.starts_with(&SMB2_TRANSFORM_PROTOCOL_ID) {
            let key = self
                .encryption_key
                .as_ref()
                .ok_or(Error::Transport("encrypted response without key".into()))?;
            decrypt_message(key, &nb.payload)?
        } else {
            nb.payload
        };
        if let Some(keys) = &self.session_keys {
            if let Some(signing_key) = keys.signing_key {
                if smb_payload.len() >= SMB2_HEADER_SIZE
                    && signing::header_wants_signing(&smb_payload)
                    && !signing::verify_signature(&signing_key, &smb_payload)
                {
                    return Err(Error::Signing("response signature invalid".into()));
                }
            }
        }
        Ok(smb_payload)
    }

    fn should_encrypt(&self, command: Smb2Command) -> bool {
        if command == Smb2Command::Negotiate || command == Smb2Command::SessionSetup {
            return false;
        }
        self.encryption_enabled && self.encryption_key.is_some()
    }

    async fn send_recv<B: Pack, R: ipkt_core::Unpack>(
        &mut self,
        command: Smb2Command,
        body: B,
        payload: Vec<u8>,
        session_id: u64,
        tree_id: u32,
    ) -> Result<Smb2Packet<R>> {
        let raw = self
            .send_recv_raw(command, body, payload, session_id, tree_id)
            .await?;
        let response = Smb2Packet::<R>::unpack(&raw).map_err(Error::Codec)?;
        if !response.header.is_success() {
            return Err(Error::StatusError {
                status: response.header.status,
                command: response.header.command.as_u16(),
            });
        }
        Ok(response)
    }

    pub async fn negotiate(&mut self) -> Result<Dialect> {
        let body = NegotiateRequest::default();
        let response: Smb2Packet<NegotiateResponse> = self
            .send_recv(Smb2Command::Negotiate, body, Vec::new(), 0, 0)
            .await?;
        self.dialect = response.body.dialect;
        self.signing_enabled = response.body.signing_enabled();
        self.encryption_enabled = self.dialect == Dialect::Smb311
            || self.dialect == Dialect::Smb302
            || self.dialect == Dialect::Smb30;
        Ok(self.dialect)
    }

    pub async fn authenticate_ntlm(&mut self, credentials: Credentials) -> Result<SmbSessionKeys> {
        let mut ntlm = NtlmSessionSetup::new(credentials);
        let req1 = ntlm.first_request(self.next_id());
        let framed = NetbiosSessionMessage::wrap(req1.pack());
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let resp1 = self.read_packet::<SessionSetupResponse>().await?;
        self.session_id = resp1.header.session_id;
        let challenge = ntlm.absorb_challenge(&resp1.body)?;
        let req2 = ntlm.second_request(&challenge, self.next_id(), self.session_id)?;
        let framed = NetbiosSessionMessage::wrap(req2.pack());
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let resp2 = self.read_packet::<SessionSetupResponse>().await?;
        if !resp2.header.is_success() {
            return Err(Error::StatusError {
                status: resp2.header.status,
                command: Smb2Command::SessionSetup.as_u16(),
            });
        }
        self.session_id = resp2.header.session_id;
        let exported = ntlm.exported_session_key(&challenge)?;
        let keys = SmbSessionKeys::from_ntlm(exported, challenge.flags);
        self.encryption_key = Some(crate::encryption::derive_encryption_key(&exported));
        self.session_keys = Some(keys.clone());
        Ok(keys)
    }

    #[must_use]
    pub fn session_keys(&self) -> Option<&SmbSessionKeys> {
        self.session_keys.as_ref()
    }

    pub async fn tree_connect(&mut self, unc_path: &str) -> Result<u32> {
        let body = TreeConnectRequest::new(unc_path);
        let response: Smb2Packet<TreeConnectResponse> = self
            .send_recv(
                Smb2Command::TreeConnect,
                body,
                Vec::new(),
                self.session_id,
                0,
            )
            .await?;
        self.tree_id = response.header.tree_id;
        Ok(self.tree_id)
    }

    pub async fn create(&mut self, name: &str) -> Result<[u8; 16]> {
        let body = CreateRequest::open(name);
        let response: Smb2Packet<CreateResponse> = self
            .send_recv(
                Smb2Command::Create,
                body,
                Vec::new(),
                self.session_id,
                self.tree_id,
            )
            .await?;
        Ok(response.body.file_id)
    }

    pub async fn read(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> Result<Vec<u8>> {
        let body = ReadRequest {
            file_id,
            offset,
            length,
        };
        let raw = self
            .send_recv_raw(
                Smb2Command::Read,
                body,
                Vec::new(),
                self.session_id,
                self.tree_id,
            )
            .await?;
        let response = Smb2Packet::<ReadResponse>::unpack(&raw).map_err(Error::Codec)?;
        if !response.header.is_success() {
            return Err(Error::StatusError {
                status: response.header.status,
                command: Smb2Command::Read.as_u16(),
            });
        }
        let data_offset = response.body.data_offset as usize;
        let data_length = response.body.data_length as usize;
        if data_offset + data_length <= raw.len() {
            return Ok(raw[data_offset..data_offset + data_length].to_vec());
        }
        Ok(response.payload)
    }

    pub async fn write(&mut self, file_id: [u8; 16], offset: u64, data: Vec<u8>) -> Result<u32> {
        let body = WriteRequest {
            file_id,
            offset,
            data: data.clone(),
        };
        let response: Smb2Packet<WriteResponse> = self
            .send_recv(
                Smb2Command::Write,
                body,
                data,
                self.session_id,
                self.tree_id,
            )
            .await?;
        Ok(response.body.count)
    }

    pub async fn pipe_transact(&mut self, file_id: [u8; 16], data: Vec<u8>) -> Result<Vec<u8>> {
        self.write(file_id, 0, data).await?;
        self.read(file_id, 0, 64 * 1024).await
    }

    pub async fn close(&mut self, file_id: [u8; 16]) -> Result<()> {
        let body = CloseRequest { file_id };
        let _: Smb2Packet<CloseResponse> = self
            .send_recv(
                Smb2Command::Close,
                body,
                Vec::new(),
                self.session_id,
                self.tree_id,
            )
            .await?;
        Ok(())
    }

    async fn read_packet<R: ipkt_core::Unpack>(&mut self) -> Result<Smb2Packet<R>> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let total_len =
            ((len_buf[1] as usize) << 16) | ((len_buf[2] as usize) << 8) | (len_buf[3] as usize);
        let mut buf = vec![0u8; 4 + total_len];
        buf[..4].copy_from_slice(&len_buf);
        self.stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let (nb, _) = NetbiosSessionMessage::unwrap(&buf)?;
        let packet = Smb2Packet::<R>::unpack(&nb.payload).map_err(Error::Codec)?;
        Ok(packet)
    }

    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    #[must_use]
    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    #[must_use]
    pub fn signing_enabled(&self) -> bool {
        self.signing_enabled
    }
}
