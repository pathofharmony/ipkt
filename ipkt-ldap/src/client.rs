use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ber::read_len;
use crate::error::{Error, Result};
use crate::messages::{BindRequest, LdapOp, SearchRequest};
use crate::spnego::gssapi_kerberos_credentials;
use ipkt_core::ByteReader;

pub const LDAP_SASL_BIND_IN_PROGRESS: u8 = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResult {
    pub result_code: u8,

    pub message: String,

    pub server_sasl_creds: Option<Vec<u8>>,
}

pub struct LdapClient {
    stream: TcpStream,
    message_id: i32,
}

impl LdapClient {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{host}:{port}");
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self {
            stream,
            message_id: 1,
        })
    }

    fn next_id(&mut self) -> i32 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }

    async fn send_recv(&mut self, pdu: Vec<u8>) -> Result<Vec<u8>> {
        self.stream
            .write_all(&pdu)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut buf = vec![0u8; 64 * 1024];
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn bind_kerberos_exchange(
        &mut self,
        name: impl Into<String>,
        ap_req: &[u8],
        make_ap_rep: impl FnOnce(Option<&[u8]>) -> std::result::Result<Vec<u8>, String>,
    ) -> Result<BindResult> {
        let name = name.into();
        let creds = gssapi_kerberos_credentials(ap_req);
        let first = self.bind_sasl(&name, "GSSAPI", creds).await?;
        if first.result_code == 0 {
            return Ok(first);
        }
        if first.result_code != LDAP_SASL_BIND_IN_PROGRESS {
            return Ok(first);
        }
        let ap_rep = make_ap_rep(first.server_sasl_creds.as_deref()).map_err(Error::Ber)?;
        let resp_creds = crate::spnego::gssapi_kerberos_response(&ap_rep);
        self.bind_sasl(&name, "GSSAPI", resp_creds).await
    }

    pub async fn bind_kerberos(
        &mut self,
        name: impl Into<String>,
        ap_req: &[u8],
    ) -> Result<BindResult> {
        let creds = gssapi_kerberos_credentials(ap_req);
        self.bind_sasl(name, "GSSAPI", creds).await
    }

    pub async fn bind_sasl(
        &mut self,
        name: impl Into<String>,
        mechanism: impl Into<String>,
        credentials: Vec<u8>,
    ) -> Result<BindResult> {
        let req = BindRequest::sasl(3, name, mechanism, credentials);
        let id = self.next_id();
        let resp = self.send_recv(req.encode(id)).await?;
        decode_bind_response(&resp)
    }

    pub async fn bind_simple(
        &mut self,
        name: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> Result<BindResult> {
        let req = BindRequest::simple(3, name, password);
        let id = self.next_id();
        let resp = self.send_recv(req.encode(id)).await?;
        decode_bind_response(&resp)
    }

    pub async fn search(&mut self, request: SearchRequest) -> Result<Vec<u8>> {
        let id = self.next_id();
        self.send_recv(request.encode(id)).await
    }
}

fn decode_bind_response(bytes: &[u8]) -> Result<BindResult> {
    let mut reader = ByteReader::new(bytes);
    if reader.read_u8()? != 0x30 {
        return Err(Error::Ber("expected SEQUENCE".into()));
    }
    let _ = read_len(&mut reader)?;
    let _id_tag = reader.read_u8()?;
    if _id_tag != 0x02 {
        return Err(Error::Ber("expected message id INTEGER".into()));
    }
    let id_len = read_len(&mut reader)?;
    let _ = reader.read_bytes(id_len)?;
    let op_tag = reader.read_u8()?;
    if op_tag != 0x0A {
        return Err(Error::Ber(format!(
            "expected ENUMERATED op, got {op_tag:#x}"
        )));
    }
    let _ = read_len(&mut reader)?;
    let op = reader.read_u8()?;
    if op != LdapOp::BindResponse as u8 {
        return Err(Error::Ber(format!("expected BindResponse, got {op}")));
    }
    let bind_len = read_len(&mut reader)?;
    let bind_end = reader.position() + bind_len;
    let mut result_code = 0u8;
    let mut message = String::new();
    let mut server_sasl_creds = None;
    while reader.position() < bind_end && !reader.is_empty() {
        let tag = reader.read_u8()?;
        let len = read_len(&mut reader)?;
        let chunk = reader.read_bytes(len)?;
        match tag {
            0x0A => result_code = chunk.first().copied().unwrap_or(0),
            0x04 if message.is_empty() => message = String::from_utf8_lossy(chunk).into_owned(),
            0x87 => server_sasl_creds = Some(chunk.to_vec()),
            _ => {}
        }
    }
    Ok(BindResult {
        result_code,
        message,
        server_sasl_creds,
    })
}
