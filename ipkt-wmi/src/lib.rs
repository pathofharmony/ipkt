#![allow(missing_docs)]

mod dcom;
mod orpc;

pub use dcom::{RemoteActivation, WMI_CLSID};
pub use orpc::{OrpcThat, OrpcThis};
