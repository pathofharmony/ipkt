pub mod paths {

    pub const SAMR: &str = "samr";

    pub const LSARPC: &str = "lsarpc";

    pub const SRVSVC: &str = "srvsvc";

    pub const WINREG: &str = "winreg";

    pub const NETLOGON: &str = "netlogon";
}

#[must_use]
pub fn pipe_create_path(pipe_name: &str) -> String {
    if pipe_name.starts_with('\\') {
        pipe_name.to_string()
    } else {
        format!("\\{pipe_name}")
    }
}

#[must_use]
pub fn ipc_unc(server: &str) -> String {
    format!("\\\\{server}\\IPC$")
}
