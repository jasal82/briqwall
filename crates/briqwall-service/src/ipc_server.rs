//! Named-pipe control server.
//!
//! Security model:
//! * The pipe rejects remote clients and network logons.
//! * Ordinary users can connect but cannot create additional pipe instances
//!   (prevents instance squatting / man-in-the-middle).
//! * Every connection is classified as privileged (elevated administrator) or
//!   not. The core only lets privileged clients *loosen* protection; anyone may
//!   tighten it. Malware running as the user therefore cannot whitelist itself.

use crate::core::Msg;
use anyhow::Result;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use briqwall_common::ipc::{read_frame, write_frame};
use briqwall_common::util::wide;
use briqwall_common::{ErrorCode, Request, Response, PIPE_NAME};

/// D: deny network logons; SYSTEM/Admins/owner full; authenticated users
/// read + write data, but *not* FILE_CREATE_PIPE_INSTANCE (0x4).
const PIPE_SDDL: &str = "D:(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;AU)";

struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

pub fn spawn(tx: Sender<Msg>) {
    std::thread::Builder::new()
        .name("ipc-listen".into())
        .spawn(move || {
            if let Err(e) = listen(tx) {
                log::error!("IPC-Server beendet: {e:#}");
            }
        })
        .expect("spawn ipc");
}

fn listen(tx: Sender<Msg>) -> Result<()> {
    let sddl = wide(PIPE_SDDL);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)?;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let name = wide(PIPE_NAME);
    let mut first = true;
    loop {
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            // Fails if someone else already owns the name (squatting attempt).
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let h = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                1 << 16,
                1 << 16,
                0,
                Some(&sa),
            )
        };
        if h.is_invalid() {
            let err = windows::core::Error::from_thread();
            log::error!("CreateNamedPipeW: {err}");
            let taken = [ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY].iter().any(|c| c.to_hresult() == err.code());
            if first && taken {
                log::error!("Pipe-Name ist bereits belegt – läuft Briqwall doppelt oder blockiert ein anderer Prozess den Namen?");
            }
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        first = false;
        let connected = match unsafe { ConnectNamedPipe(h, None) } {
            Ok(()) => true,
            Err(e) => e.code() == ERROR_PIPE_CONNECTED.to_hresult(),
        };
        if !connected {
            unsafe {
                let _ = CloseHandle(h);
            }
            continue;
        }
        let tx = tx.clone();
        let sh = SendHandle(h);
        let _ = std::thread::Builder::new().name("ipc-client".into()).spawn(move || {
            let sh = sh;
            serve(sh.0, tx);
            unsafe {
                let _ = DisconnectNamedPipe(sh.0);
                let _ = CloseHandle(sh.0);
            }
        });
    }
    // `sd` intentionally lives for the lifetime of the process.
}

fn serve(h: HANDLE, tx: Sender<Msg>) {
    let mut privileged: Option<bool> = None;
    loop {
        let Ok(frame) = read_frame(h) else { return };
        // Impersonation is only possible after reading from the pipe.
        let priv_ = *privileged.get_or_insert_with(|| client_is_admin(h));
        let resp = match serde_json::from_slice::<Request>(&frame) {
            Ok(req) => {
                let (rtx, rrx) = mpsc::channel();
                if tx.send(Msg::Ipc { req, privileged: priv_, reply: rtx }).is_err() {
                    return;
                }
                rrx.recv_timeout(Duration::from_secs(30))
                    .unwrap_or(Response::Error(ErrorCode::ServiceTimeout))
            }
            Err(e) => Response::Error(ErrorCode::BadRequest(e.to_string())),
        };
        let Ok(bytes) = serde_json::to_vec(&resp) else { return };
        if write_frame(h, &bytes).is_err() {
            return;
        }
    }
}

/// Is the client an *elevated* administrator? (Filtered UAC tokens carry the
/// Administrators SID as deny-only, so CheckTokenMembership returns false.)
fn client_is_admin(h: HANDLE) -> bool {
    unsafe {
        if ImpersonateNamedPipeClient(h).is_err() {
            return false;
        }
        let mut buf = [0u8; 68];
        let mut size = buf.len() as u32;
        let sid = PSID(buf.as_mut_ptr() as *mut _);
        let mut member = windows::core::BOOL(0);
        let ok = CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size).is_ok()
            && CheckTokenMembership(None, sid, &mut member).is_ok();
        let _ = RevertToSelf();
        ok && member.as_bool()
    }
}

#[cfg(test)]
mod probe {
    use super::*;
    #[test]
    fn pipe_create_variants() {
        let name = wide(r"\.\pipe\briqwall-probe-test");
        let sddl = wide(PIPE_SDDL);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None).unwrap() };
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        for (label, mode, sa_opt) in [
            ("plain", PIPE_TYPE_BYTE, None),
            ("reject", PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, None),
            ("sd", PIPE_TYPE_BYTE, Some(&sa)),
        ] {
            let h = unsafe { CreateNamedPipeW(PCWSTR(name.as_ptr()), PIPE_ACCESS_DUPLEX, mode, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sa_opt.map(|s| s as *const _)) };
            let err = windows::core::Error::from_thread();
            eprintln!("{label}: invalid={} err={err}", h.is_invalid());
            if !h.is_invalid() { unsafe { let _ = CloseHandle(h); } }
        }
    }
}
