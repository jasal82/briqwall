//! Control-pipe framing and client.
//!
//! Wire format: `u32` little-endian length followed by a JSON document.
//! One request → one response; a connection may carry several exchanges.

use crate::model::{Request, Response};
use crate::util::wide;
use anyhow::{anyhow, bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

/// Upper bound for a single message (the app list can get large).
pub const MAX_FRAME: usize = 32 * 1024 * 1024;

pub fn write_frame(h: HANDLE, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all(h, &len)?;
    write_all(h, payload)
}

pub fn read_frame(h: HANDLE) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    read_exact(h, &mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    read_exact(h, &mut buf)?;
    Ok(buf)
}

fn write_all(h: HANDLE, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let mut written = 0u32;
        unsafe { WriteFile(h, Some(data), Some(&mut written), None) }.context("pipe write")?;
        if written == 0 {
            bail!("pipe closed");
        }
        data = &data[written as usize..];
    }
    Ok(())
}

fn read_exact(h: HANDLE, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let mut read = 0u32;
        unsafe { ReadFile(h, Some(buf), Some(&mut read), None) }.context("pipe read")?;
        if read == 0 {
            bail!("pipe closed");
        }
        buf = &mut buf[read as usize..];
    }
    Ok(())
}

/// A connection to the Briqwall service.
pub struct Client {
    h: HANDLE,
}

unsafe impl Send for Client {}

impl Client {
    pub fn connect() -> Result<Self> {
        let name = wide(crate::PIPE_NAME);
        for _ in 0..3 {
            // SECURITY_IDENTIFICATION: the server may *identify* us (to check
            // elevation) but can never act on our behalf. Protects against a
            // rogue process squatting on the pipe name.
            let flags =
                FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0);
            let res = unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    (GENERIC_READ | GENERIC_WRITE).0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    flags,
                    None,
                )
            };
            match res {
                Ok(h) => return Ok(Self { h }),
                Err(e) if e.code() == windows::Win32::Foundation::ERROR_PIPE_BUSY.to_hresult() => {
                    unsafe {
                        let _ = WaitNamedPipeW(PCWSTR(name.as_ptr()), 1500);
                    }
                }
                Err(e) => return Err(anyhow!("Dienst nicht erreichbar: {}", e.message())),
            }
        }
        bail!("Dienst ist ausgelastet")
    }

    pub fn call(&mut self, req: &Request) -> Result<Response> {
        let payload = serde_json::to_vec(req)?;
        write_frame(self.h, &payload)?;
        let resp = read_frame(self.h)?;
        Ok(serde_json::from_slice(&resp)?)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.h);
        }
    }
}

/// Convenience: one-shot request on a fresh connection.
pub fn call(req: &Request) -> Result<Response> {
    Client::connect()?.call(req)
}
