//! Thin, safe-ish wrapper around the Windows Filtering Platform management API.
//!
//! All Briqwall objects (provider, sublayer, filters) are *persistent*: they survive
//! a service crash or reboot, so the machine fails closed instead of open.

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use briqwall_common::util::wide;

pub const PROVIDER_KEY: GUID = GUID::from_u128(0x5f1c9a3e_7b2d_4c8e_9a41_2d7e6b0c3f11);
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x5f1c9a3e_7b2d_4c8e_9a41_2d7e6b0c3f12);

pub const LAYER_OUT_V4: GUID = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
pub const LAYER_OUT_V6: GUID = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
pub const LAYER_IN_V4: GUID = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
pub const LAYER_IN_V6: GUID = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

#[derive(Clone, Debug)]
pub enum Cond {
    AppId(Vec<u8>),
    Protocol(u8),
    RemotePort(u16),
    LocalPort(u16),
    Loopback,
    /// Address and mask in host byte order.
    RemoteV4 { addr: u32, mask: u32 },
    RemoteV6 { addr: [u8; 16], prefix: u8 },
    /// Network category of the interface as Windows sees it right now.
    /// Several of these in one filter mean "any of them".
    Profile(u32),
}

#[derive(Clone, Debug)]
pub struct FilterSpec {
    pub name: String,
    pub layer: GUID,
    pub weight: u64,
    pub permit: bool,
    pub conds: Vec<Cond>,
}

fn check(code: u32, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        let msg = windows::core::HRESULT(code as i32).message();
        Err(anyhow!("{what} fehlgeschlagen (0x{code:08X}: {msg})"))
    }
}

pub struct Engine {
    h: HANDLE,
}

// The engine handle may be used from any thread (calls are serialized by BFE).
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    pub fn open() -> Result<Self> {
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.txnWaitTimeoutInMSec = 15_000;
        let name = wide("Briqwall");
        session.displayData.name = PWSTR(name.as_ptr() as *mut _);
        let mut h = HANDLE::default();
        let r = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut h)
        };
        check(r, "FwpmEngineOpen0")?;
        Ok(Self { h })
    }

    /// Create provider and sublayer if they don't exist yet.
    pub fn ensure_objects(&self) -> Result<()> {
        let pname = wide("Briqwall Firewall");
        let pdesc = wide("Anwendungsbasierte Firewall");
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = PROVIDER_KEY;
        provider.displayData.name = PWSTR(pname.as_ptr() as *mut _);
        provider.displayData.description = PWSTR(pdesc.as_ptr() as *mut _);
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        let r = unsafe { FwpmProviderAdd0(self.h, &provider, None) };
        if r != FWP_E_ALREADY_EXISTS.0 as u32 {
            check(r, "FwpmProviderAdd0")?;
        }

        let sname = wide("Briqwall Regeln");
        let mut pkey = PROVIDER_KEY;
        let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sub.subLayerKey = SUBLAYER_KEY;
        sub.displayData.name = PWSTR(sname.as_ptr() as *mut _);
        sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sub.providerKey = &mut pkey;
        sub.weight = 0x8000;
        let r = unsafe { FwpmSubLayerAdd0(self.h, &sub, None) };
        if r != FWP_E_ALREADY_EXISTS.0 as u32 {
            check(r, "FwpmSubLayerAdd0")?;
        }
        Ok(())
    }

    pub fn begin(&self) -> Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.h, 0) }, "FwpmTransactionBegin0")
    }
    pub fn commit(&self) -> Result<()> {
        check(unsafe { FwpmTransactionCommit0(self.h) }, "FwpmTransactionCommit0")
    }
    pub fn abort(&self) {
        unsafe {
            let _ = FwpmTransactionAbort0(self.h);
        }
    }

    /// Run `f` inside a transaction; abort on error.
    pub fn transaction<T>(&self, f: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        self.begin()?;
        match f(self) {
            Ok(v) => {
                self.commit()?;
                Ok(v)
            }
            Err(e) => {
                self.abort();
                Err(e)
            }
        }
    }

    /// Add a filter. If Windows turns it down and it carries a network
    /// profile condition, it is added once more without: the condition only
    /// narrows a permit that was correct at the moment it was compiled, and a
    /// permit that is missing altogether would cut off file sharing at home.
    pub fn add_filter(&self, spec: &FilterSpec) -> Result<u64> {
        match self.add_filter_as_is(spec) {
            Err(e) if spec.conds.iter().any(|c| matches!(c, Cond::Profile(_))) => {
                static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    log::warn!("Filter mit Netzwerkprofil-Bedingung abgelehnt, setze ihn ohne: {e:#}");
                }
                let mut plain = spec.clone();
                plain.conds.retain(|c| !matches!(c, Cond::Profile(_)));
                self.add_filter_as_is(&plain)
            }
            other => other,
        }
    }

    fn add_filter_as_is(&self, spec: &FilterSpec) -> Result<u64> {
        // Everything the condition array points to must outlive FwpmFilterAdd0.
        let mut blobs: Vec<Box<FWP_BYTE_BLOB>> = Vec::new();
        let mut datas: Vec<Vec<u8>> = Vec::new();
        let mut v4s: Vec<Box<FWP_V4_ADDR_AND_MASK>> = Vec::new();
        let mut v6s: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(spec.conds.len());

        for c in &spec.conds {
            let mut fc: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            fc.matchType = FWP_MATCH_EQUAL;
            match c {
                Cond::AppId(bytes) => {
                    let mut data = bytes.clone();
                    let mut blob =
                        Box::new(FWP_BYTE_BLOB { size: data.len() as u32, data: data.as_mut_ptr() });
                    fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    fc.conditionValue.Anonymous.byteBlob = &mut *blob;
                    datas.push(data);
                    blobs.push(blob);
                }
                Cond::Protocol(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    fc.conditionValue.r#type = FWP_UINT8;
                    fc.conditionValue.Anonymous.uint8 = *p;
                }
                Cond::RemotePort(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    fc.conditionValue.r#type = FWP_UINT16;
                    fc.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::LocalPort(p) => {
                    // Also used as ICMP type at the ALE layers.
                    fc.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    fc.conditionValue.r#type = FWP_UINT16;
                    fc.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::Loopback => {
                    fc.fieldKey = FWPM_CONDITION_FLAGS;
                    fc.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    fc.conditionValue.r#type = FWP_UINT32;
                    fc.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
                Cond::Profile(category) => {
                    fc.fieldKey = FWPM_CONDITION_CURRENT_PROFILE_ID;
                    fc.conditionValue.r#type = FWP_UINT32;
                    fc.conditionValue.Anonymous.uint32 = *category;
                }
                Cond::RemoteV4 { addr, mask } => {
                    let mut m = Box::new(FWP_V4_ADDR_AND_MASK { addr: *addr, mask: *mask });
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    fc.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    fc.conditionValue.Anonymous.v4AddrMask = &mut *m;
                    v4s.push(m);
                }
                Cond::RemoteV6 { addr, prefix } => {
                    let mut m =
                        Box::new(FWP_V6_ADDR_AND_MASK { addr: *addr, prefixLength: *prefix });
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    fc.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    fc.conditionValue.Anonymous.v6AddrMask = &mut *m;
                    v6s.push(m);
                }
            }
            conds.push(fc);
        }

        let name = wide(&spec.name);
        let mut weight = spec.weight;
        let mut pkey = PROVIDER_KEY;
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.displayData.name = PWSTR(name.as_ptr() as *mut _);
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        f.providerKey = &mut pkey;
        f.layerKey = spec.layer;
        f.subLayerKey = SUBLAYER_KEY;
        f.weight.r#type = FWP_UINT64;
        f.weight.Anonymous.uint64 = &mut weight;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition =
            if conds.is_empty() { std::ptr::null_mut() } else { conds.as_mut_ptr() };
        f.action.r#type = if spec.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };

        let mut id = 0u64;
        let r = unsafe { FwpmFilterAdd0(self.h, &f, None, Some(&mut id)) };
        drop((blobs, datas, v4s, v6s));
        check(r, &format!("FwpmFilterAdd0 ({})", spec.name))?;
        Ok(id)
    }

    pub fn delete_filter(&self, id: u64) {
        unsafe {
            let _ = FwpmFilterDeleteById0(self.h, id);
        }
    }

    /// Ids of all filters belonging to Briqwall (by provider or sublayer).
    pub fn our_filter_ids(&self) -> Result<Vec<u64>> {
        let mut ids = Vec::new();
        unsafe {
            let mut eh = HANDLE::default();
            check(FwpmFilterCreateEnumHandle0(self.h, None, &mut eh), "FwpmFilterCreateEnumHandle0")?;
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut n = 0u32;
                let r = FwpmFilterEnum0(self.h, eh, 512, &mut entries, &mut n);
                if r != 0 {
                    let _ = FwpmFilterDestroyEnumHandle0(self.h, eh);
                    check(r, "FwpmFilterEnum0")?;
                }
                for i in 0..n as usize {
                    let f = &**entries.add(i);
                    let ours_provider = !f.providerKey.is_null() && *f.providerKey == PROVIDER_KEY;
                    if ours_provider || f.subLayerKey == SUBLAYER_KEY {
                        ids.push(f.filterId);
                    }
                }
                if !entries.is_null() {
                    let mut p = entries as *mut c_void;
                    FwpmFreeMemory0(&mut p);
                }
                if n < 512 {
                    break;
                }
            }
            let _ = FwpmFilterDestroyEnumHandle0(self.h, eh);
        }
        Ok(ids)
    }

    /// Remove all Briqwall filters (call inside a transaction for atomic rebuilds).
    pub fn purge_filters(&self) -> Result<usize> {
        let ids = self.our_filter_ids()?;
        for id in &ids {
            self.delete_filter(*id);
        }
        Ok(ids.len())
    }

    /// Remove every trace of Briqwall from WFP.
    pub fn uninstall(&self) -> Result<()> {
        self.transaction(|e| {
            e.purge_filters()?;
            unsafe {
                let _ = FwpmSubLayerDeleteByKey0(e.h, &SUBLAYER_KEY);
                let _ = FwpmProviderDeleteByKey0(e.h, &PROVIDER_KEY);
            }
            Ok(())
        })
    }

    pub fn enable_net_events(&self) -> Result<()> {
        let mut v: FWP_VALUE0 = unsafe { std::mem::zeroed() };
        v.r#type = FWP_UINT32;
        v.Anonymous.uint32 = 1;
        check(
            unsafe { FwpmEngineSetOption0(self.h, FWPM_ENGINE_COLLECT_NET_EVENTS, &v) },
            "FwpmEngineSetOption0(COLLECT_NET_EVENTS)",
        )
    }

    /// Subscribe to net events. `ctx` must stay valid for the lifetime of the subscription.
    pub fn subscribe(
        &self,
        cb: FWPM_NET_EVENT_CALLBACK0,
        ctx: *const c_void,
    ) -> Result<HANDLE> {
        let mut tmpl: FWPM_NET_EVENT_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        let mut sub: FWPM_NET_EVENT_SUBSCRIPTION0 = unsafe { std::mem::zeroed() };
        sub.enumTemplate = &mut tmpl;
        let mut eh = HANDLE::default();
        check(
            unsafe { FwpmNetEventSubscribe0(self.h, &sub, cb, Some(ctx), &mut eh) },
            "FwpmNetEventSubscribe0",
        )?;
        Ok(eh)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.h);
        }
    }
}

/// WFP app id for a Win32 path (NT device path, lower-case, UTF-16, NUL-terminated).
pub fn app_id_for_path(path: &str) -> Result<Vec<u8>> {
    let w = wide(path);
    unsafe {
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check(FwpmGetAppIdFromFileName0(PCWSTR(w.as_ptr()), &mut blob), "FwpmGetAppIdFromFileName0")?;
        let b = &*blob;
        let v = std::slice::from_raw_parts(b.data, b.size as usize).to_vec();
        let mut p = blob as *mut c_void;
        FwpmFreeMemory0(&mut p);
        Ok(v)
    }
}

/// App id used by WFP for kernel-originated traffic.
pub fn system_app_id() -> Vec<u8> {
    wide("System").iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// Decode an app id blob to a string (device path or pseudo name).
pub fn app_id_to_string(blob: &[u8]) -> String {
    let u16s: Vec<u16> = blob.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    briqwall_common::util::from_wide(&u16s)
}
