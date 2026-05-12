use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::runtime_support;

pub const SHADOW_COPY_CONTEXT: &str = "ClientAccessible";

#[derive(Debug, Clone)]
pub struct ShadowCopy {
    pub id: String,
    pub device_object: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackedShadowCopy {
    pub id: String,
    pub volume: String,
    pub device_object: String,
    pub context: String,
    pub created_at: String,
    pub created_by_pid: u32,
    pub created_by_exe: Option<String>,
}

pub fn shadow_copy_source_root(device_object: &str) -> PathBuf {
    let normalized = device_object.trim_end_matches(['\\', '/']);
    PathBuf::from(format!(r"{normalized}\"))
}

#[cfg(target_os = "windows")]
pub fn create_shadow_copy(volume: &str) -> Result<ShadowCopy> {
    let shadow_copy = platform::create_shadow_copy(volume)?;
    if let Err(track_error) = track_shadow_copy(volume, &shadow_copy) {
        let rollback_result = platform::delete_shadow_copy(&shadow_copy.id);
        return match rollback_result {
            Ok(()) => Err(track_error.context(format!(
                "rollback created shadow copy {} after tracker failure",
                shadow_copy.id
            ))),
            Err(delete_error) => Err(track_error.context(format!(
                "also failed to roll back shadow copy {}: {delete_error:#}",
                shadow_copy.id
            ))),
        };
    }

    append_tracker_log(format!(
        "tracked shadow copy id={} volume={} device_object={}",
        shadow_copy.id, volume, shadow_copy.device_object
    ));
    Ok(shadow_copy)
}

#[cfg(not(target_os = "windows"))]
pub fn create_shadow_copy(_volume: &str) -> Result<ShadowCopy> {
    anyhow::bail!("VSS shadow copy creation is only supported on Windows hosts")
}

#[cfg(target_os = "windows")]
pub fn delete_shadow_copy(shadow_id: &str) -> Result<()> {
    platform::delete_shadow_copy(shadow_id)?;
    if let Err(error) = untrack_shadow_copy(shadow_id) {
        append_tracker_log(format!(
            "deleted shadow copy {} but tracker cleanup failed: {error:#}",
            shadow_id
        ));
    } else {
        append_tracker_log(format!("untracked shadow copy id={shadow_id}"));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn delete_shadow_copy(_shadow_id: &str) -> Result<()> {
    anyhow::bail!("VSS shadow copy deletion is only supported on Windows hosts")
}

pub fn tracked_shadow_copies() -> Result<Vec<TrackedShadowCopy>> {
    load_tracked_shadow_copies_from_path(&runtime_support::shadow_copy_tracker_path())
}

pub fn reconcile_tracked_shadow_copies() -> Result<Vec<TrackedShadowCopy>> {
    let path = runtime_support::shadow_copy_tracker_path();
    let tracked = load_tracked_shadow_copies_from_path(&path)?;
    let mut existing = Vec::with_capacity(tracked.len());
    let mut removed_ids = Vec::new();

    for entry in tracked {
        if shadow_copy_exists(&entry.id)? {
            existing.push(entry);
        } else {
            removed_ids.push(entry.id);
        }
    }

    sort_tracked_shadow_copies(&mut existing);
    if !removed_ids.is_empty() {
        save_tracked_shadow_copies_to_path(&path, &existing)?;
        append_tracker_log(format!(
            "pruned {} stale tracked shadow {}: {}",
            removed_ids.len(),
            if removed_ids.len() == 1 {
                "copy"
            } else {
                "copies"
            },
            removed_ids.join(", ")
        ));
    }

    Ok(existing)
}

#[cfg(target_os = "windows")]
fn shadow_copy_exists(shadow_id: &str) -> Result<bool> {
    platform::shadow_copy_exists(shadow_id)
}

#[cfg(not(target_os = "windows"))]
fn shadow_copy_exists(_shadow_id: &str) -> Result<bool> {
    Ok(false)
}

fn track_shadow_copy(volume: &str, shadow_copy: &ShadowCopy) -> Result<()> {
    let path = runtime_support::shadow_copy_tracker_path();
    let mut tracked = load_tracked_shadow_copies_from_path(&path)?;
    tracked.retain(|entry| entry.id != shadow_copy.id);
    tracked.push(TrackedShadowCopy {
        id: shadow_copy.id.clone(),
        volume: normalize_tracked_volume(volume),
        device_object: shadow_copy.device_object.clone(),
        context: shadow_copy.context.clone(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        created_by_pid: std::process::id(),
        created_by_exe: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
    });
    sort_tracked_shadow_copies(&mut tracked);
    save_tracked_shadow_copies_to_path(&path, &tracked)
}

fn untrack_shadow_copy(shadow_id: &str) -> Result<()> {
    let path = runtime_support::shadow_copy_tracker_path();
    let mut tracked = load_tracked_shadow_copies_from_path(&path)?;
    let original_len = tracked.len();
    tracked.retain(|entry| entry.id != shadow_id);
    if tracked.len() == original_len {
        return Ok(());
    }
    save_tracked_shadow_copies_to_path(&path, &tracked)
}

fn load_tracked_shadow_copies_from_path(path: &Path) -> Result<Vec<TrackedShadowCopy>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let bytes = fs::read(path).with_context(|| format!("read VSS tracker {}", path.display()))?;
    let mut tracked: Vec<TrackedShadowCopy> = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode VSS tracker {}", path.display()))?;
    sort_tracked_shadow_copies(&mut tracked);
    Ok(tracked)
}

fn save_tracked_shadow_copies_to_path(path: &Path, tracked: &[TrackedShadowCopy]) -> Result<()> {
    if tracked.is_empty() {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("remove empty VSS tracker {}", path.display()))?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create VSS tracker directory {}", parent.display()))?;
    }

    let bytes = serde_json::to_vec_pretty(tracked)?;
    fs::write(path, bytes).with_context(|| format!("write VSS tracker {}", path.display()))
}

fn sort_tracked_shadow_copies(tracked: &mut [TrackedShadowCopy]) {
    tracked.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn normalize_tracked_volume(volume: &str) -> String {
    let trimmed = volume.trim().trim_end_matches(['\\', '/']);
    let trimmed = trimmed.strip_prefix(r"\\.\").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    let trimmed = trimmed.trim_end_matches(':');

    let mut characters = trimmed.chars();
    match (characters.next(), characters.next()) {
        (Some(letter), None) if letter.is_ascii_alphabetic() => {
            format!("{}:", letter.to_ascii_uppercase())
        }
        _ => volume.trim().to_string(),
    }
}

fn append_tracker_log(message: String) {
    let _ = runtime_support::append_technical_log("vss-tracker", message);
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::mem::{self, MaybeUninit};
    use std::ptr;
    use std::slice;

    use anyhow::{Context, Result, bail};
    use windows::Win32::Foundation::RPC_E_TOO_LATE;
    use windows::Win32::Storage::Vss::{
        IVssAsync, VSS_CTX_ALL, VSS_CTX_CLIENT_ACCESSIBLE, VSS_E_OBJECT_NOT_FOUND,
        VSS_OBJECT_SNAPSHOT, VSS_OBJECT_TYPE, VSS_SNAPSHOT_PROP,
    };
    use windows::Win32::System::Com::{
        CLSIDFromString, COINIT_MULTITHREADED, CoInitializeEx, CoInitializeSecurity,
        CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        StringFromGUID2,
    };
    use windows::core::{
        BOOL, BSTR, Error as WindowsError, GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface,
        InterfaceType, PCWSTR, Type,
    };

    use super::{SHADOW_COPY_CONTEXT, ShadowCopy};

    #[link(name = "vssapi")]
    unsafe extern "system" {
        fn CreateVssBackupComponentsInternal(pp_backup: *mut *mut c_void) -> HRESULT;
        fn VssFreeSnapshotPropertiesInternal(properties: *mut VSS_SNAPSHOT_PROP);
    }

    #[repr(transparent)]
    #[derive(Clone, PartialEq, Eq)]
    struct IVssBackupComponents(IUnknown);

    impl core::ops::Deref for IVssBackupComponents {
        type Target = IUnknown;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    unsafe impl Interface for IVssBackupComponents {
        type Vtable = IVssBackupComponents_Vtbl;
        const IID: GUID = GUID::from_u128(0x665c1d5fc218414da05d7fef5f9d5c86);
    }

    #[allow(non_snake_case)]
    impl IVssBackupComponents {
        unsafe fn InitializeForBackup(&self, xml: BSTR) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).InitializeForBackup)(
                    windows::core::Interface::as_raw(self),
                    core::mem::transmute(xml),
                )
                .ok()
            }
        }

        unsafe fn SetContext(&self, context: i32) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).SetContext)(
                    windows::core::Interface::as_raw(self),
                    context,
                )
                .ok()
            }
        }

        unsafe fn StartSnapshotSet(&self, snapshot_set_id: *mut GUID) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).StartSnapshotSet)(
                    windows::core::Interface::as_raw(self),
                    snapshot_set_id,
                )
                .ok()
            }
        }

        unsafe fn AddToSnapshotSet(
            &self,
            volume_name: PCWSTR,
            provider_id: GUID,
            snapshot_id: *mut GUID,
        ) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).AddToSnapshotSet)(
                    windows::core::Interface::as_raw(self),
                    volume_name,
                    provider_id,
                    snapshot_id,
                )
                .ok()
            }
        }

        unsafe fn DoSnapshotSet(&self) -> windows::core::Result<IVssAsync> {
            let mut result__ = ptr::null_mut();
            unsafe {
                (windows::core::Interface::vtable(self).DoSnapshotSet)(
                    windows::core::Interface::as_raw(self),
                    &mut result__,
                )
                .and_then(|| <IVssAsync as Type<IVssAsync, InterfaceType>>::from_abi(result__))
            }
        }

        unsafe fn DeleteSnapshots(
            &self,
            source_object_id: GUID,
            source_object_type: VSS_OBJECT_TYPE,
            force_delete: BOOL,
            deleted_snapshots: *mut i32,
            non_deleted_snapshot_id: *mut GUID,
        ) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).DeleteSnapshots)(
                    windows::core::Interface::as_raw(self),
                    source_object_id,
                    source_object_type,
                    force_delete,
                    deleted_snapshots,
                    non_deleted_snapshot_id,
                )
                .ok()
            }
        }

        unsafe fn GetSnapshotProperties(
            &self,
            snapshot_id: GUID,
            properties: *mut VSS_SNAPSHOT_PROP,
        ) -> HRESULT {
            unsafe {
                (windows::core::Interface::vtable(self).GetSnapshotProperties)(
                    windows::core::Interface::as_raw(self),
                    snapshot_id,
                    properties,
                )
            }
        }

        unsafe fn IsVolumeSupported(
            &self,
            provider_id: GUID,
            volume_name: PCWSTR,
            supported: *mut BOOL,
        ) -> windows::core::Result<()> {
            unsafe {
                (windows::core::Interface::vtable(self).IsVolumeSupported)(
                    windows::core::Interface::as_raw(self),
                    provider_id,
                    volume_name,
                    supported,
                )
                .ok()
            }
        }
    }

    #[allow(non_snake_case)]
    #[repr(C)]
    struct IVssBackupComponents_Vtbl {
        base__: IUnknown_Vtbl,
        GetWriterComponentsCount: usize,
        GetWriterComponents: usize,
        InitializeForBackup: unsafe extern "system" fn(*mut c_void, BSTR) -> HRESULT,
        SetBackupState: usize,
        InitializeForRestore: usize,
        SetRestoreState: usize,
        GatherWriterMetadata: usize,
        GetWriterMetadataCount: usize,
        GetWriterMetadata: usize,
        FreeWriterMetadata: usize,
        AddComponent: usize,
        PrepareForBackup: usize,
        AbortBackup: usize,
        GatherWriterStatus: usize,
        GetWriterStatusCount: usize,
        FreeWriterStatus: usize,
        GetWriterStatus: usize,
        SetBackupSucceeded: usize,
        SetBackupOptions: usize,
        SetSelectedForRestore: usize,
        SetRestoreOptions: usize,
        SetAdditionalRestores: usize,
        SetPreviousBackupStamp: usize,
        SaveAsXML: usize,
        BackupComplete: usize,
        AddAlternativeLocationMapping: usize,
        AddRestoreSubcomponent: usize,
        SetFileRestoreStatus: usize,
        AddNewTarget: usize,
        SetRangesFilePath: usize,
        PreRestore: usize,
        PostRestore: usize,
        SetContext: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
        StartSnapshotSet: unsafe extern "system" fn(*mut c_void, *mut GUID) -> HRESULT,
        AddToSnapshotSet:
            unsafe extern "system" fn(*mut c_void, PCWSTR, GUID, *mut GUID) -> HRESULT,
        DoSnapshotSet: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT,
        DeleteSnapshots: unsafe extern "system" fn(
            *mut c_void,
            GUID,
            VSS_OBJECT_TYPE,
            BOOL,
            *mut i32,
            *mut GUID,
        ) -> HRESULT,
        ImportSnapshots: usize,
        BreakSnapshotSet: usize,
        GetSnapshotProperties:
            unsafe extern "system" fn(*mut c_void, GUID, *mut VSS_SNAPSHOT_PROP) -> HRESULT,
        Query: usize,
        IsVolumeSupported:
            unsafe extern "system" fn(*mut c_void, GUID, PCWSTR, *mut BOOL) -> HRESULT,
        DisableWriterClasses: usize,
        EnableWriterClasses: usize,
        DisableWriterInstances: usize,
        ExposeSnapshot: usize,
        RevertToSnapshot: usize,
        QueryRevertStatus: usize,
    }

    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    pub fn create_shadow_copy(volume: &str) -> Result<ShadowCopy> {
        let volume_root = volume_root_path(volume)?;
        let _com = initialize_com()?;
        let requestor = create_requestor(VSS_CTX_CLIENT_ACCESSIBLE.0)?;

        ensure_volume_supported(&requestor, &volume_root)?;

        let mut snapshot_set_id = null_guid();
        unsafe { requestor.StartSnapshotSet(&mut snapshot_set_id) }
            .context("start VSS snapshot set")?;

        let mut snapshot_id = null_guid();
        let volume_name = wide_string(&volume_root);
        unsafe {
            requestor.AddToSnapshotSet(
                PCWSTR(volume_name.as_ptr()),
                null_guid(),
                &mut snapshot_id,
            )
        }
        .with_context(|| format!("add volume {volume_root} to VSS snapshot set"))?;

        do_snapshot_set(&requestor)?;

        match read_shadow_copy(&requestor, snapshot_id)? {
            Some(shadow_copy) => Ok(shadow_copy),
            None => {
                let snapshot_id = guid_to_string(&snapshot_id)?;
                bail!(
                    "VSS snapshot {snapshot_id} was created but its properties are no longer available"
                );
            }
        }
    }

    pub fn delete_shadow_copy(shadow_id: &str) -> Result<()> {
        let snapshot_id = parse_guid(shadow_id)?;
        let _com = initialize_com()?;
        let requestor = create_requestor(VSS_CTX_ALL.0)?;
        let mut deleted_snapshots = 0;
        let mut non_deleted_snapshot_id = null_guid();

        unsafe {
            requestor.DeleteSnapshots(
                snapshot_id,
                VSS_OBJECT_SNAPSHOT,
                BOOL(1),
                &mut deleted_snapshots,
                &mut non_deleted_snapshot_id,
            )
        }
        .with_context(|| format!("delete shadow copy {shadow_id}"))?;

        if deleted_snapshots <= 0 {
            bail!("VSS did not delete shadow copy {shadow_id}");
        }

        Ok(())
    }

    pub fn shadow_copy_exists(shadow_id: &str) -> Result<bool> {
        let snapshot_id = parse_guid(shadow_id)?;
        let _com = initialize_com()?;
        let requestor = create_requestor(VSS_CTX_ALL.0)?;
        snapshot_exists(&requestor, snapshot_id)
    }

    fn initialize_com() -> Result<ComApartment> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .context("initialize COM for VSS")?;
        match unsafe {
            CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            )
        } {
            Ok(()) => {}
            Err(error) if error.code() == RPC_E_TOO_LATE => {}
            Err(error) => return Err(error).context("initialize COM security for VSS"),
        }
        Ok(ComApartment)
    }

    fn create_requestor(context: i32) -> Result<IVssBackupComponents> {
        let requestor = unsafe { create_vss_backup_components() }
            .context("create VSS backup components")?;

        unsafe { requestor.InitializeForBackup(BSTR::default()) }
            .context("initialize VSS backup components")?;
        unsafe { requestor.SetContext(context) }.context("set VSS snapshot context")?;

        Ok(requestor)
    }

    fn ensure_volume_supported(
        requestor: &IVssBackupComponents,
        volume_root: &str,
    ) -> Result<()> {
        let mut supported = BOOL(0);
        let volume_name = wide_string(volume_root);
        unsafe { requestor.IsVolumeSupported(null_guid(), PCWSTR(volume_name.as_ptr()), &mut supported) }
            .with_context(|| format!("check VSS support for {volume_root}"))?;

        if supported.0 == 0 {
            bail!("VSS does not support creating a shadow copy for {volume_root}");
        }

        Ok(())
    }

    fn do_snapshot_set(requestor: &IVssBackupComponents) -> Result<()> {
        let async_operation = unsafe { requestor.DoSnapshotSet() }
            .context("commit VSS snapshot set")?;
        wait_for_async(&async_operation, "commit VSS snapshot set")
    }

    fn wait_for_async(async_operation: &IVssAsync, action: &str) -> Result<()> {
        unsafe { async_operation.Wait(u32::MAX) }
            .with_context(|| format!("wait for {action}"))?;

        let mut operation_result = HRESULT(0);
        let mut reserved = 0;
        unsafe { async_operation.QueryStatus(&mut operation_result, &mut reserved) }
            .with_context(|| format!("query VSS async status for {action}"))?;
        check_hresult(operation_result, action)
    }

    fn read_shadow_copy(
        requestor: &IVssBackupComponents,
        snapshot_id: GUID,
    ) -> Result<Option<ShadowCopy>> {
        let mut properties = MaybeUninit::<VSS_SNAPSHOT_PROP>::zeroed();
        let status = unsafe { requestor.GetSnapshotProperties(snapshot_id, properties.as_mut_ptr()) };

        if status == VSS_E_OBJECT_NOT_FOUND {
            return Ok(None);
        }

        check_hresult(
            status,
            format!(
                "read VSS snapshot properties for {}",
                guid_to_string(&snapshot_id)?
            ),
        )?;

        let mut properties = unsafe { properties.assume_init() };
        let result = shadow_copy_from_properties(&properties);
        unsafe {
            VssFreeSnapshotPropertiesInternal(&mut properties);
        }
        result.map(Some)
    }

    fn snapshot_exists(requestor: &IVssBackupComponents, snapshot_id: GUID) -> Result<bool> {
        let mut properties = MaybeUninit::<VSS_SNAPSHOT_PROP>::zeroed();
        let status = unsafe { requestor.GetSnapshotProperties(snapshot_id, properties.as_mut_ptr()) };

        if status == VSS_E_OBJECT_NOT_FOUND {
            return Ok(false);
        }

        check_hresult(
            status,
            format!(
                "read VSS snapshot properties for {}",
                guid_to_string(&snapshot_id)?
            ),
        )?;

        let mut properties = unsafe { properties.assume_init() };
        unsafe {
            VssFreeSnapshotPropertiesInternal(&mut properties);
        }
        Ok(true)
    }

    fn shadow_copy_from_properties(properties: &VSS_SNAPSHOT_PROP) -> Result<ShadowCopy> {
        let id = guid_to_string(&properties.m_SnapshotId)?;
        let device_object = wide_ptr_to_string(properties.m_pwszSnapshotDeviceObject);
        if device_object.trim().is_empty() {
            bail!("VSS snapshot {id} did not provide a device object");
        }

        Ok(ShadowCopy {
            id,
            device_object,
            context: SHADOW_COPY_CONTEXT.to_string(),
        })
    }

    fn parse_guid(value: &str) -> Result<GUID> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("shadow copy id is empty");
        }

        let canonical = if trimmed.starts_with('{') {
            trimmed.to_string()
        } else {
            format!("{{{trimmed}}}")
        };
        let wide = wide_string(&canonical);
        let guid = unsafe { CLSIDFromString(PCWSTR(wide.as_ptr())) }
            .with_context(|| format!("parse shadow copy id {trimmed}"))?;

        Ok(guid)
    }

    fn guid_to_string(guid: &GUID) -> Result<String> {
        let guid = unsafe { mem::transmute_copy(guid) };
        let mut buffer = [0u16; 39];
        let written = unsafe { StringFromGUID2(&guid, &mut buffer) };
        if written <= 1 {
            bail!("format VSS snapshot id as a GUID string");
        }

        Ok(String::from_utf16_lossy(&buffer[..written as usize - 1]))
    }

    fn wide_string(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn wide_ptr_to_string(value: *const u16) -> String {
        if value.is_null() {
            return String::new();
        }

        unsafe {
            let mut length = 0usize;
            while *value.add(length) != 0 {
                length += 1;
            }

            String::from_utf16_lossy(slice::from_raw_parts(value, length))
        }
    }

    fn null_guid() -> GUID {
        unsafe { mem::zeroed() }
    }

    fn check_hresult(status: HRESULT, action: impl Into<String>) -> Result<()> {
        if status.0 < 0 {
            let action = action.into();
            return Err(WindowsError::from(status)).with_context(|| action);
        }

        Ok(())
    }

    unsafe fn create_vss_backup_components() -> windows::core::Result<IVssBackupComponents> {
        let mut requestor = ptr::null_mut();
        let status = unsafe { CreateVssBackupComponentsInternal(&mut requestor) };
        if status.0 < 0 {
            return Err(WindowsError::from(status));
        }

        unsafe { <IVssBackupComponents as Type<IVssBackupComponents, InterfaceType>>::from_abi(requestor) }
    }

    fn volume_root_path(volume: &str) -> Result<String> {
        Ok(format!("{}\\", normalize_volume(volume)?))
    }

    fn normalize_volume(value: &str) -> Result<String> {
        let trimmed = value.trim().trim_end_matches(['\\', '/']);
        let trimmed = trimmed.strip_prefix(r"\\.\").unwrap_or(trimmed);
        let trimmed = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
        let trimmed = trimmed.trim_end_matches(':');

        let mut characters = trimmed.chars();
        let Some(letter) = characters.next() else {
            bail!("volume must contain a drive letter, for example C:");
        };
        if characters.next().is_some() || !letter.is_ascii_alphabetic() {
            bail!("volume must be a single drive letter, for example C:");
        }

        Ok(format!("{}:", letter.to_ascii_uppercase()))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        TrackedShadowCopy, load_tracked_shadow_copies_from_path, normalize_tracked_volume,
        save_tracked_shadow_copies_to_path,
    };

    #[test]
    fn tracked_shadow_copy_file_round_trips_in_created_order() -> Result<()> {
        let temp = tempdir()?;
        let tracker_path = temp.path().join("vss-shadow-copies.json");
        let entries = vec![
            sample_tracked_shadow_copy("older", "2026-05-11T22:15:00Z"),
            sample_tracked_shadow_copy("newer", "2026-05-11T22:16:00Z"),
        ];

        save_tracked_shadow_copies_to_path(&tracker_path, &entries)?;
        let loaded = load_tracked_shadow_copies_from_path(&tracker_path)?;

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "newer");
        assert_eq!(loaded[1].id, "older");
        Ok(())
    }

    #[test]
    fn saving_empty_tracker_removes_tracker_file() -> Result<()> {
        let temp = tempdir()?;
        let tracker_path = temp.path().join("vss-shadow-copies.json");

        save_tracked_shadow_copies_to_path(
            &tracker_path,
            &[sample_tracked_shadow_copy("one", "2026-05-11T22:16:00Z")],
        )?;
        assert!(tracker_path.exists());

        save_tracked_shadow_copies_to_path(&tracker_path, &[])?;
        assert!(!tracker_path.exists());
        Ok(())
    }

    #[test]
    fn normalize_tracked_volume_keeps_drive_letter_shape() {
        assert_eq!(normalize_tracked_volume("c"), "C:");
        assert_eq!(normalize_tracked_volume(r"\\.\e:"), "E:");
        assert_eq!(normalize_tracked_volume("Volume{shadow}"), "Volume{shadow}");
    }

    fn sample_tracked_shadow_copy(id: &str, created_at: &str) -> TrackedShadowCopy {
        TrackedShadowCopy {
            id: id.to_string(),
            volume: "C:".to_string(),
            device_object: format!(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{id}"),
            context: "ClientAccessible".to_string(),
            created_at: created_at.to_string(),
            created_by_pid: 4242,
            created_by_exe: Some(r"C:\Tools\holo-forensics.exe".to_string()),
        }
    }
}