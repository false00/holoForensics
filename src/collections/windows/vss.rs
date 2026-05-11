use std::path::PathBuf;

use anyhow::Result;

pub const SHADOW_COPY_CONTEXT: &str = "ClientAccessible";

#[derive(Debug, Clone)]
pub struct ShadowCopy {
    pub id: String,
    pub device_object: String,
    pub context: String,
}

pub fn shadow_copy_source_root(device_object: &str) -> PathBuf {
    let normalized = device_object.trim_end_matches(['\\', '/']);
    PathBuf::from(format!(r"{normalized}\"))
}

#[cfg(target_os = "windows")]
pub fn create_shadow_copy(volume: &str) -> Result<ShadowCopy> {
    platform::create_shadow_copy(volume)
}

#[cfg(not(target_os = "windows"))]
pub fn create_shadow_copy(_volume: &str) -> Result<ShadowCopy> {
    anyhow::bail!("VSS shadow copy creation is only supported on Windows hosts")
}

#[cfg(target_os = "windows")]
pub fn delete_shadow_copy(shadow_id: &str) -> Result<()> {
    platform::delete_shadow_copy(shadow_id)
}

#[cfg(not(target_os = "windows"))]
pub fn delete_shadow_copy(_shadow_id: &str) -> Result<()> {
    anyhow::bail!("VSS shadow copy deletion is only supported on Windows hosts")
}

#[cfg(target_os = "windows")]
mod platform {
    use anyhow::{Context, Result, anyhow, bail};
    use windows::Win32::Foundation::RPC_E_TOO_LATE;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Wmi::{IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator};
    use windows::core::{BSTR, PCWSTR, VARIANT, w};

    use super::{SHADOW_COPY_CONTEXT, ShadowCopy};

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
        let _com = initialize_wmi()?;
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .context("create WMI locator")?;
        let services = connect_wmi_services(&locator)?;

        let class_object = get_wmi_object(&services, "Win32_ShadowCopy")?;
        let mut input_signature = None;
        unsafe {
            class_object.GetMethod(w!("Create"), 0, &mut input_signature, std::ptr::null_mut())
        }
        .context("read Win32_ShadowCopy.Create signature")?;
        let input_signature = input_signature
            .ok_or_else(|| anyhow!("Win32_ShadowCopy.Create did not expose an input signature"))?;
        let input_instance = unsafe { input_signature.SpawnInstance(0) }
            .context("spawn Win32_ShadowCopy.Create input instance")?;

        let volume_variant = VARIANT::from(volume_root.as_str());
        unsafe { input_instance.Put(w!("Volume"), 0, &volume_variant, 0) }
            .context("set Win32_ShadowCopy.Create Volume argument")?;
        let context_variant = VARIANT::from(SHADOW_COPY_CONTEXT);
        unsafe { input_instance.Put(w!("Context"), 0, &context_variant, 0) }
            .context("set Win32_ShadowCopy.Create Context argument")?;

        let mut output_params = None;
        let class_path = BSTR::from("Win32_ShadowCopy");
        let method_name = BSTR::from("Create");
        unsafe {
            services.ExecMethod(
                &class_path,
                &method_name,
                windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE(0),
                None,
                &input_instance,
                Some(&mut output_params),
                None,
            )
        }
        .context("invoke Win32_ShadowCopy.Create")?;
        let output_params = output_params
            .ok_or_else(|| anyhow!("Win32_ShadowCopy.Create returned no output parameters"))?;

        let return_value = wmi_i32_property(&output_params, w!("ReturnValue"))
            .context("read Win32_ShadowCopy.Create ReturnValue")?;
        if return_value != 0 {
            bail!("Win32_ShadowCopy.Create returned {}", return_value);
        }

        let shadow_id = wmi_string_property(&output_params, w!("ShadowID"))
            .context("read Win32_ShadowCopy.Create ShadowID")?;
        if shadow_id.trim().is_empty() {
            bail!("Win32_ShadowCopy.Create returned an empty shadow copy id");
        }

        let instance_path = BSTR::from(format!(r#"Win32_ShadowCopy.ID="{}""#, shadow_id));
        let shadow_object = get_wmi_object(&services, &instance_path.to_string())?;
        let device_object = wmi_string_property(&shadow_object, w!("DeviceObject"))
            .context("read shadow copy device object")?;
        if device_object.trim().is_empty() {
            bail!("Win32_ShadowCopy.Create returned an empty shadow copy device object");
        }

        Ok(ShadowCopy {
            id: shadow_id,
            device_object,
            context: SHADOW_COPY_CONTEXT.to_string(),
        })
    }

    pub fn delete_shadow_copy(shadow_id: &str) -> Result<()> {
        let _com = initialize_wmi()?;
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .context("create WMI locator")?;
        let services = connect_wmi_services(&locator)?;
        let object_path = BSTR::from(format!(r#"Win32_ShadowCopy.ID="{}""#, shadow_id));
        unsafe {
            services.DeleteInstance(
                &object_path,
                windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE(0),
                None,
                None,
            )
        }
        .with_context(|| format!("delete shadow copy {}", shadow_id))
    }

    fn initialize_wmi() -> Result<ComApartment> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .context("initialize COM for WMI")?;
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
            Err(error) => return Err(error).context("initialize COM security for WMI"),
        }
        Ok(ComApartment)
    }

    fn connect_wmi_services(locator: &IWbemLocator) -> Result<IWbemServices> {
        let namespace = BSTR::from("ROOT\\CIMV2");
        let empty = BSTR::from("");
        let services =
            unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
                .context("connect WMI namespace ROOT\\CIMV2")?;

        unsafe {
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
        }
        .context("configure WMI proxy security")?;
        Ok(services)
    }

    fn get_wmi_object(services: &IWbemServices, object_path: &str) -> Result<IWbemClassObject> {
        let mut object = None;
        let object_path = BSTR::from(object_path);
        unsafe {
            services.GetObject(
                &object_path,
                windows::Win32::System::Wmi::WBEM_GENERIC_FLAG_TYPE(0),
                None,
                Some(&mut object),
                None,
            )
        }
        .with_context(|| format!("get WMI object {object_path}"))?;
        object.ok_or_else(|| anyhow!("WMI object {object_path} was not returned"))
    }

    fn wmi_string_property(object: &IWbemClassObject, property_name: PCWSTR) -> Result<String> {
        let mut value = VARIANT::default();
        unsafe { object.Get(property_name, 0, &mut value, None, None) }
            .context("read WMI string property")?;
        Ok(BSTR::try_from(&value)
            .map(|value| value.to_string())
            .unwrap_or_default())
    }

    fn wmi_i32_property(object: &IWbemClassObject, property_name: PCWSTR) -> Result<i32> {
        let mut value = VARIANT::default();
        unsafe { object.Get(property_name, 0, &mut value, None, None) }
            .context("read WMI integer property")?;
        i32::try_from(&value).map_err(|error| anyhow!(error))
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
