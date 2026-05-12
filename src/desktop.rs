use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::mem::size_of_val;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize};
use slint::fontique_08::fontique;
use slint::{ComponentHandle, VecModel};

use crate::app::{self, ParseCli, ParseEvent, ParseRunOptions};
use crate::collection_catalog;
use crate::collections::windows::{indx, logfile, mft, registry, usn_journal, vss};
use crate::runtime_support;

#[cfg(windows)]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::{E_ABORT, ERROR_SUCCESS, HWND},
        Graphics::Dwm::{
            DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
            DwmSetWindowAttribute,
        },
        Storage::FileSystem::GetVolumeInformationW,
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoTaskMemFree, CoUninitialize,
        },
        System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW},
        UI::Shell::{
            FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_PATHMUSTEXIST, FOS_PICKFOLDERS,
            FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName,
            SIGDN_FILESYSPATH, ShellExecuteW,
        },
        UI::WindowsAndMessaging::{
            MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TASKMODAL, MessageBoxW, SW_SHOWNORMAL,
        },
    },
    core::{BOOL, Error as WindowsError, HSTRING, PCWSTR, w},
};

slint::include_modules!();

const FIGTREE_REGULAR: &[u8] = include_bytes!("../assets/fonts/Figtree-Regular.ttf");
const FIGTREE_MEDIUM: &[u8] = include_bytes!("../assets/fonts/Figtree-Medium.ttf");
const TOMORROW_THIN: &[u8] = include_bytes!("../assets/fonts/Tomorrow-Thin.ttf");
const TOMORROW_LIGHT: &[u8] = include_bytes!("../assets/fonts/Tomorrow-Light.ttf");
const TOMORROW_REGULAR: &[u8] = include_bytes!("../assets/fonts/Tomorrow-Regular.ttf");
const MAX_LOG_LINES: usize = 80;
const TRIAGE_COLLECTION_TITLES: &[&str] = &[
    "Windows Event Logs",
    "Registry Hives",
    "$MFT",
    "$LogFile",
    "INDX Records",
    "SRUM",
    "LNK Files",
    "Jump Lists",
    "Prefetch",
    "$UsnJrnl",
    "Browser Artifacts",
    "Scheduled Tasks",
    "USB and External Devices",
];
const DEFAULT_COLLECTION_USN_CHUNK_INDEX: i32 = 1;
const FALSE00_REPOSITORY_URL: &str = "https://github.com/false00/holoForensics";

#[derive(Debug, Clone, Copy, Default)]
pub struct DesktopLaunchOptions {
    pub screenshot_state: Option<DesktopScreenshotState>,
    pub theme_override: Option<DesktopThemeOverride>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopScreenshotState {
    Main,
    About,
    Settings,
    Scope,
    UsnSettings,
    CollectionProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopThemeOverride {
    Auto,
    Dark,
    Light,
}

impl DesktopThemeOverride {
    fn to_theme_mode(self) -> i32 {
        match self {
            Self::Auto => 0,
            Self::Dark => 1,
            Self::Light => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopSettings {
    theme_mode: i32,
    collection_profile: i32,
    #[serde(
        default = "default_collection_volumes",
        alias = "collection_volume",
        deserialize_with = "deserialize_collection_volumes"
    )]
    collection_volumes: Vec<String>,
    collection_archive_path: String,
    collection_usn_mode: i32,
    #[serde(default = "default_collection_usn_chunk_index")]
    collection_usn_chunk_index: i32,
    collection_sparse: bool,
    #[serde(default = "default_collection_elevate")]
    collection_elevate: bool,
    custom_usn_selected: bool,
    parse_archive_path: String,
    parse_output_path: String,
    use_elasticsearch: bool,
    elasticsearch_url: String,
    elasticsearch_username: String,
    elasticsearch_index: String,
    elasticsearch_insecure: bool,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            theme_mode: 0,
            collection_profile: 0,
            collection_volumes: default_collection_volumes(),
            collection_archive_path: String::new(),
            collection_usn_mode: 2,
            collection_usn_chunk_index: default_collection_usn_chunk_index(),
            collection_sparse: false,
            collection_elevate: default_collection_elevate(),
            custom_usn_selected: true,
            parse_archive_path: String::new(),
            parse_output_path: String::new(),
            use_elasticsearch: false,
            elasticsearch_url: String::new(),
            elasticsearch_username: String::new(),
            elasticsearch_index: String::new(),
            elasticsearch_insecure: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum CollectionVolumesSetting {
    One(String),
    Many(Vec<String>),
}

fn deserialize_collection_volumes<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<CollectionVolumesSetting>::deserialize(deserializer)?;
    Ok(match value {
        Some(CollectionVolumesSetting::One(value)) => vec![value],
        Some(CollectionVolumesSetting::Many(values)) => values,
        None => default_collection_volumes(),
    })
}

#[derive(Debug, Clone)]
struct DetectedPlanRecord {
    id: String,
    title: String,
    subtitle: String,
    detail: String,
    selected: bool,
}

impl DetectedPlanRecord {
    fn from_backend(plan: app::DetectedPlan) -> Self {
        Self {
            id: plan.id,
            title: plan.artifact,
            subtitle: plan.parser,
            detail: collection_label(&plan.collection),
            selected: true,
        }
    }

    fn to_ui_item(&self) -> ParseArtifactItem {
        ParseArtifactItem {
            id: self.id.clone().into(),
            title: self.title.clone().into(),
            subtitle: self.subtitle.clone().into(),
            detail: self.detail.clone().into(),
            selected: self.selected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectionDriveRecord {
    volume: String,
    filesystem: String,
}

impl CollectionDriveRecord {
    fn to_ui_item(&self, selected_volumes: &[String]) -> DriveItem {
        DriveItem {
            volume: self.volume.clone().into(),
            filesystem: self.filesystem.clone().into(),
            selected: selected_volumes.iter().any(|volume| volume == &self.volume),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectionSourceState {
    supported_volumes: Vec<String>,
    unsupported_volumes: Vec<String>,
    summary: String,
}

impl CollectionSourceState {
    fn supported(&self) -> bool {
        !self.supported_volumes.is_empty()
    }
}

#[derive(Debug, Clone)]
struct CollectionCatalogRecord {
    title: String,
    category: String,
    status: String,
    summary: String,
    targets: String,
    note: String,
    live: bool,
    configurable: bool,
    selected: bool,
}

impl CollectionCatalogRecord {
    fn new(
        title: &str,
        category: &str,
        status: &str,
        summary: &str,
        targets: &str,
        note: &str,
        live: bool,
    ) -> Self {
        Self {
            title: title.to_string(),
            category: category.to_string(),
            status: status.to_string(),
            summary: summary.to_string(),
            targets: targets.to_string(),
            note: note.to_string(),
            live,
            configurable: false,
            selected: false,
        }
    }

    fn with_configurable(mut self, configurable: bool) -> Self {
        self.configurable = configurable;
        self
    }

    fn to_ui_item(&self) -> CollectionSurfaceItem {
        CollectionSurfaceItem {
            title: self.title.clone().into(),
            category: self.category.clone().into(),
            status: self.status.clone().into(),
            summary: self.summary.clone().into(),
            targets: self.targets.clone().into(),
            selected: self.selected,
            live: self.live,
            configurable: self.configurable,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CollectionRuntimePhase {
    #[default]
    Idle,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
enum CollectionActivityTone {
    ScopeOnly = 0,
    Ready = 1,
    Queued = 2,
    Running = 3,
    Complete = 4,
    Failed = 5,
}

#[derive(Debug, Clone)]
struct CollectionActivityRecord {
    title: String,
    category: String,
    detail: String,
    status: String,
    tone: CollectionActivityTone,
    active: bool,
    show_progress: bool,
    progress_value: f32,
    progress_text: String,
    package_pending: bool,
}

#[derive(Debug, Clone)]
struct CollectionActivityDetailRecord {
    name: String,
    state: String,
    detail: String,
}

impl CollectionActivityDetailRecord {
    fn to_ui_item(&self) -> CollectionActivityDetailItem {
        CollectionActivityDetailItem {
            name: self.name.clone().into(),
            state: self.state.clone().into(),
            detail: self.detail.clone().into(),
        }
    }
}

impl CollectionActivityRecord {
    fn to_ui_item(&self) -> CollectionActivityItem {
        CollectionActivityItem {
            title: self.title.clone().into(),
            category: self.category.clone().into(),
            detail: self.detail.clone().into(),
            status: self.status.clone().into(),
            tone: self.tone as i32,
            active: self.active,
            show_progress: self.show_progress,
            progress_value: self.progress_value,
            progress_text: self.progress_text.clone().into(),
            package_pending: self.package_pending,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CollectionCollectorProgress {
    current_volume: Option<String>,
    current_job_progress: f32,
    detail: String,
    progress_text: String,
    completed_jobs: usize,
    staged_paths: usize,
    artifact_paths: Vec<String>,
    started: bool,
    active: bool,
}

#[derive(Debug, Clone, Default)]
struct CollectionProgressState {
    runtime_jobs: usize,
    completed_jobs: usize,
    current_collector: Option<String>,
    packaging_started: bool,
    packaging_entry_count: usize,
    completed: bool,
    output_zip: Option<PathBuf>,
    collectors: BTreeMap<String, CollectionCollectorProgress>,
}

#[derive(Debug)]
struct DesktopState {
    project_root: PathBuf,
    settings_path: PathBuf,
    collection_catalog: Vec<CollectionCatalogRecord>,
    collection_runtime_phase: CollectionRuntimePhase,
    collection_progress: Option<CollectionProgressState>,
    selected_collection_activity_title: Option<String>,
    detected_plans: Vec<DetectedPlanRecord>,
    selected_collection_volumes: Vec<String>,
    tracked_shadow_copies: Vec<vss::TrackedShadowCopy>,
}

impl DesktopState {
    fn new(project_root: PathBuf, settings_path: PathBuf) -> Self {
        Self {
            project_root,
            settings_path,
            collection_catalog: build_collection_catalog_records(),
            collection_runtime_phase: CollectionRuntimePhase::Idle,
            collection_progress: None,
            selected_collection_activity_title: None,
            detected_plans: Vec::new(),
            selected_collection_volumes: default_collection_volumes(),
            tracked_shadow_copies: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct ProgressTracker {
    started_at: Instant,
    total_plans: usize,
    completed_plans: usize,
}

impl ProgressTracker {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            total_plans: 0,
            completed_plans: 0,
        }
    }

    fn observe(&mut self, event: &ParseEvent) {
        match event {
            ParseEvent::PlansResolved { total_plans, .. } => {
                self.total_plans = *total_plans;
                self.completed_plans = 0;
            }
            ParseEvent::PlanFinished { .. } => {
                self.completed_plans += 1;
            }
            ParseEvent::Completed { total_entries, .. } => {
                if self.total_plans == 0 {
                    self.total_plans = *total_entries;
                }
                self.completed_plans = self.total_plans.max(self.completed_plans);
            }
            _ => {}
        }
    }

    fn progress_value(&self) -> f32 {
        if self.total_plans == 0 {
            0.0
        } else {
            (self.completed_plans as f32 / self.total_plans as f32).clamp(0.0, 1.0)
        }
    }

    fn summary(&self) -> String {
        format!(
            "{} | {} | {}",
            format_elapsed(self.started_at.elapsed()),
            format_remaining(
                self.started_at.elapsed(),
                self.completed_plans,
                self.total_plans
            ),
            format_rate(self.started_at.elapsed(), self.completed_plans)
        )
    }
}

#[derive(Debug, Clone)]
struct ParseExecutionRequest {
    input: PathBuf,
    output: Option<PathBuf>,
    selected_plan_ids: BTreeSet<String>,
    opensearch_url: Option<String>,
    opensearch_username: Option<String>,
    opensearch_password: Option<String>,
    opensearch_index: Option<String>,
    opensearch_insecure: bool,
}

#[derive(Debug, Clone)]
struct CollectionExecutionRequest {
    volumes: Vec<String>,
    skipped_volumes: Vec<String>,
    output_zip: PathBuf,
    collect_usn: bool,
    collect_registry: bool,
    collect_evtx: bool,
    collect_srum: bool,
    collect_prefetch: bool,
    collect_browser_artifacts: bool,
    collect_jump_lists: bool,
    collect_lnk: bool,
    collect_mft: bool,
    collect_logfile: bool,
    collect_indx: bool,
    mode: usn_journal::UsnDumpMode,
    sparse: bool,
    chunk_size_mib: usize,
    elevate: bool,
}

fn default_collection_volumes() -> Vec<String> {
    vec!["C:".to_string()]
}

fn default_collection_usn_chunk_index() -> i32 {
    DEFAULT_COLLECTION_USN_CHUNK_INDEX
}

fn default_collection_elevate() -> bool {
    true
}

pub fn launch() -> Result<()> {
    launch_with_options(DesktopLaunchOptions::default())
}

pub fn launch_with_options(options: DesktopLaunchOptions) -> Result<()> {
    let result = guard_desktop_action("Launch desktop UI", || try_launch_with_options(options));
    if let Err(error) = &result {
        report_startup_failure(error);
    }
    result
}

fn try_launch_with_options(options: DesktopLaunchOptions) -> Result<()> {
    let app = AppWindow::new()?;
    register_embedded_fonts();

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let settings_path = resolve_settings_path();
    let settings = load_settings(&settings_path).unwrap_or_default();
    let state = Arc::new(Mutex::new(DesktopState::new(
        project_root.clone(),
        settings_path,
    )));

    initialize_app(&app, &state, &settings, options)?;
    app.run()?;
    Ok(())
}

pub fn validate_offline_parse(input: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = app::run_parse_request(
        ParseCli {
            input: Some(input),
            output,
            opensearch_url: None,
            opensearch_username: None,
            opensearch_password: None,
            opensearch_index: None,
            opensearch_insecure: false,
        },
        ParseRunOptions {
            project_root: Some(project_root),
            selected_plan_ids: None,
        },
        |_| {},
    )?;

    println!(
        "Validated desktop parse workflow. Manifest: {}",
        summary.manifest_path.display()
    );
    Ok(())
}

fn report_startup_failure(error: &anyhow::Error) {
    let title = "Holo Forensics could not start";
    let summary = error_summary(error);
    let detail = format_error_details(error);
    let log_path = runtime_support::technical_log_path();
    let log_hint = match runtime_support::append_technical_log(
        "desktop-startup",
        format!("{title}\n{detail}").as_str(),
    ) {
        Ok(()) => Some(display_path(&log_path)),
        Err(log_error) => Some(format!("Technical log unavailable: {log_error}")),
    };

    show_startup_error_dialog(
        title,
        &build_startup_error_dialog_body(&summary, &detail, log_hint.as_deref()),
    );
}

fn build_startup_error_dialog_body(summary: &str, detail: &str, log_hint: Option<&str>) -> String {
    let mut body = summary.trim().to_string();
    if body.is_empty() {
        body = "The desktop UI failed during startup.".to_string();
    }

    if detail.trim() != body {
        body.push_str("\n\nDetails:\n");
        body.push_str(detail.trim());
    }

    if let Some(log_hint) = log_hint.filter(|value| !value.trim().is_empty()) {
        body.push_str("\n\n");
        body.push_str(log_hint);
    }

    body
}

#[cfg(windows)]
fn show_startup_error_dialog(title: &str, body: &str) {
    let title = HSTRING::from(title);
    let body = HSTRING::from(body);

    unsafe {
        let _ = MessageBoxW(
            None,
            &body,
            &title,
            MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(windows))]
fn show_startup_error_dialog(_title: &str, _body: &str) {}

fn initialize_app(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    settings: &DesktopSettings,
    options: DesktopLaunchOptions,
) -> Result<()> {
    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };

    let theme = app.global::<ThemeTokens>();
    theme.set_system_dark(detect_system_dark());
    theme.set_theme_mode(
        options
            .theme_override
            .map(DesktopThemeOverride::to_theme_mode)
            .unwrap_or_else(|| settings.theme_mode.clamp(0, 2)),
    );

    let drives = available_collection_drives();
    let collection_volumes =
        normalized_selected_volumes_or_default(&settings.collection_volumes, &drives);
    let collection_output_dir = normalize_collection_output_dir(
        &settings.collection_archive_path,
        &default_collection_output_dir(&project_root),
    );
    let collection_elevate = default_collection_elevate();
    let parse_output_path = if settings.parse_output_path.trim().is_empty() {
        display_path(&default_parse_output_path(&project_root))
    } else {
        settings.parse_output_path.clone()
    };

    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        state_guard.selected_collection_volumes = collection_volumes;
    }

    app.set_collection_profile(settings.collection_profile.clamp(0, 2));
    app.set_app_version(env!("CARGO_PKG_VERSION").into());
    app.set_collection_archive_path(display_path(&collection_output_dir).into());
    refresh_collection_output_filename(app);
    app.set_collection_usn_mode(settings.collection_usn_mode.clamp(0, 2));
    app.set_collection_usn_chunk_index(settings.collection_usn_chunk_index.clamp(0, 4));
    app.set_collection_sparse(settings.collection_sparse);
    app.set_collection_elevate(collection_elevate);
    app.set_custom_usn_selected(settings.custom_usn_selected);
    app.set_shadow_copy_recovery_open(false);
    app.set_shadow_copy_recovery_summary("".into());
    app.set_shadow_copy_recovery_items(
        Rc::new(VecModel::from(Vec::<ShadowCopyRecoveryItem>::new())).into(),
    );
    app.set_error_dialog_open(false);
    app.set_error_dialog_title("".into());
    app.set_error_dialog_summary("".into());
    app.set_error_dialog_detail("".into());
    app.set_error_dialog_log_path(display_path(&runtime_support::technical_log_path()).into());
    app.set_collection_status("Ready to create an evidence package.".into());
    app.set_collection_activity_summary("".into());

    app.set_parse_archive_path(settings.parse_archive_path.clone().into());
    app.set_parse_output_path(parse_output_path.into());
    app.set_use_elasticsearch(settings.use_elasticsearch);
    app.set_parse_progress_value(0.0);
    app.set_parse_status("Ready to inspect a collection zip.".into());
    app.set_parse_summary(
        "Inspect a zip to detect supported artifact groups and choose what to parse.".into(),
    );

    app.set_elasticsearch_url(settings.elasticsearch_url.clone().into());
    app.set_elasticsearch_username(settings.elasticsearch_username.clone().into());
    app.set_elasticsearch_password("".into());
    app.set_elasticsearch_index(settings.elasticsearch_index.clone().into());
    app.set_elasticsearch_insecure(settings.elasticsearch_insecure);

    apply_collection_profile_from_app(app, state);
    refresh_collection_catalog(app, state);
    refresh_collection_drives(app, state);
    refresh_collection_activity(app, state);
    refresh_detected_plans(app, state);
    sync_technical_logs(app);
    apply_launch_overlays(app, state, options.screenshot_state);
    wire_callbacks(app, state);
    if options.screenshot_state.is_none()
        && let Err(error) = refresh_shadow_copy_recovery(app, state, true)
    {
        report_collection_error(app, "Shadow copy recovery check failed", &error);
    }
    schedule_collection_drive_refresh(app.as_weak(), Arc::clone(state));
    schedule_collection_activity_pulse(app.as_weak());
    schedule_technical_log_refresh(app.as_weak());
    schedule_window_chrome_theme_refresh(app.as_weak());
    Ok(())
}

fn apply_launch_overlays(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    screenshot_state: Option<DesktopScreenshotState>,
) {
    app.set_settings_open(false);
    app.set_about_open(false);
    app.set_evidence_scope_open(false);
    app.set_collection_usn_settings_open(false);
    app.set_shadow_copy_recovery_open(false);
    app.set_error_dialog_open(false);
    app.set_collection_running(false);

    match screenshot_state.unwrap_or(DesktopScreenshotState::Main) {
        DesktopScreenshotState::Main => {}
        DesktopScreenshotState::About => app.set_about_open(true),
        DesktopScreenshotState::Settings => app.set_settings_open(true),
        DesktopScreenshotState::Scope => app.set_evidence_scope_open(true),
        DesktopScreenshotState::UsnSettings => {
            app.set_evidence_scope_open(true);
            app.set_collection_usn_settings_open(true);
        }
        DesktopScreenshotState::CollectionProgress => {
            seed_collection_progress_overlay(app, state);
        }
    }
}

fn seed_collection_progress_overlay(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        state_guard.collection_runtime_phase = CollectionRuntimePhase::Running;
        state_guard.selected_collection_activity_title = Some("Registry Hives".to_string());
        state_guard.collection_progress = Some(CollectionProgressState {
            runtime_jobs: 2,
            completed_jobs: 1,
            current_collector: Some("Registry Hives".to_string()),
            collectors: BTreeMap::from([
                (
                    "$UsnJrnl".to_string(),
                    CollectionCollectorProgress {
                        current_volume: Some("C:".to_string()),
                        current_job_progress: 0.0,
                        detail: "Collected and staged the USN Journal from C:.".to_string(),
                        progress_text: "2 staged paths".to_string(),
                        completed_jobs: 1,
                        staged_paths: 2,
                        artifact_paths: vec![
                            "C/$Extend/$UsnJrnl/$J.bin".to_string(),
                            "$metadata/collectors/C/windows_usn_journal/manifest.json".to_string(),
                        ],
                        started: true,
                        active: false,
                    },
                ),
                (
                    "Registry Hives".to_string(),
                    CollectionCollectorProgress {
                        current_volume: Some("C:".to_string()),
                        current_job_progress: 0.58,
                        detail:
                            "Copying transaction-safe registry artifacts from the VSS snapshot."
                                .to_string(),
                        progress_text: "23 / 72 artifacts".to_string(),
                        completed_jobs: 0,
                        staged_paths: 0,
                        artifact_paths: Vec::new(),
                        started: true,
                        active: true,
                    },
                ),
            ]),
            ..Default::default()
        });
    }

    app.set_collection_running(true);
    app.set_collection_status("Collecting Registry Hives on C:".into());
    app.set_collection_log(
        "[2026-05-08T08:04:10Z] source=collection-ui Starting collection package runtime_collectors=2 runtime_jobs=2 zip=output/holo-forensics-full.zip\n[2026-05-08T08:04:11Z] source=collection-ui $UsnJrnl started on C:\n[2026-05-08T08:04:20Z] source=collection-ui $UsnJrnl finished on C: staged 2 paths\n[2026-05-08T08:04:20Z] source=collection-ui Registry Hives started on C:"
            .into(),
    );
    refresh_collection_activity(app, state);
}

fn guard_desktop_action<T>(operation: &str, action: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result,
        Err(payload) => Err(anyhow!(
            "{operation} panicked unexpectedly. {}",
            panic_payload_message(payload)
        )),
    }
}

fn panic_payload_message(payload: Box<dyn Any + Send>) -> String {
    let payload = match payload.downcast::<String>() {
        Ok(message) => return *message,
        Err(payload) => payload,
    };

    let payload = match payload.downcast::<&'static str>() {
        Ok(message) => return (*message).to_string(),
        Err(payload) => payload,
    };

    let _ = payload;
    "Unknown panic payload.".to_string()
}

fn error_summary(error: &anyhow::Error) -> String {
    error
        .chain()
        .next()
        .map(|cause| cause.to_string())
        .filter(|message| !message.trim().is_empty())
        .unwrap_or_else(|| "The operation failed without an error message.".to_string())
}

fn format_error_details(error: &anyhow::Error) -> String {
    let mut causes = error
        .chain()
        .map(|cause| cause.to_string())
        .filter(|message| !message.trim().is_empty())
        .collect::<Vec<_>>();

    causes.dedup();

    match causes.split_first() {
        Some((primary, [])) => primary.clone(),
        Some((primary, remaining)) => {
            let mut detail = primary.clone();
            detail.push_str("\n\nCaused by:");
            for cause in remaining {
                detail.push_str("\n- ");
                detail.push_str(cause);
            }
            detail
        }
        None => "The operation failed without an error message.".to_string(),
    }
}

fn show_error_dialog(app: &AppWindow, title: &str, summary: &str, detail: &str) {
    app.set_error_dialog_title(title.into());
    app.set_error_dialog_summary(summary.into());
    app.set_error_dialog_detail(detail.into());
    app.set_error_dialog_open(true);
}

fn report_collection_error(app: &AppWindow, title: &str, error: &anyhow::Error) {
    let summary = error_summary(error);
    let detail = format_error_details(error);

    app.set_collection_status(title.into());
    append_collection_log(app, &detail);
    show_error_dialog(app, title, &summary, &detail);
}

fn report_ui_error(app: &AppWindow, title: &str, error: &anyhow::Error) {
    let summary = error_summary(error);
    let detail = format_error_details(error);

    append_technical_log(app, "desktop-ui", &format!("{title}: {detail}"));
    show_error_dialog(app, title, &summary, &detail);
}

fn report_parse_error(app: &AppWindow, title: &str, error: &anyhow::Error) {
    let summary = error_summary(error);
    let detail = format_error_details(error);

    app.set_parse_status(title.into());
    app.set_parse_summary(summary.clone().into());
    append_parse_log(app, &detail);
    show_error_dialog(app, title, &summary, &detail);
}

fn build_shadow_copy_recovery_summary(count: usize) -> String {
    format!(
        "Holo Forensics found {} previously tracked Volume Shadow {} that still exist. Keep them for reuse, or delete every recovered snapshot now.",
        count,
        if count == 1 { "Copy" } else { "Copies" }
    )
}

fn tracked_shadow_copy_to_ui_item(entry: &vss::TrackedShadowCopy) -> ShadowCopyRecoveryItem {
    ShadowCopyRecoveryItem {
        volume: entry.volume.clone().into(),
        created_at: entry.created_at.clone().into(),
        shadow_id: entry.id.clone().into(),
        device_object: entry.device_object.clone().into(),
    }
}

fn refresh_shadow_copy_recovery(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    open_if_any: bool,
) -> Result<()> {
    let tracked_shadow_copies = vss::reconcile_tracked_shadow_copies()?;
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        state_guard.tracked_shadow_copies = tracked_shadow_copies.clone();
    }

    let items = tracked_shadow_copies
        .iter()
        .map(tracked_shadow_copy_to_ui_item)
        .collect::<Vec<_>>();
    app.set_shadow_copy_recovery_items(Rc::new(VecModel::from(items)).into());

    if tracked_shadow_copies.is_empty() {
        app.set_shadow_copy_recovery_summary("".into());
        app.set_shadow_copy_recovery_open(false);
        return Ok(());
    }

    app.set_shadow_copy_recovery_summary(
        build_shadow_copy_recovery_summary(tracked_shadow_copies.len()).into(),
    );
    if open_if_any {
        app.set_shadow_copy_recovery_open(true);
    }
    Ok(())
}

fn keep_tracked_shadow_copies(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let count = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.tracked_shadow_copies.len()
    };
    app.set_shadow_copy_recovery_open(false);
    if count > 0 {
        app.set_collection_status(
            format!(
                "Keeping {} recovered shadow {}.",
                count,
                pluralize(count, "copy", "copies")
            )
            .into(),
        );
        append_collection_log(
            app,
            &format!(
                "Keeping {} tracked VSS shadow {} for possible reuse.",
                count,
                pluralize(count, "copy", "copies")
            ),
        );
    }
}

fn delete_tracked_shadow_copies(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> Result<()> {
    let tracked_shadow_copies = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.tracked_shadow_copies.clone()
    };
    if tracked_shadow_copies.is_empty() {
        app.set_shadow_copy_recovery_open(false);
        return Ok(());
    }

    let mut deleted = 0usize;
    let mut failures = Vec::new();
    for shadow_copy in &tracked_shadow_copies {
        match vss::delete_shadow_copy(&shadow_copy.id) {
            Ok(()) => deleted += 1,
            Err(error) => failures.push(format!(
                "{} on {}: {error:#}",
                shadow_copy.id, shadow_copy.volume
            )),
        }
    }

    refresh_shadow_copy_recovery(app, state, !failures.is_empty())?;
    if failures.is_empty() {
        app.set_shadow_copy_recovery_open(false);
        app.set_collection_status(
            format!(
                "Deleted {} recovered shadow {}.",
                deleted,
                pluralize(deleted, "copy", "copies")
            )
            .into(),
        );
        append_collection_log(
            app,
            &format!(
                "Deleted {} tracked VSS shadow {} from the previous run.",
                deleted,
                pluralize(deleted, "copy", "copies")
            ),
        );
        return Ok(());
    }

    Err(anyhow!(format!(
        "Failed to delete {} recovered shadow {}.\n\n{}",
        failures.len(),
        pluralize(failures.len(), "copy", "copies"),
        failures.join("\n")
    )))
}

fn wire_callbacks(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let keep_shadow_copies_app = app.as_weak();
    let keep_shadow_copies_state = Arc::clone(state);
    app.on_keep_shadow_copies_requested(move || {
        let Some(app) = keep_shadow_copies_app.upgrade() else {
            return;
        };
        keep_tracked_shadow_copies(&app, &keep_shadow_copies_state);
    });

    let delete_shadow_copies_app = app.as_weak();
    let delete_shadow_copies_state = Arc::clone(state);
    app.on_delete_shadow_copies_requested(move || {
        let Some(app) = delete_shadow_copies_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Delete recovered shadow copies", || {
            delete_tracked_shadow_copies(&app, &delete_shadow_copies_state)
        }) {
            report_collection_error(&app, "Shadow copy cleanup failed", &error);
        }
    });

    let persist_app = app.as_weak();
    let persist_state = Arc::clone(state);
    app.on_persist_settings_requested(move || {
        let Some(app) = persist_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update desktop settings", || {
            persist_settings(&app, &persist_state)?;
            apply_collection_profile_from_app(&app, &persist_state);
            refresh_collection_output_filename(&app);
            refresh_collection_catalog(&app, &persist_state);
            refresh_collection_drives(&app, &persist_state);
            refresh_collection_activity(&app, &persist_state);
            schedule_window_chrome_theme_refresh(app.as_weak());
            Ok(())
        }) {
            report_collection_error(&app, "Settings update failed", &error);
        }
    });

    let open_developer_repo_app = app.as_weak();
    app.on_open_developer_repo_requested(move || {
        let Some(app) = open_developer_repo_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Open developer repository", || {
            open_external_url(FALSE00_REPOSITORY_URL)
        }) {
            report_ui_error(&app, "Open repository failed", &error);
        }
    });

    let browse_collection_app = app.as_weak();
    let browse_collection_state = Arc::clone(state);
    app.on_browse_collection_directory_requested(move || {
        let Some(app) = browse_collection_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update collection destination", || {
            let default_dir = {
                let state_guard = browse_collection_state
                    .lock()
                    .expect("desktop state poisoned");
                default_collection_output_dir(&state_guard.project_root)
            };
            let current_dir = normalize_collection_output_dir(
                app.get_collection_archive_path().as_ref(),
                &default_dir,
            );

            if let Some(path) = browse_for_directory(&current_dir)? {
                app.set_collection_archive_path(display_path(&path).into());
                refresh_collection_output_filename(&app);
                persist_settings(&app, &browse_collection_state)?;
                app.set_collection_status("Destination folder updated.".into());
            }
            Ok(())
        }) {
            report_collection_error(&app, "Destination update failed", &error);
        }
    });

    let select_drive_app = app.as_weak();
    let select_drive_state = Arc::clone(state);
    app.on_select_drive_requested(move |index| {
        let Some(app) = select_drive_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update selected collection source", || {
            let drives = available_collection_drives();
            let selected_index = index.max(0) as usize;
            if let Some(volume) = drives
                .get(selected_index)
                .map(|drive| drive.volume.clone())
                .or_else(|| drives.first().map(|drive| drive.volume.clone()))
            {
                {
                    let mut state_guard =
                        select_drive_state.lock().expect("desktop state poisoned");
                    toggle_selected_collection_volume(
                        &mut state_guard.selected_collection_volumes,
                        &volume,
                        &drives,
                    );
                }
                set_collection_runtime_phase(&select_drive_state, CollectionRuntimePhase::Idle);
                refresh_collection_drives(&app, &select_drive_state);
                refresh_collection_activity(&app, &select_drive_state);
                persist_settings(&app, &select_drive_state)?;
            }
            Ok(())
        }) {
            report_collection_error(&app, "Source volume update failed", &error);
        }
    });

    let select_activity_app = app.as_weak();
    let select_activity_state = Arc::clone(state);
    app.on_select_collection_activity_requested(move |index| {
        let Some(app) = select_activity_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update collection activity detail", || {
            {
                let mut state_guard = select_activity_state
                    .lock()
                    .expect("desktop state poisoned");
                let drives = available_collection_drives();
                let source_state =
                    collection_source_state(&state_guard.selected_collection_volumes, &drives);
                let (records, _) = build_collection_activity_snapshot(
                    &state_guard.collection_catalog,
                    state_guard.collection_runtime_phase,
                    source_state.supported_volumes.len(),
                    source_state.unsupported_volumes.len(),
                    state_guard.collection_progress.as_ref(),
                );
                state_guard.selected_collection_activity_title = records
                    .get(index.max(0) as usize)
                    .map(|record| record.title.clone());
            }
            refresh_collection_activity(&app, &select_activity_state);
            Ok(())
        }) {
            report_collection_error(&app, "Collection activity update failed", &error);
        }
    });

    let inspect_app = app.as_weak();
    let inspect_state = Arc::clone(state);
    app.on_inspect_archive_requested(move || {
        let Some(app) = inspect_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Start archive inspection", || {
            start_archive_inspection(&app, &inspect_state)
        }) {
            report_parse_error(&app, "Inspection failed", &error);
        }
    });

    let select_collection_app = app.as_weak();
    let select_collection_state = Arc::clone(state);
    app.on_select_collection_requested(move |index| {
        let Some(app) = select_collection_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update collection brief", || {
            select_collection_catalog_item(&app, &select_collection_state, index.max(0) as usize)
        }) {
            report_collection_error(&app, "Collection brief update failed", &error);
        }
    });

    let select_all_collections_app = app.as_weak();
    let select_all_collections_state = Arc::clone(state);
    app.on_select_all_collections_requested(move || {
        let Some(app) = select_all_collections_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Select all collection surfaces", || {
            set_all_collection_catalog_items(&app, &select_all_collections_state, true)
        }) {
            report_collection_error(&app, "Collection scope update failed", &error);
        }
    });

    let deselect_all_collections_app = app.as_weak();
    let deselect_all_collections_state = Arc::clone(state);
    app.on_deselect_all_collections_requested(move || {
        let Some(app) = deselect_all_collections_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Deselect all collection surfaces", || {
            set_all_collection_catalog_items(&app, &deselect_all_collections_state, false)
        }) {
            report_collection_error(&app, "Collection scope update failed", &error);
        }
    });

    let toggle_app = app.as_weak();
    let toggle_state = Arc::clone(state);
    app.on_toggle_detected_artifact(move |index| {
        let Some(app) = toggle_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Update parse selection", || {
            toggle_detected_plan(&app, &toggle_state, index.max(0) as usize)
        }) {
            report_parse_error(&app, "Selection update failed", &error);
        }
    });

    let run_parse_app = app.as_weak();
    let run_parse_state = Arc::clone(state);
    app.on_run_parse_requested(move || {
        let Some(app) = run_parse_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Start parse request", || {
            start_parse_run(&app, &run_parse_state)
        }) {
            report_parse_error(&app, "Parse request failed", &error);
        }
    });

    let run_collection_app = app.as_weak();
    let run_collection_state = Arc::clone(state);
    app.on_run_collection_requested(move || {
        let Some(app) = run_collection_app.upgrade() else {
            return;
        };
        if let Err(error) = guard_desktop_action("Start collection request", || {
            start_collection_run(&app, &run_collection_state)
        }) {
            report_collection_error(&app, "Collection request failed", &error);
        }
    });
}

fn start_collection_run(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> Result<()> {
    if app.get_collection_running() || app.get_parse_running() || app.get_parse_inspecting() {
        return Ok(());
    }

    let request = collect_collection_request(app, state)?;
    persist_settings(app, state)?;
    set_collection_runtime_phase(state, CollectionRuntimePhase::Running);

    app.set_collection_running(true);
    app.set_collection_status(
        format!("Collecting {}", format_selected_volumes(&request.volumes)).into(),
    );
    refresh_collection_activity(app, state);
    append_collection_log(
        app,
        &format!(
            "Queue evidence package collection volumes={} collectors={} zip={}",
            request.volumes.join(", "),
            selected_runtime_collectors_label(&request),
            display_path(&request.output_zip)
        ),
    );
    if !request.skipped_volumes.is_empty() {
        append_collection_log(
            app,
            &format!(
                "Skipping selected unsupported source {}: {}",
                pluralize(request.skipped_volumes.len(), "volume", "volumes"),
                request.skipped_volumes.join(", ")
            ),
        );
    }

    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };
    let staging_root = request.output_zip.with_extension("staging");
    let ui = app.as_weak();
    let state_for_ui = Arc::clone(state);

    std::thread::spawn(move || {
        let ui_for_events = ui.clone();
        let state_for_events = Arc::clone(&state_for_ui);
        let result = guard_desktop_action("Run collection workflow", || {
            app::collect_collection_archive_with_reporter(
                &app::CollectionArchiveRequest {
                    volumes: request.volumes.clone(),
                    output_zip: request.output_zip.clone(),
                    staging_root: Some(staging_root),
                    usn: request.collect_usn.then_some(app::UsnCollectionOptions {
                        mode: request.mode,
                        sparse: request.sparse,
                        chunk_size_mib: request.chunk_size_mib,
                        elevate: request.elevate,
                    }),
                    registry: request
                        .collect_registry
                        .then_some(app::RegistryCollectionOptions {
                            method: registry::RegistryCollectMethod::VssSnapshot,
                            elevate: request.elevate,
                        }),
                    evtx: request.collect_evtx.then_some(app::EvtxCollectionOptions {
                        elevate: request.elevate,
                    }),
                    srum: request.collect_srum.then_some(app::SrumCollectionOptions {
                        elevate: request.elevate,
                    }),
                    prefetch: request
                        .collect_prefetch
                        .then_some(app::PrefetchCollectionOptions {
                            elevate: request.elevate,
                        }),
                    browser_artifacts: request.collect_browser_artifacts.then_some(
                        app::BrowserArtifactsCollectionOptions {
                            elevate: request.elevate,
                        },
                    ),
                    jump_lists: request.collect_jump_lists.then_some(
                        app::JumpListsCollectionOptions {
                            elevate: request.elevate,
                        },
                    ),
                    lnk: request.collect_lnk.then_some(app::LnkCollectionOptions {
                        elevate: request.elevate,
                    }),
                    mft: request.collect_mft.then_some(app::MftCollectionOptions {
                        mode: mft::MftAcquisitionMode::Vss,
                        elevate: request.elevate,
                    }),
                    logfile: request
                        .collect_logfile
                        .then_some(app::LogFileCollectionOptions {
                            mode: logfile::LogFileAcquisitionMode::Vss,
                            elevate: request.elevate,
                        }),
                    indx: request.collect_indx.then_some(app::IndxCollectionOptions {
                        mode: indx::IndxAcquisitionMode::Vss,
                        include_deleted_dirs: false,
                        max_directories: None,
                        elevate: request.elevate,
                    }),
                },
                &mut |event| {
                    dispatch_collection_event(
                        ui_for_events.clone(),
                        Arc::clone(&state_for_events),
                        event,
                    )
                },
            )
        });

        let _ = slint::invoke_from_event_loop(move || {
            let Some(app) = ui.upgrade() else {
                return;
            };

            app.set_collection_running(false);
            match result {
                Ok(summary) => {
                    set_collection_runtime_phase(&state_for_ui, CollectionRuntimePhase::Succeeded);
                    app.set_collection_status(
                        format!(
                            "Collection zip created: {}",
                            file_name_or_path(&summary.output_zip)
                        )
                        .into(),
                    );
                    append_collection_log(
                        &app,
                        &format!(
                            "Collection staging complete {}",
                            display_path(&summary.staging_dir)
                        ),
                    );
                    app.set_parse_archive_path(display_path(&summary.output_zip).into());
                    app.set_parse_output_path(
                        display_path(&parse_output_path_for_zip(
                            &project_root,
                            &summary.output_zip,
                        ))
                        .into(),
                    );
                    append_collection_log(
                        &app,
                        "Package ready for preservation, transfer, or later offline analysis.",
                    );
                }
                Err(error) => {
                    set_collection_runtime_phase(&state_for_ui, CollectionRuntimePhase::Failed);
                    report_collection_error(&app, "Collection failed", &error);
                }
            }
            refresh_collection_activity(&app, &state_for_ui);
        });
    });

    Ok(())
}

fn start_archive_inspection(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> Result<()> {
    let input = parse_existing_file(
        app.get_parse_archive_path().to_string(),
        "Provide a readable collection zip path before inspecting.",
    )?;
    start_archive_inspection_for_input(app, state, input)
}

fn start_archive_inspection_for_input(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    input: PathBuf,
) -> Result<()> {
    if app.get_parse_running() || app.get_parse_inspecting() {
        return Ok(());
    }

    persist_settings(app, state)?;
    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };
    let inspection_root = inspection_cache_dir(&project_root, &input);
    let input_for_thread = input.clone();
    let input_for_ui = input.clone();
    let ui = app.as_weak();
    let state_for_ui = Arc::clone(state);

    app.set_parse_archive_path(display_path(&input).into());
    app.set_parse_inspecting(true);
    app.set_parse_progress_value(0.0);
    app.set_parse_status(format!("Inspecting {}", file_name_or_path(&input)).into());
    app.set_parse_summary("Extracting the zip and resolving supported parser plans.".into());
    append_parse_log(app, &format!("Inspect {}", display_path(&input)));

    std::thread::spawn(move || {
        let result = guard_desktop_action("Inspect collection archive", || {
            app::inspect_parse_archive(
                &input_for_thread,
                app::ParseInspectionOptions {
                    project_root: Some(project_root.clone()),
                    extraction_root: Some(inspection_root),
                },
            )
        });

        let _ = slint::invoke_from_event_loop(move || {
            let Some(app) = ui.upgrade() else {
                return;
            };

            app.set_parse_inspecting(false);
            match result {
                Ok(summary) => {
                    replace_detected_plans(&state_for_ui, summary.detected_plans);
                    refresh_detected_plans(&app, &state_for_ui);
                    app.set_parse_output_path(
                        display_path(&parse_output_path_for_zip(&project_root, &input_for_ui))
                            .into(),
                    );
                    let count = {
                        let state_guard = state_for_ui.lock().expect("desktop state poisoned");
                        state_guard.detected_plans.len()
                    };
                    app.set_parse_status(if count == 0 {
                        "No supported artifacts detected".into()
                    } else {
                        format!("Detected {} supported artifact groups", count).into()
                    });
                    append_parse_log(&app, &build_inspection_log(&input_for_ui, count));
                }
                Err(error) => {
                    replace_detected_plans(&state_for_ui, Vec::new());
                    refresh_detected_plans(&app, &state_for_ui);
                    report_parse_error(&app, "Inspection failed", &error);
                }
            }
        });
    });

    Ok(())
}

fn start_parse_run(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> Result<()> {
    if app.get_parse_running() || app.get_parse_inspecting() || app.get_collection_running() {
        return Ok(());
    }

    let request = collect_parse_request(app, state)?;
    persist_settings(app, state)?;

    app.set_parse_running(true);
    app.set_parse_progress_value(0.0);
    app.set_parse_status(format!("Parsing {}", file_name_or_path(&request.input)).into());
    app.set_parse_summary(
        format!(
            "Selected {} artifact groups.",
            request.selected_plan_ids.len()
        )
        .into(),
    );
    append_parse_log(
        app,
        &format!(
            "Run parse zip={} output={}",
            display_path(&request.input),
            request
                .output
                .as_ref()
                .map(|path| display_path(path))
                .unwrap_or_else(|| "default output".to_string())
        ),
    );

    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };
    let ui = app.as_weak();

    std::thread::spawn(move || {
        let mut tracker = ProgressTracker::new();
        let ui_for_events = ui.clone();
        let result = guard_desktop_action("Run parse workflow", || {
            app::run_parse_request(
                ParseCli {
                    input: Some(request.input.clone()),
                    output: request.output.clone(),
                    opensearch_url: request.opensearch_url.clone(),
                    opensearch_username: request.opensearch_username.clone(),
                    opensearch_password: request.opensearch_password.clone(),
                    opensearch_index: request.opensearch_index.clone(),
                    opensearch_insecure: request.opensearch_insecure,
                },
                ParseRunOptions {
                    project_root: Some(project_root),
                    selected_plan_ids: Some(request.selected_plan_ids.clone()),
                },
                |event| dispatch_parse_event(ui_for_events.clone(), &mut tracker, event),
            )
        });

        let _ = slint::invoke_from_event_loop(move || {
            let Some(app) = ui.upgrade() else {
                return;
            };

            app.set_parse_running(false);
            match result {
                Ok(summary) => {
                    app.set_parse_progress_value(1.0);
                    app.set_parse_status(
                        format!(
                            "Parse completed: {}",
                            file_name_or_path(&summary.manifest_path)
                        )
                        .into(),
                    );
                    app.set_parse_summary(display_path(&summary.manifest_path).into());
                    append_parse_log(
                        &app,
                        &format!("Manifest {}", display_path(&summary.manifest_path)),
                    );
                }
                Err(error) => {
                    report_parse_error(&app, "Parse failed", &error);
                }
            }
        });
    });

    Ok(())
}

fn dispatch_parse_event(
    ui: slint::Weak<AppWindow>,
    tracker: &mut ProgressTracker,
    event: ParseEvent,
) {
    tracker.observe(&event);

    let status = event_title(&event);
    let summary = tracker.summary();
    let progress = match event {
        ParseEvent::Completed { .. } => 1.0,
        _ => tracker.progress_value(),
    };
    let log_line = event_log_line(&event);

    let _ = slint::invoke_from_event_loop(move || {
        let Some(app) = ui.upgrade() else {
            return;
        };

        app.set_parse_status(status.into());
        app.set_parse_summary(summary.into());
        app.set_parse_progress_value(progress);
        append_parse_log(&app, &log_line);
    });
}

fn dispatch_collection_event(
    ui: slint::Weak<AppWindow>,
    state: Arc<Mutex<DesktopState>>,
    event: app::CollectionEvent,
) {
    let status = collection_event_status(&event);
    let log_line = collection_event_log_line(&event);
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        observe_collection_event(&mut state_guard, &event);
    }

    let _ = slint::invoke_from_event_loop(move || {
        let Some(app) = ui.upgrade() else {
            return;
        };

        app.set_collection_status(status.into());
        refresh_collection_activity(&app, &state);
        if let Some(line) = log_line.as_deref() {
            append_collection_log(&app, line);
        }
    });
}

fn observe_collection_event(state: &mut DesktopState, event: &app::CollectionEvent) {
    let progress = state
        .collection_progress
        .get_or_insert_with(Default::default);
    match event {
        app::CollectionEvent::RunStarting {
            runtime_jobs,
            output_zip,
            ..
        } => {
            *progress = CollectionProgressState {
                runtime_jobs: *runtime_jobs,
                output_zip: Some(output_zip.clone()),
                ..Default::default()
            };
        }
        app::CollectionEvent::CollectorStarted {
            collection_title,
            volume,
            progress_value,
            detail,
            progress_text,
        }
        | app::CollectionEvent::CollectorProgress {
            collection_title,
            volume,
            progress_value,
            detail,
            progress_text,
        } => {
            let entry = progress
                .collectors
                .entry(collection_title.clone())
                .or_default();
            entry.current_volume = Some(volume.clone());
            entry.current_job_progress = progress_value.clamp(0.0, 1.0);
            entry.detail = detail.clone();
            entry.progress_text = progress_text.clone();
            entry.started = true;
            entry.active = true;
            progress.current_collector = Some(collection_title.clone());
            progress.packaging_started = false;
        }
        app::CollectionEvent::CollectorFinished {
            collection_title,
            volume,
            detail,
            progress_text,
            staged_paths,
            artifact_paths,
            ..
        } => {
            let entry = progress
                .collectors
                .entry(collection_title.clone())
                .or_default();
            entry.current_volume = Some(volume.clone());
            entry.current_job_progress = 0.0;
            entry.detail = detail.clone();
            entry.progress_text = progress_text.clone();
            entry.completed_jobs = entry.completed_jobs.saturating_add(1);
            entry.staged_paths = entry.staged_paths.saturating_add(*staged_paths);
            entry.artifact_paths.extend(artifact_paths.iter().cloned());
            entry.artifact_paths.sort();
            entry.artifact_paths.dedup();
            entry.started = true;
            entry.active = false;
            progress.completed_jobs = progress.completed_jobs.saturating_add(1);
            progress.current_collector = None;
        }
        app::CollectionEvent::PackagingStarting {
            output_zip,
            entry_count,
        } => {
            progress.packaging_started = true;
            progress.packaging_entry_count = *entry_count;
            progress.current_collector = None;
            progress.output_zip = Some(output_zip.clone());
            for entry in progress.collectors.values_mut() {
                entry.active = false;
            }
        }
        app::CollectionEvent::Completed {
            output_zip,
            staged_paths: _,
        } => {
            progress.completed = true;
            progress.packaging_started = false;
            progress.current_collector = None;
            progress.output_zip = Some(output_zip.clone());
            for entry in progress.collectors.values_mut() {
                entry.active = false;
            }
        }
    }
}

fn collection_event_status(event: &app::CollectionEvent) -> String {
    match event {
        app::CollectionEvent::RunStarting {
            runtime_collectors, ..
        } => format!(
            "Starting {} runtime {}",
            runtime_collectors,
            pluralize(*runtime_collectors, "collector", "collectors")
        ),
        app::CollectionEvent::CollectorStarted {
            collection_title,
            volume,
            ..
        }
        | app::CollectionEvent::CollectorProgress {
            collection_title,
            volume,
            ..
        } => format!("Collecting {collection_title} on {volume}"),
        app::CollectionEvent::CollectorFinished {
            collection_title,
            volume,
            ..
        } => format!("{collection_title} staged from {volume}"),
        app::CollectionEvent::PackagingStarting { .. } => {
            "Packaging collected evidence into the zip.".to_string()
        }
        app::CollectionEvent::Completed { output_zip, .. } => {
            format!("Collection zip created: {}", file_name_or_path(output_zip))
        }
    }
}

fn collection_event_log_line(event: &app::CollectionEvent) -> Option<String> {
    match event {
        app::CollectionEvent::RunStarting {
            runtime_collectors,
            runtime_jobs,
            output_zip,
        } => Some(format!(
            "Starting collection package runtime_collectors={} runtime_jobs={} zip={}",
            runtime_collectors,
            runtime_jobs,
            display_path(output_zip)
        )),
        app::CollectionEvent::CollectorStarted {
            collection_title,
            volume,
            ..
        } => Some(format!("{collection_title} started on {volume}")),
        app::CollectionEvent::CollectorProgress { .. } => None,
        app::CollectionEvent::CollectorFinished {
            collection_title,
            volume,
            staged_paths,
            ..
        } => Some(format!(
            "{collection_title} finished on {volume} staged {staged_paths} {}",
            pluralize(*staged_paths, "path", "paths")
        )),
        app::CollectionEvent::PackagingStarting {
            output_zip,
            entry_count,
        } => Some(format!(
            "Packaging {} staged {} into {}",
            entry_count,
            pluralize(*entry_count, "entry", "entries"),
            display_path(output_zip)
        )),
        app::CollectionEvent::Completed {
            output_zip,
            staged_paths,
        } => Some(format!(
            "Created zip {} from {} staged {}",
            display_path(output_zip),
            staged_paths,
            pluralize(*staged_paths, "path", "paths")
        )),
    }
}

fn collect_collection_request(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
) -> Result<CollectionExecutionRequest> {
    let (
        collect_usn,
        collect_registry,
        collect_evtx,
        collect_srum,
        collect_prefetch,
        collect_browser_artifacts,
        collect_jump_lists,
        collect_lnk,
        collect_mft,
        collect_logfile,
        collect_indx,
    ) = {
        let state_guard = state.lock().expect("desktop state poisoned");
        let selected_live_titles = state_guard
            .collection_catalog
            .iter()
            .filter(|record| record.live && record.selected)
            .map(|record| record.title.clone())
            .collect::<Vec<_>>();
        (
            selected_live_titles.iter().any(|title| title == "$UsnJrnl"),
            selected_live_titles
                .iter()
                .any(|title| title == "Registry Hives"),
            selected_live_titles
                .iter()
                .any(|title| title == "Windows Event Logs"),
            selected_live_titles.iter().any(|title| title == "SRUM"),
            selected_live_titles.iter().any(|title| title == "Prefetch"),
            selected_live_titles
                .iter()
                .any(|title| title == "Browser Artifacts"),
            selected_live_titles
                .iter()
                .any(|title| title == "Jump Lists"),
            selected_live_titles
                .iter()
                .any(|title| title == "LNK Files"),
            selected_live_titles.iter().any(|title| title == "$MFT"),
            selected_live_titles.iter().any(|title| title == "$LogFile"),
            selected_live_titles
                .iter()
                .any(|title| title == "INDX Records"),
        )
    };
    if !collect_usn
        && !collect_registry
        && !collect_evtx
        && !collect_srum
        && !collect_prefetch
        && !collect_browser_artifacts
        && !collect_jump_lists
        && !collect_lnk
        && !collect_mft
        && !collect_logfile
        && !collect_indx
    {
        return Err(anyhow!(
            "Select at least one currently available evidence group before creating a package."
        ));
    }

    let drives = available_collection_drives();
    let selected_volumes = {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        state_guard.selected_collection_volumes = normalized_selected_volumes_or_default(
            &state_guard.selected_collection_volumes,
            &drives,
        );
        state_guard.selected_collection_volumes.clone()
    };
    let source_state = collection_source_state(&selected_volumes, &drives);
    if !source_state.supported() {
        return Err(anyhow!(ntfs_artifact_requirement_message()));
    }
    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };
    let default_output_dir = default_collection_output_dir(&project_root);
    let output_dir = normalize_collection_output_dir(
        app.get_collection_archive_path().as_ref(),
        &default_output_dir,
    );
    let output_zip = output_dir.join(collection_output_filename(app.get_collection_profile()));

    Ok(CollectionExecutionRequest {
        volumes: source_state.supported_volumes,
        skipped_volumes: source_state.unsupported_volumes,
        output_zip,
        collect_usn,
        collect_registry,
        collect_evtx,
        collect_srum,
        collect_prefetch,
        collect_browser_artifacts,
        collect_jump_lists,
        collect_lnk,
        collect_mft,
        collect_logfile,
        collect_indx,
        mode: usn_mode_from_index(app.get_collection_usn_mode()),
        sparse: app.get_collection_sparse() && app.get_collection_usn_mode() == 2,
        chunk_size_mib: usn_chunk_size_mib_from_index(app.get_collection_usn_chunk_index()),
        elevate: app.get_collection_elevate(),
    })
}

fn collect_parse_request(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
) -> Result<ParseExecutionRequest> {
    let input = parse_existing_file(
        app.get_parse_archive_path().to_string(),
        "Provide a readable collection zip path before parsing.",
    )?;

    let selected_plan_ids = {
        let state_guard = state.lock().expect("desktop state poisoned");
        if state_guard.detected_plans.is_empty() {
            return Err(anyhow!("Inspect the selected zip before starting a parse."));
        }
        state_guard
            .detected_plans
            .iter()
            .filter(|plan| plan.selected)
            .map(|plan| plan.id.clone())
            .collect::<BTreeSet<_>>()
    };
    if selected_plan_ids.is_empty() {
        return Err(anyhow!(
            "Select at least one detected artifact group before starting a parse."
        ));
    }

    let project_root = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.project_root.clone()
    };
    let output = normalized_path(app.get_parse_output_path().to_string())
        .or_else(|| Some(parse_output_path_for_zip(&project_root, &input)));

    let use_elasticsearch = app.get_use_elasticsearch();
    let opensearch_url = normalized_string(app.get_elasticsearch_url().to_string());
    if use_elasticsearch && opensearch_url.is_none() {
        return Err(anyhow!(
            "Enable Elasticsearch only after configuring a destination URL in Settings."
        ));
    }

    Ok(ParseExecutionRequest {
        input,
        output,
        selected_plan_ids,
        opensearch_url: if use_elasticsearch {
            opensearch_url
        } else {
            None
        },
        opensearch_username: if use_elasticsearch {
            normalized_string(app.get_elasticsearch_username().to_string())
        } else {
            None
        },
        opensearch_password: if use_elasticsearch {
            normalized_string(app.get_elasticsearch_password().to_string())
        } else {
            None
        },
        opensearch_index: if use_elasticsearch {
            normalized_string(app.get_elasticsearch_index().to_string())
        } else {
            None
        },
        opensearch_insecure: use_elasticsearch && app.get_elasticsearch_insecure(),
    })
}

fn toggle_detected_plan(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    index: usize,
) -> Result<()> {
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        let Some(plan) = state_guard.detected_plans.get_mut(index) else {
            return Ok(());
        };
        plan.selected = !plan.selected;
    }

    refresh_detected_plans(app, state);
    Ok(())
}

fn replace_detected_plans(state: &Arc<Mutex<DesktopState>>, detected: Vec<app::DetectedPlan>) {
    let mut state_guard = state.lock().expect("desktop state poisoned");
    state_guard.detected_plans = detected
        .into_iter()
        .map(DetectedPlanRecord::from_backend)
        .collect();
}

fn refresh_detected_plans(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let (items, total, selected) = {
        let state_guard = state.lock().expect("desktop state poisoned");
        let items = state_guard
            .detected_plans
            .iter()
            .map(DetectedPlanRecord::to_ui_item)
            .collect::<Vec<_>>();
        let total = state_guard.detected_plans.len();
        let selected = state_guard
            .detected_plans
            .iter()
            .filter(|plan| plan.selected)
            .count();
        (items, total, selected)
    };

    app.set_detected_artifacts(Rc::new(VecModel::from(items)).into());
    if !app.get_parse_running() && !app.get_parse_inspecting() {
        let summary = if total == 0 {
            "No supported artifact groups detected yet.".to_string()
        } else {
            format!(
                "Selected {} of {} detected artifact groups.",
                selected, total
            )
        };
        app.set_parse_summary(summary.into());
    }
}

fn select_collection_catalog_item(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    index: usize,
) -> Result<()> {
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        if state_guard.collection_catalog.is_empty() {
            return Ok(());
        }

        if app.get_collection_profile() != 2 {
            app.set_collection_profile(2);
        }

        let selected_index = index.min(state_guard.collection_catalog.len() - 1);
        if let Some(record) = state_guard.collection_catalog.get_mut(selected_index) {
            record.selected = !record.selected;
        }
        if !state_guard
            .collection_catalog
            .iter()
            .any(|record| record.selected)
        {
            if let Some(record) = state_guard.collection_catalog.get_mut(selected_index) {
                record.selected = true;
            }
        }
    }

    set_collection_runtime_phase(state, CollectionRuntimePhase::Idle);
    refresh_collection_catalog(app, state);
    refresh_collection_activity(app, state);
    refresh_collection_output_filename(app);
    persist_settings(app, state)?;
    Ok(())
}

fn set_all_collection_catalog_items(
    app: &AppWindow,
    state: &Arc<Mutex<DesktopState>>,
    selected: bool,
) -> Result<()> {
    {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        for record in &mut state_guard.collection_catalog {
            record.selected = selected;
        }
        app.set_collection_profile(2);
    }

    set_collection_runtime_phase(state, CollectionRuntimePhase::Idle);
    refresh_collection_catalog(app, state);
    refresh_collection_activity(app, state);
    refresh_collection_output_filename(app);
    persist_settings(app, state)?;
    Ok(())
}

fn apply_collection_profile_from_app(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let profile = app.get_collection_profile().clamp(0, 2);
    if profile == 2 {
        return;
    }

    let mut state_guard = state.lock().expect("desktop state poisoned");
    apply_collection_profile(&mut state_guard.collection_catalog, profile);
}

fn apply_collection_profile(records: &mut [CollectionCatalogRecord], profile: i32) {
    match profile {
        1 => {
            for record in records {
                record.selected = TRIAGE_COLLECTION_TITLES.contains(&record.title.as_str());
            }
        }
        _ => {
            for record in records {
                record.selected = true;
            }
        }
    }
}

fn refresh_collection_catalog(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let (items, selected_record) = {
        let state_guard = state.lock().expect("desktop state poisoned");
        let items = state_guard
            .collection_catalog
            .iter()
            .map(CollectionCatalogRecord::to_ui_item)
            .collect::<Vec<_>>();
        let selected_record = state_guard
            .collection_catalog
            .iter()
            .find(|record| record.selected)
            .or_else(|| state_guard.collection_catalog.first())
            .cloned();
        (items, selected_record)
    };

    app.set_collection_catalog(Rc::new(VecModel::from(items)).into());

    if let Some(record) = selected_record {
        app.set_selected_collection_title(record.title.into());
        app.set_selected_collection_category(record.category.into());
        app.set_selected_collection_status(record.status.into());
        app.set_selected_collection_summary(record.summary.into());
        app.set_selected_collection_targets(record.targets.into());
        app.set_selected_collection_note(record.note.into());
        app.set_selected_collection_live(record.live);
    } else {
        app.set_selected_collection_title("".into());
        app.set_selected_collection_category("".into());
        app.set_selected_collection_status("".into());
        app.set_selected_collection_summary("".into());
        app.set_selected_collection_targets("".into());
        app.set_selected_collection_note("".into());
        app.set_selected_collection_live(false);
    }
}

fn refresh_collection_activity(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let drives = available_collection_drives();
    let (items, summary, detail_title, detail_status, detail_summary, detail_items) = {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        let source_state =
            collection_source_state(&state_guard.selected_collection_volumes, &drives);
        let (items, summary) = build_collection_activity_snapshot(
            &state_guard.collection_catalog,
            state_guard.collection_runtime_phase,
            source_state.supported_volumes.len(),
            source_state.unsupported_volumes.len(),
            state_guard.collection_progress.as_ref(),
        );
        if state_guard
            .selected_collection_activity_title
            .as_ref()
            .is_none_or(|title| !items.iter().any(|item| &item.title == title))
        {
            state_guard.selected_collection_activity_title = items
                .iter()
                .find(|item| item.active)
                .map(|item| item.title.clone())
                .or_else(|| {
                    items
                        .iter()
                        .find(|item| item.tone == CollectionActivityTone::Complete)
                        .map(|item| item.title.clone())
                })
                .or_else(|| items.first().map(|item| item.title.clone()));
        }
        let selected_title = state_guard.selected_collection_activity_title.clone();
        let selected_record = selected_title
            .as_ref()
            .and_then(|title| items.iter().find(|item| &item.title == title));
        let detail_items = build_collection_activity_details(
            selected_record,
            state_guard.collection_progress.as_ref(),
        );
        let detail_title = selected_record
            .map(|record| record.title.clone())
            .unwrap_or_else(|| "Collection details".to_string());
        let detail_status = selected_record
            .map(|record| record.status.clone())
            .unwrap_or_default();
        let detail_summary = collection_activity_detail_summary(
            selected_record,
            state_guard.collection_progress.as_ref(),
            detail_items.len(),
        );
        (
            items,
            summary,
            detail_title,
            detail_status,
            detail_summary,
            detail_items,
        )
    };

    let ui_items = items
        .iter()
        .map(CollectionActivityRecord::to_ui_item)
        .collect::<Vec<_>>();
    let ui_detail_items = detail_items
        .iter()
        .map(CollectionActivityDetailRecord::to_ui_item)
        .collect::<Vec<_>>();
    app.set_collection_activity_items(Rc::new(VecModel::from(ui_items)).into());
    app.set_collection_activity_summary(summary.into());
    app.set_collection_activity_detail_title(detail_title.into());
    app.set_collection_activity_detail_status(detail_status.into());
    app.set_collection_activity_detail_summary(detail_summary.into());
    app.set_collection_activity_detail_items(Rc::new(VecModel::from(ui_detail_items)).into());
}

fn set_collection_runtime_phase(state: &Arc<Mutex<DesktopState>>, phase: CollectionRuntimePhase) {
    let mut state_guard = state.lock().expect("desktop state poisoned");
    state_guard.collection_runtime_phase = phase;
    if matches!(
        phase,
        CollectionRuntimePhase::Idle | CollectionRuntimePhase::Running
    ) {
        state_guard.collection_progress = None;
    }
}

fn build_collection_activity_snapshot(
    catalog: &[CollectionCatalogRecord],
    phase: CollectionRuntimePhase,
    supported_source_count: usize,
    unsupported_source_count: usize,
    progress_state: Option<&CollectionProgressState>,
) -> (Vec<CollectionActivityRecord>, String) {
    let mut selected = catalog
        .iter()
        .filter(|record| record.selected)
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        right
            .live
            .cmp(&left.live)
            .then_with(|| left.title.cmp(&right.title))
    });

    let runtime_selected = selected.iter().filter(|record| record.live).count();
    let scope_only_selected = selected.len().saturating_sub(runtime_selected);
    let summary = build_collection_activity_summary(
        selected.len(),
        runtime_selected,
        scope_only_selected,
        phase,
        supported_source_count,
        unsupported_source_count,
        progress_state,
    );

    let mut runtime_slot = 0usize;
    let items = selected
        .into_iter()
        .map(|record| {
            let item = if record.live {
                let current_slot = runtime_slot;
                runtime_slot += 1;
                build_runtime_activity_record(
                    record,
                    phase,
                    current_slot,
                    supported_source_count,
                    unsupported_source_count,
                    progress_state,
                )
            } else {
                CollectionActivityRecord {
                    title: record.title.clone(),
                    category: record.category.clone(),
                    detail:
                        "Selected in scope, but still a planning surface until its runtime collector ships."
                            .to_string(),
                    status: "Scope only".to_string(),
                    tone: CollectionActivityTone::ScopeOnly,
                    active: false,
                    show_progress: false,
                    progress_value: 0.0,
                    progress_text: String::new(),
                    package_pending: false,
                }
            };
            item
        })
        .collect::<Vec<_>>();

    (items, summary)
}

fn build_collection_activity_details(
    record: Option<&CollectionActivityRecord>,
    progress_state: Option<&CollectionProgressState>,
) -> Vec<CollectionActivityDetailRecord> {
    let Some(record) = record else {
        return Vec::new();
    };
    if !matches!(
        record.title.as_str(),
        "Registry Hives"
            | "$UsnJrnl"
            | "Windows Event Logs"
            | "SRUM"
            | "Prefetch"
            | "Browser Artifacts"
            | "Jump Lists"
            | "LNK Files"
            | "$MFT"
            | "$LogFile"
            | "INDX Records"
    ) {
        return Vec::new();
    }

    let progress_entry = progress_state.and_then(|state| state.collectors.get(&record.title));
    if let Some(entry) = progress_entry
        && !entry.artifact_paths.is_empty()
    {
        let mut collected = entry
            .artifact_paths
            .iter()
            .map(|path| CollectionActivityDetailRecord {
                name: artifact_name_for_path(path),
                state: "Collected".to_string(),
                detail: format!("{} - {}", artifact_detail_for_path(path), path),
            })
            .collect::<Vec<_>>();
        if !entry.active {
            return collected;
        }
        collected.extend(
            expected_collection_artifacts(&record.title)
                .into_iter()
                .map(|(name, detail)| CollectionActivityDetailRecord {
                    name: name.to_string(),
                    state: "In progress".to_string(),
                    detail: detail.to_string(),
                }),
        );
        return collected;
    }

    let state = if progress_entry.map(|entry| entry.active).unwrap_or(false) {
        "In progress"
    } else if matches!(
        record.tone,
        CollectionActivityTone::Ready | CollectionActivityTone::Queued
    ) {
        "Expected"
    } else {
        "Pending"
    };

    expected_collection_artifacts(&record.title)
        .into_iter()
        .map(|(name, detail)| CollectionActivityDetailRecord {
            name: name.to_string(),
            state: state.to_string(),
            detail: detail.to_string(),
        })
        .collect()
}

fn collection_activity_detail_summary(
    record: Option<&CollectionActivityRecord>,
    progress_state: Option<&CollectionProgressState>,
    detail_count: usize,
) -> String {
    let Some(record) = record else {
        return "Select a runtime collector to inspect expected or staged artifacts.".to_string();
    };
    let progress_entry = progress_state.and_then(|state| state.collectors.get(&record.title));
    if progress_entry
        .map(|entry| !entry.artifact_paths.is_empty())
        .unwrap_or(false)
    {
        return format!(
            "{} reported {} {}.",
            record.title,
            detail_count,
            pluralize(detail_count, "artifact", "artifacts")
        );
    }
    if progress_entry.map(|entry| entry.active).unwrap_or(false) {
        return format!(
            "{} is running. Showing expected artifact coverage.",
            record.title
        );
    }
    format!(
        "{} artifact coverage expected for this collector.",
        record.title
    )
}

fn expected_collection_artifacts(title: &str) -> Vec<(&'static str, &'static str)> {
    match title {
        "Registry Hives" => vec![
            ("C/Windows/System32/config/SYSTEM", "System hive"),
            ("C/Windows/System32/config/SOFTWARE", "Software hive"),
            ("C/Windows/System32/config/SAM", "Accounts hive"),
            ("C/Windows/System32/config/SECURITY", "Security hive"),
            ("C/Windows/System32/config/DEFAULT", "Default profile hive"),
            (
                "C/Windows/System32/config/COMPONENTS",
                "Servicing components hive",
            ),
            (
                "C/Windows/AppCompat/Programs/Amcache.hve",
                "AmCache program inventory hive",
            ),
            (
                "C/Boot/BCD or C/EFI/Microsoft/Boot/BCD",
                "Boot configuration data",
            ),
            ("C/Users/<user>/NTUSER.DAT", "User registry hive"),
            (
                "C/Users/<user>/AppData/Local/Microsoft/Windows/USRCLASS.DAT",
                "User class registry hive",
            ),
            (
                "Service profile NTUSER.DAT and USRCLASS.DAT",
                "LocalService, NetworkService, and systemprofile hives",
            ),
            (
                "Adjacent .LOG, .LOG1, .LOG2, .blf, .regtrans-ms",
                "Registry transaction logs and sidecars",
            ),
            (
                "$metadata/collectors/C/windows_registry/manifest.json",
                "Collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_registry/collection.log",
                "Collection log",
            ),
        ],
        "$UsnJrnl" => vec![
            (
                "C/$Extend/$UsnJrnl/$J.bin",
                "Collected raw USN journal bytes",
            ),
            (
                "$metadata/collectors/C/windows_usn_journal/manifest.json",
                "USN collection manifest",
            ),
        ],
        "Windows Event Logs" => vec![
            (
                "C/Windows/System32/winevt/Logs/*.evtx",
                "All available event log files from the VSS snapshot",
            ),
            (
                "C/Windows/System32/winevt/Logs/Archive-*.evtx",
                "Archived event log files when present",
            ),
            (
                "$metadata/collectors/C/windows_evtx/manifest.json",
                "EVTX collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_evtx/collection.log",
                "EVTX collection log",
            ),
        ],
        "SRUM" => vec![
            ("C/Windows/System32/sru/SRUDB.dat", "Main SRUM ESE database"),
            (
                "C/Windows/System32/sru/*.log, *.chk, *.jrs",
                "SRUM ESE companion files when present",
            ),
            (
                "C/Windows/System32/config/SOFTWARE",
                "Required registry hive for SRUM parser enrichment",
            ),
            (
                "C/Windows/System32/config/SYSTEM",
                "Recommended registry hive for SRUM context",
            ),
            (
                "$metadata/collectors/C/windows_srum/manifest.json",
                "SRUM collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_srum/collection.log",
                "SRUM collection log",
            ),
        ],
        "Prefetch" => vec![
            (
                "C/Windows/Prefetch/*.pf",
                "Application Prefetch files preserved from the VSS snapshot",
            ),
            (
                "C/Windows/Prefetch/NTOSBOOT-B00DFAAD.pf",
                "Boot Prefetch file when present",
            ),
            (
                "C/Windows/Prefetch/Layout.ini",
                "Layout guidance file from the snapshot when present",
            ),
            (
                "C/Windows/Prefetch/Ag*.db",
                "Superfetch or ReadyBoot databases when present in the Prefetch directory",
            ),
            (
                "$metadata/collectors/C/windows_prefetch/manifest.json",
                "Prefetch collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_prefetch/collection.log",
                "Prefetch collection log",
            ),
        ],
        "Browser Artifacts" => vec![
            (
                "C/Users/*/AppData/Local/Google/Chrome/User Data/*/History*, Cookies*, Web Data*, Login Data*",
                "Targeted Chrome profile databases and SQLite sidecars",
            ),
            (
                "C/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History*, Cookies*, Web Data*, Login Data*",
                "Targeted Edge Chromium profile databases and SQLite sidecars",
            ),
            (
                "C/Users/*/AppData/Local/*/User Data/*/Sessions and storage directories",
                "Chromium sessions, local storage, IndexedDB, file system, storage, databases, and service workers",
            ),
            (
                "C/Users/*/AppData/Local/*/User Data/*/Extensions/*/*/manifest.json",
                "Chromium extension manifests without package image/UI assets",
            ),
            (
                "C/Users/*/AppData/Roaming/Mozilla/Firefox/",
                "Firefox roaming profiles including places.sqlite, cookies, sessions, logins, preferences, and extensions",
            ),
            (
                "C/Users/*/AppData/Local/Mozilla/Firefox/",
                "Firefox local cache and runtime profile artifacts",
            ),
            (
                "C/Users/*/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/",
                "Legacy Edge package artifacts when present",
            ),
            (
                "C/Users/*/AppData/Roaming/Microsoft/Protect/",
                "Per-user DPAPI master key material for encrypted browser data",
            ),
            (
                "C/Users/*/AppData/Roaming/Microsoft/Credentials/",
                "Per-user credential material for browser secret recovery",
            ),
            (
                "C/Users/*/NTUSER.DAT and ntuser.dat.LOG*",
                "User registry hive and transaction logs for context and DPAPI support",
            ),
            (
                "C/Windows/System32/config/SYSTEM, SECURITY, SOFTWARE",
                "System hives needed for DPAPI and browser parser enrichment",
            ),
            (
                "$metadata/collectors/C/windows_browser_artifacts/manifest.json",
                "Browser artifact collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_browser_artifacts/collection.log",
                "Browser artifact collection log",
            ),
        ],
        "Jump Lists" => vec![
            (
                "C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms",
                "Per-user Automatic Jump Lists preserved from the VSS snapshot",
            ),
            (
                "C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms",
                "Per-user Custom Jump Lists preserved even when parsing is deferred",
            ),
            (
                "C/jump_lists_manifest.jsonl",
                "JSONL artifact manifest with source path, profile, artifact type, AppID candidate, timestamps, and SHA-256",
            ),
            (
                "$metadata/collectors/C/windows_jump_lists/manifest.json",
                "Jump Lists collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_jump_lists/collection.log",
                "Jump Lists collection log",
            ),
        ],
        "LNK Files" => vec![
            (
                "C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk",
                "Per-user Recent shortcuts preserved from the VSS snapshot",
            ),
            (
                "C/Users/*/AppData/Roaming/Microsoft/Office/Recent/*.lnk",
                "Per-user Office Recent shortcuts copied as raw LNK evidence",
            ),
            (
                "C/Users/*/Desktop/*.lnk",
                "Per-user desktop shortcuts preserved without resolving shortcut targets",
            ),
            (
                "C/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/**/*.lnk",
                "Per-user Start Menu shortcuts collected recursively while skipping reparse points",
            ),
            (
                "C/ProgramData/Microsoft/Windows/Start Menu/**/*.lnk",
                "Common Start Menu shortcuts preserved from the snapshot",
            ),
            (
                "C/lnk_manifest.jsonl",
                "JSONL artifact manifest with source path, VSS path, location, timestamps, attributes, and SHA-256",
            ),
            (
                "$metadata/collectors/C/windows_lnk/manifest.json",
                "LNK collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_lnk/collection.log",
                "LNK collection log",
            ),
        ],
        "$MFT" => vec![
            ("C/$MFT.bin", "Raw Master File Table bytes"),
            ("C/$MFT.bin.sha256", "SHA-256 hash for the collected $MFT"),
            (
                "$metadata/collectors/C/windows_mft/manifest.json",
                "$MFT collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_mft/collection.log",
                "$MFT collection log",
            ),
        ],
        "$LogFile" => vec![
            ("C/$LogFile.bin", "Raw NTFS transaction log bytes"),
            (
                "C/$LogFile.bin.sha256",
                "SHA-256 hash for the collected $LogFile",
            ),
            (
                "$metadata/collectors/C/windows_logfile/manifest.json",
                "$LogFile collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_logfile/collection.log",
                "$LogFile collection log",
            ),
        ],
        "INDX Records" => vec![
            (
                "C/INDX.rawpack",
                "Packed raw $I30 directory index attributes",
            ),
            (
                "C/INDX.rawpack.sha256",
                "SHA-256 hash for the collected INDX rawpack",
            ),
            (
                "$metadata/collectors/C/windows_indx/manifest.json",
                "INDX collection manifest",
            ),
            (
                "$metadata/collectors/C/windows_indx/collection.log",
                "INDX collection log",
            ),
        ],
        _ => Vec::new(),
    }
}

fn artifact_detail_for_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/manifest.json") {
        "Collection manifest".to_string()
    } else if lower.ends_with("/collection.log") {
        "Collection log".to_string()
    } else if lower.ends_with("$j.bin") {
        "Collected raw USN journal bytes".to_string()
    } else if lower.ends_with("$mft.bin") {
        "Raw Master File Table bytes".to_string()
    } else if lower.ends_with("$mft.bin.sha256") {
        "SHA-256 hash for collected $MFT".to_string()
    } else if lower.ends_with("$logfile.bin") {
        "Raw NTFS transaction log bytes".to_string()
    } else if lower.ends_with("$logfile.bin.sha256") {
        "SHA-256 hash for collected $LogFile".to_string()
    } else if lower.ends_with("indx.rawpack") {
        "Packed raw $I30 directory index attributes".to_string()
    } else if lower.ends_with("indx.rawpack.sha256") {
        "SHA-256 hash for collected INDX records".to_string()
    } else if lower.ends_with("$j.bin.metadata.json") {
        "USN collection metadata sidecar".to_string()
    } else if lower.ends_with("amcache.hve") {
        "AmCache program inventory hive".to_string()
    } else if lower.ends_with("ntuser.dat") {
        "User or service-profile registry hive".to_string()
    } else if lower.ends_with("usrclass.dat") {
        "User class registry hive".to_string()
    } else if lower.ends_with(".log")
        || lower.ends_with(".log1")
        || lower.ends_with(".log2")
        || lower.ends_with(".blf")
        || lower.ends_with(".regtrans-ms")
    {
        "Registry transaction log or sidecar".to_string()
    } else if lower.ends_with("/bcd") {
        "Boot configuration data".to_string()
    } else if lower.ends_with(".evtx") {
        "Windows Event Log file".to_string()
    } else if lower.contains("/windows/prefetch/") {
        if lower.ends_with(".pf") {
            "Windows Prefetch execution artifact".to_string()
        } else if lower.ends_with("layout.ini") {
            "Prefetch layout guidance file".to_string()
        } else if lower.ends_with(".db") {
            "Superfetch or ReadyBoot database from the Prefetch directory".to_string()
        } else {
            "Prefetch directory artifact".to_string()
        }
    } else if lower.contains("/windows/system32/sru/") {
        "SRUM database or ESE companion file".to_string()
    } else if lower.ends_with("/lnk_manifest.jsonl") {
        "LNK JSONL artifact manifest".to_string()
    } else if lower.ends_with(".lnk") {
        "Windows shortcut (LNK) file".to_string()
    } else if lower.ends_with("/jump_lists_manifest.jsonl") {
        "Jump Lists JSONL artifact manifest".to_string()
    } else if lower.ends_with(".automaticdestinations-ms")
        || lower.ends_with(".customdestinations-ms")
    {
        "Jump List file".to_string()
    } else if lower.contains("/google/chrome/user data/") {
        "Chrome browser profile artifact".to_string()
    } else if lower.contains("/microsoft/edge/user data/") {
        "Microsoft Edge browser profile artifact".to_string()
    } else if lower.contains("/mozilla/firefox/") {
        "Firefox browser profile artifact".to_string()
    } else if lower.contains("/microsoft/protect/")
        || lower.contains("/microsoft/credentials/")
        || lower.contains("/microsoft/vault/")
    {
        "DPAPI or credential support artifact".to_string()
    } else {
        "Collected artifact".to_string()
    }
}

fn artifact_name_for_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/manifest.json") {
        "Collection manifest".to_string()
    } else if lower.ends_with("/collection.log") {
        "Collection log".to_string()
    } else if lower.ends_with("$j.bin") {
        "$J.bin".to_string()
    } else if lower.ends_with("$j.bin.metadata.json") {
        "$J.bin metadata".to_string()
    } else if lower.ends_with("$mft.bin") {
        "$MFT.bin".to_string()
    } else if lower.ends_with("$mft.bin.sha256") {
        "$MFT.bin.sha256".to_string()
    } else if lower.ends_with("$logfile.bin") {
        "$LogFile.bin".to_string()
    } else if lower.ends_with("$logfile.bin.sha256") {
        "$LogFile.bin.sha256".to_string()
    } else if lower.ends_with("indx.rawpack") {
        "INDX.rawpack".to_string()
    } else if lower.ends_with("indx.rawpack.sha256") {
        "INDX.rawpack.sha256".to_string()
    } else if lower.ends_with("/lnk_manifest.jsonl") {
        "lnk_manifest.jsonl".to_string()
    } else if lower.ends_with("/jump_lists_manifest.jsonl") {
        "jump_lists_manifest.jsonl".to_string()
    } else if lower.contains("/windows/system32/sru/") {
        path.rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(path)
            .to_string()
    } else if lower.contains("/google/chrome/user data/")
        || lower.contains("/microsoft/edge/user data/")
        || lower.contains("/mozilla/firefox/")
        || lower.contains("/microsoft/protect/")
        || lower.contains("/microsoft/credentials/")
        || lower.contains("/microsoft/vault/")
    {
        path.rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(path)
            .to_string()
    } else if lower.ends_with(".evtx") {
        path.rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(path)
            .to_string()
    } else {
        path.rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(path)
            .to_string()
    }
}

fn build_runtime_activity_record(
    record: &CollectionCatalogRecord,
    phase: CollectionRuntimePhase,
    runtime_slot: usize,
    supported_source_count: usize,
    unsupported_source_count: usize,
    progress_state: Option<&CollectionProgressState>,
) -> CollectionActivityRecord {
    if supported_source_count == 0 {
        return CollectionActivityRecord {
            title: record.title.clone(),
            category: record.category.clone(),
            detail: ntfs_artifact_requirement_message().to_string(),
            status: "Blocked".to_string(),
            tone: CollectionActivityTone::Failed,
            active: false,
            show_progress: false,
            progress_value: 0.0,
            progress_text: String::new(),
            package_pending: false,
        };
    }

    let total_jobs = supported_source_count.max(1);
    let progress_entry = progress_state.and_then(|state| state.collectors.get(&record.title));
    let packaging_started = progress_state
        .map(|state| state.packaging_started)
        .unwrap_or(false);
    let default_running_detail = if unsupported_source_count == 0 {
        format!(
            "Collector is staging evidence from {} selected {} and packaging it for handoff.",
            supported_source_count,
            pluralize(supported_source_count, "source", "sources")
        )
    } else {
        format!(
            "Collector is staging evidence from {} selected {}. Some artifacts are being skipped on {} non-NTFS {}.",
            supported_source_count,
            pluralize(supported_source_count, "source", "sources"),
            unsupported_source_count,
            pluralize(unsupported_source_count, "source", "sources")
        )
    };

    let (
        detail,
        status,
        tone,
        active,
        show_progress,
        progress_value,
        progress_text,
        package_pending,
    ) = match phase {
        CollectionRuntimePhase::Idle => (
            if unsupported_source_count == 0 {
                if supported_source_count == 1 {
                    "Runtime collector available in Create Package on the selected source."
                        .to_string()
                } else {
                    format!(
                        "Runtime collector available in Create Package on {} selected {}.",
                        supported_source_count,
                        pluralize(supported_source_count, "source", "sources")
                    )
                }
            } else {
                format!(
                    "Collector will stage artifacts from {} selected {}. Some artifacts will be skipped on {} non-NTFS {}.",
                    supported_source_count,
                    pluralize(supported_source_count, "source", "sources"),
                    unsupported_source_count,
                    pluralize(unsupported_source_count, "source", "sources")
                )
            },
            "Ready".to_string(),
            CollectionActivityTone::Ready,
            false,
            false,
            0.0,
            String::new(),
            false,
        ),
        CollectionRuntimePhase::Running => {
            if let Some(entry) = progress_entry {
                let row_progress = collection_progress_value(entry, total_jobs);
                let row_progress_text = collection_progress_text(entry, total_jobs);
                if entry.active {
                    (
                        if entry.detail.is_empty() {
                            default_running_detail.clone()
                        } else {
                            entry.detail.clone()
                        },
                        "Running".to_string(),
                        CollectionActivityTone::Running,
                        true,
                        true,
                        row_progress.max(0.05),
                        if row_progress_text.is_empty() {
                            "In progress".to_string()
                        } else {
                            row_progress_text
                        },
                        false,
                    )
                } else if entry.completed_jobs >= total_jobs {
                    (
                        if packaging_started {
                            format!(
                                "Collector finished staging {} {} and is waiting for zip packaging.",
                                entry.staged_paths,
                                pluralize(entry.staged_paths, "path", "paths")
                            )
                        } else {
                            "Collector finished staging evidence and is waiting for package assembly."
                                .to_string()
                        },
                        "Staged".to_string(),
                        CollectionActivityTone::Ready,
                        false,
                        true,
                        1.0,
                        if entry.staged_paths > 0 {
                            format!(
                                "{} staged {}",
                                entry.staged_paths,
                                pluralize(entry.staged_paths, "path", "paths")
                            )
                        } else {
                            row_progress_text
                        },
                        true,
                    )
                } else {
                    (
                        "Collector is queued for another selected source volume.".to_string(),
                        "Queued".to_string(),
                        CollectionActivityTone::Queued,
                        false,
                        true,
                        row_progress,
                        row_progress_text,
                        false,
                    )
                }
            } else {
                (
                    if runtime_slot == 0 {
                        default_running_detail.clone()
                    } else {
                        "Selected runtime collector is queued behind the active collection task."
                            .to_string()
                    },
                    if runtime_slot == 0 {
                        "Running".to_string()
                    } else {
                        "Queued".to_string()
                    },
                    if runtime_slot == 0 {
                        CollectionActivityTone::Running
                    } else {
                        CollectionActivityTone::Queued
                    },
                    runtime_slot == 0,
                    runtime_slot == 0,
                    if runtime_slot == 0 { 0.05 } else { 0.0 },
                    if runtime_slot == 0 {
                        "Starting".to_string()
                    } else {
                        String::new()
                    },
                    false,
                )
            }
        }
        CollectionRuntimePhase::Succeeded => (
            if let Some(entry) = progress_entry {
                if entry.staged_paths > 0 {
                    format!(
                        "Packaged {} staged {} successfully.",
                        entry.staged_paths,
                        pluralize(entry.staged_paths, "path", "paths")
                    )
                } else if unsupported_source_count == 0 {
                    format!(
                        "Collector finished and packaged evidence from {} selected {} successfully.",
                        supported_source_count,
                        pluralize(supported_source_count, "source", "sources")
                    )
                } else {
                    format!(
                        "Collector finished and packaged evidence from {} selected {}. Some artifacts were skipped on {} non-NTFS {}.",
                        supported_source_count,
                        pluralize(supported_source_count, "source", "sources"),
                        unsupported_source_count,
                        pluralize(unsupported_source_count, "source", "sources")
                    )
                }
            } else {
                format!(
                    "Collector finished and packaged evidence from {} selected {} successfully.",
                    supported_source_count,
                    pluralize(supported_source_count, "source", "sources")
                )
            },
            "Packaged".to_string(),
            CollectionActivityTone::Complete,
            false,
            true,
            1.0,
            progress_entry
                .map(|entry| {
                    if entry.staged_paths > 0 {
                        format!(
                            "{} staged {}",
                            entry.staged_paths,
                            pluralize(entry.staged_paths, "path", "paths")
                        )
                    } else {
                        "Packaged".to_string()
                    }
                })
                .unwrap_or_else(|| "Packaged".to_string()),
            false,
        ),
        CollectionRuntimePhase::Failed => {
            if let Some(entry) = progress_entry {
                let row_progress = collection_progress_value(entry, total_jobs);
                let row_progress_text = collection_progress_text(entry, total_jobs);
                if entry.completed_jobs >= total_jobs {
                    (
                        format!(
                            "Collector staged {} before the package run failed later.",
                            if entry.staged_paths > 0 {
                                format!(
                                    "{} {}",
                                    entry.staged_paths,
                                    pluralize(entry.staged_paths, "path", "paths")
                                )
                            } else {
                                "its evidence".to_string()
                            }
                        ),
                        "Staged".to_string(),
                        CollectionActivityTone::Ready,
                        false,
                        true,
                        1.0,
                        if entry.staged_paths > 0 {
                            format!(
                                "{} staged {}",
                                entry.staged_paths,
                                pluralize(entry.staged_paths, "path", "paths")
                            )
                        } else {
                            row_progress_text
                        },
                        false,
                    )
                } else {
                    (
                        if entry.detail.is_empty() {
                            "Collector did not complete. Review the technical log below for the runtime failure."
                                .to_string()
                        } else {
                            format!(
                                "{} Collection stopped before this collector finished.",
                                entry.detail
                            )
                        },
                        "Failed".to_string(),
                        CollectionActivityTone::Failed,
                        false,
                        true,
                        row_progress.max(0.05),
                        if row_progress_text.is_empty() {
                            "Interrupted".to_string()
                        } else {
                            row_progress_text
                        },
                        false,
                    )
                }
            } else {
                (
                    if runtime_slot == 0 {
                        "Collector did not complete. Review the technical log below for the runtime failure."
                            .to_string()
                    } else {
                        "Selected runtime collector remained queued because the active collection failed."
                            .to_string()
                    },
                    if runtime_slot == 0 {
                        "Failed".to_string()
                    } else {
                        "Queued".to_string()
                    },
                    if runtime_slot == 0 {
                        CollectionActivityTone::Failed
                    } else {
                        CollectionActivityTone::Queued
                    },
                    false,
                    runtime_slot == 0,
                    if runtime_slot == 0 { 0.05 } else { 0.0 },
                    if runtime_slot == 0 {
                        "Interrupted".to_string()
                    } else {
                        String::new()
                    },
                    false,
                )
            }
        }
    };

    CollectionActivityRecord {
        title: record.title.clone(),
        category: record.category.clone(),
        detail,
        status,
        tone,
        active,
        show_progress,
        progress_value,
        progress_text,
        package_pending,
    }
}

fn collection_progress_value(entry: &CollectionCollectorProgress, total_jobs: usize) -> f32 {
    if total_jobs == 0 {
        return 0.0;
    }

    ((entry.completed_jobs as f32
        + if entry.active {
            entry.current_job_progress.clamp(0.0, 1.0)
        } else {
            0.0
        })
        / total_jobs as f32)
        .clamp(0.0, 1.0)
}

fn collection_progress_text(entry: &CollectionCollectorProgress, total_jobs: usize) -> String {
    let mut parts = Vec::new();
    if total_jobs > 1 {
        parts.push(format!(
            "{} of {} sources complete",
            entry.completed_jobs, total_jobs
        ));
    }
    if entry.active && total_jobs > 1 {
        if let Some(volume) = entry.current_volume.as_deref() {
            parts.push(volume.to_string());
        }
    }
    if !entry.progress_text.trim().is_empty() {
        parts.push(entry.progress_text.clone());
    }
    parts.join(" • ")
}

fn build_collection_activity_summary(
    selected_count: usize,
    runtime_selected: usize,
    scope_only_selected: usize,
    phase: CollectionRuntimePhase,
    supported_source_count: usize,
    unsupported_source_count: usize,
    progress_state: Option<&CollectionProgressState>,
) -> String {
    if selected_count == 0 {
        return "No evidence groups are selected yet.".to_string();
    }

    if runtime_selected == 0 {
        return format!(
            "{} selected {} remain scope-only. Add a runtime collector to Create Package.",
            selected_count,
            pluralize(selected_count, "surface", "surfaces"),
        );
    }

    if supported_source_count == 0 {
        return format!(
            "{} runtime {} {} NTFS-backed sources. {} selected {} remain scope-only until their collectors ship. Some artifacts will be skipped on the current non-NTFS selection.",
            runtime_selected,
            pluralize(runtime_selected, "collector", "collectors"),
            if runtime_selected == 1 {
                "requires"
            } else {
                "require"
            },
            scope_only_selected,
            pluralize(scope_only_selected, "surface", "surfaces"),
        );
    }

    let source_clause = format_supported_source_clause(supported_source_count);
    let unsupported_clause_idle = if unsupported_source_count == 0 {
        String::new()
    } else {
        format!(
            " Some artifacts will be skipped on {} non-NTFS {}.",
            unsupported_source_count,
            pluralize(unsupported_source_count, "source", "sources")
        )
    };
    let unsupported_clause_past = if unsupported_source_count == 0 {
        String::new()
    } else {
        format!(
            " Some artifacts were skipped on {} non-NTFS {}.",
            unsupported_source_count,
            pluralize(unsupported_source_count, "source", "sources")
        )
    };

    match phase {
        CollectionRuntimePhase::Idle => format!(
            "{} runtime {} ready{}. {} selected {} remain scope-only until their collectors ship.{}",
            runtime_selected,
            pluralize(runtime_selected, "collector", "collectors"),
            source_clause,
            scope_only_selected,
            pluralize(scope_only_selected, "surface", "surfaces"),
            unsupported_clause_idle,
        ),
        CollectionRuntimePhase::Running => {
            if let Some(progress) = progress_state {
                let completed_tasks = progress.completed_jobs.min(progress.runtime_jobs);
                if progress.packaging_started {
                    format!(
                        "{} of {} runtime collection tasks complete. Packaging {} staged {} into the zip. {} selected {} remain scope-only and are not collected yet.{}",
                        completed_tasks,
                        progress.runtime_jobs.max(runtime_selected),
                        progress.packaging_entry_count,
                        pluralize(progress.packaging_entry_count, "entry", "entries"),
                        scope_only_selected,
                        pluralize(scope_only_selected, "surface", "surfaces"),
                        unsupported_clause_idle,
                    )
                } else if let Some(active_title) = progress.current_collector.as_ref() {
                    format!(
                        "{} of {} runtime collection tasks complete. {} in progress{}. {} selected {} remain scope-only and are not collected yet.{}",
                        completed_tasks,
                        progress.runtime_jobs.max(runtime_selected),
                        active_title,
                        source_clause,
                        scope_only_selected,
                        pluralize(scope_only_selected, "surface", "surfaces"),
                        unsupported_clause_idle,
                    )
                } else {
                    format!(
                        "{} runtime {} in flight{}. {} selected {} remain scope-only and are not collected yet.{}",
                        runtime_selected,
                        pluralize(runtime_selected, "collector", "collectors"),
                        source_clause,
                        scope_only_selected,
                        pluralize(scope_only_selected, "surface", "surfaces"),
                        unsupported_clause_idle,
                    )
                }
            } else {
                format!(
                    "{} runtime {} in flight{}. {} selected {} remain scope-only and are not collected yet.{}",
                    runtime_selected,
                    pluralize(runtime_selected, "collector", "collectors"),
                    source_clause,
                    scope_only_selected,
                    pluralize(scope_only_selected, "surface", "surfaces"),
                    unsupported_clause_idle,
                )
            }
        }
        CollectionRuntimePhase::Succeeded => {
            if let Some(progress) = progress_state {
                format!(
                    "{} runtime collection tasks completed across {} {}{}. {} selected {} remain scope-only and were not packaged.{}",
                    progress.runtime_jobs.max(runtime_selected),
                    runtime_selected,
                    pluralize(runtime_selected, "collector", "collectors"),
                    source_clause,
                    scope_only_selected,
                    pluralize(scope_only_selected, "surface", "surfaces"),
                    unsupported_clause_past,
                )
            } else {
                format!(
                    "{} runtime {} completed{}. {} selected {} remain scope-only and were not packaged.{}",
                    runtime_selected,
                    pluralize(runtime_selected, "collector", "collectors"),
                    source_clause,
                    scope_only_selected,
                    pluralize(scope_only_selected, "surface", "surfaces"),
                    unsupported_clause_past,
                )
            }
        }
        CollectionRuntimePhase::Failed => {
            if let Some(progress) = progress_state {
                if let Some(active_title) = progress.current_collector.as_ref() {
                    format!(
                        "{} of {} runtime collection tasks completed before {} failed{}. {} selected {} remain scope-only; review the technical log for the runtime error.{}",
                        progress.completed_jobs.min(progress.runtime_jobs),
                        progress.runtime_jobs.max(runtime_selected),
                        active_title,
                        source_clause,
                        scope_only_selected,
                        pluralize(scope_only_selected, "surface", "surfaces"),
                        unsupported_clause_idle,
                    )
                } else {
                    format!(
                        "{} runtime {} stopped or failed{}. {} selected {} remain scope-only; review the technical log for the runtime error.{}",
                        runtime_selected,
                        pluralize(runtime_selected, "collector", "collectors"),
                        source_clause,
                        scope_only_selected,
                        pluralize(scope_only_selected, "surface", "surfaces"),
                        unsupported_clause_idle,
                    )
                }
            } else {
                format!(
                    "{} runtime {} stopped or failed{}. {} selected {} remain scope-only; review the technical log for the runtime error.{}",
                    runtime_selected,
                    pluralize(runtime_selected, "collector", "collectors"),
                    source_clause,
                    scope_only_selected,
                    pluralize(scope_only_selected, "surface", "surfaces"),
                    unsupported_clause_idle,
                )
            }
        }
    }
}

fn pluralize<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn ntfs_artifact_requirement_message() -> &'static str {
    "Some selected artifacts require NTFS-backed sources. Select at least one NTFS volume to collect them."
}

fn ntfs_artifact_status_message() -> &'static str {
    "Select at least one NTFS source to collect NTFS-only artifacts."
}

fn refresh_collection_drives(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) {
    let drives = available_collection_drives();
    let selected_volumes = {
        let mut state_guard = state.lock().expect("desktop state poisoned");
        state_guard.selected_collection_volumes = normalized_selected_volumes_or_default(
            &state_guard.selected_collection_volumes,
            &drives,
        );
        state_guard.selected_collection_volumes.clone()
    };

    let items = drives
        .iter()
        .map(|drive| drive.to_ui_item(&selected_volumes))
        .collect::<Vec<_>>();
    app.set_collection_drives(Rc::new(VecModel::from(items)).into());

    let previous_supported = app.get_collection_source_supported();
    let source_state = collection_source_state(&selected_volumes, &drives);
    app.set_collection_source_supported(source_state.supported());
    app.set_collection_source_summary(source_state.summary.clone().into());

    if app.get_collection_running() {
        return;
    }

    if !source_state.supported() {
        app.set_collection_status(ntfs_artifact_status_message().into());
    } else if !previous_supported {
        app.set_collection_status("Ready to create an evidence package.".into());
    }
}

fn persist_settings(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> Result<()> {
    let settings = settings_from_app(app, state);
    let settings_path = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.settings_path.clone()
    };
    save_settings(&settings_path, &settings)
}

fn settings_from_app(app: &AppWindow, state: &Arc<Mutex<DesktopState>>) -> DesktopSettings {
    let theme = app.global::<ThemeTokens>();
    let collection_volumes = {
        let state_guard = state.lock().expect("desktop state poisoned");
        state_guard.selected_collection_volumes.clone()
    };
    DesktopSettings {
        theme_mode: theme.get_theme_mode(),
        collection_profile: app.get_collection_profile(),
        collection_volumes,
        collection_archive_path: app.get_collection_archive_path().to_string(),
        collection_usn_mode: app.get_collection_usn_mode(),
        collection_usn_chunk_index: app.get_collection_usn_chunk_index(),
        collection_sparse: app.get_collection_sparse(),
        collection_elevate: app.get_collection_elevate(),
        custom_usn_selected: app.get_custom_usn_selected(),
        parse_archive_path: app.get_parse_archive_path().to_string(),
        parse_output_path: app.get_parse_output_path().to_string(),
        use_elasticsearch: app.get_use_elasticsearch(),
        elasticsearch_url: app.get_elasticsearch_url().to_string(),
        elasticsearch_username: app.get_elasticsearch_username().to_string(),
        elasticsearch_index: app.get_elasticsearch_index().to_string(),
        elasticsearch_insecure: app.get_elasticsearch_insecure(),
    }
}

fn resolve_settings_path() -> PathBuf {
    runtime_support::app_settings_path()
}

fn load_settings(path: &Path) -> Result<DesktopSettings> {
    let bytes =
        fs::read(path).with_context(|| format!("read desktop settings {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decode desktop settings {}", path.display()))
}

fn save_settings(path: &Path, settings: &DesktopSettings) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create desktop settings directory {}", parent.display()))?;
    }

    let bytes = serde_json::to_vec_pretty(settings)?;
    fs::write(path, bytes).with_context(|| format!("write desktop settings {}", path.display()))
}

fn append_collection_log(app: &AppWindow, line: &str) {
    append_technical_log(app, "collection-ui", line);
}

fn append_parse_log(app: &AppWindow, line: &str) {
    append_technical_log(app, "parse-ui", line);
}

fn append_technical_log(app: &AppWindow, source: &str, line: &str) {
    if let Err(error) = runtime_support::append_technical_log(source, line) {
        set_technical_log_text(app, format!("Technical log unavailable: {error}"));
        return;
    }
    sync_technical_logs(app);
}

fn sync_technical_logs(app: &AppWindow) {
    match runtime_support::read_technical_log_tail(MAX_LOG_LINES) {
        Ok(log) => set_technical_log_text(app, log),
        Err(error) => set_technical_log_text(app, format!("Technical log unavailable: {error}")),
    }
}

fn set_technical_log_text(app: &AppWindow, value: String) {
    app.set_collection_log(value.clone().into());
    app.set_parse_log(value.into());
}

fn event_title(event: &ParseEvent) -> String {
    match event {
        ParseEvent::Starting { input, .. } => format!("Starting {}", file_name_or_path(input)),
        ParseEvent::Extracting { input, .. } => format!("Extracting {}", file_name_or_path(input)),
        ParseEvent::PlansResolved { total_plans, .. } => {
            format!("Resolved {} selected parser plans", total_plans)
        }
        ParseEvent::ParserFamilyStarted {
            name, index, total, ..
        } => {
            format!("Family {}/{} {}", index, total, name)
        }
        ParseEvent::PlanStarted {
            parser,
            artifact,
            index,
            total,
        } => format!("Plan {}/{} {} -> {}", index, total, parser, artifact),
        ParseEvent::PlanFinished {
            parser,
            artifact,
            status,
            ..
        } => format!(
            "{} -> {} [{}]",
            parser,
            artifact,
            status.to_ascii_uppercase()
        ),
        ParseEvent::ManifestWritten { path } => format!("Manifest {}", file_name_or_path(path)),
        ParseEvent::Completed { manifest_path, .. } => {
            format!("Completed {}", file_name_or_path(manifest_path))
        }
    }
}

fn event_log_line(event: &ParseEvent) -> String {
    match event {
        ParseEvent::Starting { input, output_dir } => format!(
            "Starting parse for {} -> {}",
            display_path(input),
            display_path(output_dir)
        ),
        ParseEvent::Extracting { input, destination } => format!(
            "Extracting {} into {}",
            display_path(input),
            display_path(destination)
        ),
        ParseEvent::PlansResolved {
            family_count,
            total_plans,
        } => format!(
            "Resolved {} parser families and {} selected plans",
            family_count, total_plans
        ),
        ParseEvent::ParserFamilyStarted {
            name,
            index,
            total,
            planned_items,
        } => format!(
            "Family {}/{} {} with {} runnable plans",
            index, total, name, planned_items
        ),
        ParseEvent::PlanStarted {
            parser,
            artifact,
            index,
            total,
        } => format!("Plan {}/{} {} -> {}", index, total, parser, artifact),
        ParseEvent::PlanFinished {
            parser,
            artifact,
            status,
            output_path,
            error,
            ..
        } => {
            let mut line = format!(
                "{} -> {} [{}]",
                parser,
                artifact,
                status.to_ascii_uppercase()
            );
            if let Some(path) = output_path.as_ref() {
                line.push_str(&format!(" {}", display_path(path)));
            }
            if let Some(error_text) = error.as_ref() {
                line.push_str(&format!(" {}", error_text));
            }
            line
        }
        ParseEvent::ManifestWritten { path } => {
            format!("Manifest written {}", display_path(path))
        }
        ParseEvent::Completed {
            manifest_path,
            total_entries,
            exported_records,
        } => {
            let mut line = format!(
                "Completed with {} manifest entries {}",
                total_entries,
                display_path(manifest_path)
            );
            if let Some(exported) = exported_records {
                line.push_str(&format!(" exported {}", exported));
            }
            line
        }
    }
}

fn build_inspection_log(input: &Path, count: usize) -> String {
    if count == 0 {
        return format!(
            "Inspect {}\nNo supported artifact groups were detected in the selected archive.",
            display_path(input)
        );
    }

    format!(
        "Inspect {}\nDetected {} supported artifact groups. Toggle the rows below to control what gets parsed.",
        display_path(input),
        count
    )
}

fn detect_system_dark() -> bool {
    detect_system_dark_platform().unwrap_or(false)
}

#[cfg(windows)]
fn detect_system_dark_platform() -> Option<bool> {
    let mut value = 1u32;
    let mut value_size = size_of_val(&value) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
            w!("AppsUseLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast()),
            Some(&mut value_size),
        )
    };

    (status == ERROR_SUCCESS).then_some(value == 0)
}

#[cfg(not(windows))]
fn detect_system_dark_platform() -> Option<bool> {
    None
}

#[cfg(windows)]
fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn decode_wide(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn normalized_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalized_path(value: String) -> Option<PathBuf> {
    normalized_string(value).map(PathBuf::from)
}

fn normalized_drive_label(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let first = trimmed.chars().find(|ch| ch.is_ascii_alphabetic())?;
    Some(format!("{}:", first.to_ascii_uppercase()))
}

fn normalized_selected_volumes_or_default(
    values: &[String],
    drives: &[CollectionDriveRecord],
) -> Vec<String> {
    let mut selected = Vec::new();

    for value in values {
        if let Some(volume) = normalized_drive_label(value) {
            if drives.iter().any(|drive| drive.volume == volume)
                && !selected
                    .iter()
                    .any(|selected_volume| selected_volume == &volume)
            {
                selected.push(volume);
            }
        }
    }

    if selected.is_empty() {
        if let Some(first_drive) = drives.first() {
            selected.push(first_drive.volume.clone());
        }
    }

    order_selected_collection_volumes(&mut selected, drives);
    selected
}

fn order_selected_collection_volumes(values: &mut Vec<String>, drives: &[CollectionDriveRecord]) {
    values.sort_by_key(|value| {
        drives
            .iter()
            .position(|drive| drive.volume == *value)
            .unwrap_or(usize::MAX)
    });
}

fn toggle_selected_collection_volume(
    values: &mut Vec<String>,
    volume: &str,
    drives: &[CollectionDriveRecord],
) {
    if let Some(position) = values.iter().position(|selected| selected == volume) {
        if values.len() > 1 {
            values.remove(position);
        }
    } else {
        values.push(volume.to_string());
    }

    *values = normalized_selected_volumes_or_default(values, drives);
}

fn format_selected_volumes(values: &[String]) -> String {
    if values.len() == 1 {
        values
            .first()
            .cloned()
            .unwrap_or_else(|| "volume".to_string())
    } else {
        format!("{} volumes ({})", values.len(), values.join(", "))
    }
}

fn format_supported_source_clause(count: usize) -> String {
    if count > 1 {
        format!(
            " across {} selected source {}",
            count,
            pluralize(count, "volume", "volumes")
        )
    } else {
        String::new()
    }
}

fn format_drive_with_filesystem(drive: &CollectionDriveRecord) -> String {
    let filesystem = if drive.filesystem.trim().is_empty() {
        "UNK"
    } else {
        drive.filesystem.trim()
    };
    format!("{} ({})", drive.volume, filesystem)
}

fn selected_collection_drive<'a>(
    selected_volume: &str,
    drives: &'a [CollectionDriveRecord],
) -> Option<&'a CollectionDriveRecord> {
    drives.iter().find(|drive| drive.volume == selected_volume)
}

fn collection_source_state(
    selected_volumes: &[String],
    drives: &[CollectionDriveRecord],
) -> CollectionSourceState {
    let mut selected_drives = selected_volumes
        .iter()
        .filter_map(|volume| selected_collection_drive(volume, drives))
        .collect::<Vec<_>>();
    selected_drives.sort_by_key(|drive| {
        drives
            .iter()
            .position(|candidate| candidate.volume == drive.volume)
            .unwrap_or(usize::MAX)
    });

    if selected_drives.is_empty() {
        return CollectionSourceState {
            supported_volumes: Vec::new(),
            unsupported_volumes: Vec::new(),
            summary: "No readable source volume is currently available.".to_string(),
        };
    }

    let mut supported_volumes = Vec::new();
    let mut unsupported_volumes = Vec::new();
    for drive in selected_drives {
        if drive.filesystem.trim().eq_ignore_ascii_case("NTFS") {
            supported_volumes.push(drive.volume.clone());
        } else {
            unsupported_volumes.push(format_drive_with_filesystem(drive));
        }
    }

    let summary = if supported_volumes.is_empty() {
        if unsupported_volumes.len() == 1 {
            format!(
                "{} selected. Some artifacts will be skipped.",
                unsupported_volumes[0]
            )
        } else {
            format!(
                "{} non-NTFS sources selected. Some artifacts will be skipped.",
                unsupported_volumes.len()
            )
        }
    } else if unsupported_volumes.is_empty() {
        if supported_volumes.len() == 1 {
            format!(
                "{} selected and ready for collection.",
                supported_volumes[0]
            )
        } else {
            format!(
                "{} selected volumes ready for collection.",
                supported_volumes.len()
            )
        }
    } else if unsupported_volumes.len() == 1 {
        format!(
            "{} selected {} ready. Some artifacts will be skipped on {}.",
            supported_volumes.len(),
            pluralize(supported_volumes.len(), "source", "sources"),
            unsupported_volumes[0]
        )
    } else {
        format!(
            "{} selected {} ready. Some artifacts will be skipped on {} non-NTFS sources.",
            supported_volumes.len(),
            pluralize(supported_volumes.len(), "source", "sources"),
            unsupported_volumes.len()
        )
    };

    CollectionSourceState {
        supported_volumes,
        unsupported_volumes,
        summary,
    }
}

fn available_collection_drives() -> Vec<CollectionDriveRecord> {
    let mut drives = Vec::new();
    if let Some(main_drive) = env::var("SystemDrive")
        .ok()
        .or_else(|| env::var("HOMEDRIVE").ok())
        .and_then(|value| normalized_drive_label(&value))
        .and_then(|volume| collection_drive_record(volume))
    {
        drives.push(main_drive);
    }

    for letter in b'A'..=b'Z' {
        let volume = format!("{}:", letter as char);
        if let Some(record) = collection_drive_record(volume) {
            if !drives.iter().any(|drive| drive.volume == record.volume) {
                drives.push(record);
            }
        }
    }

    if drives.is_empty() {
        drives.push(CollectionDriveRecord {
            volume: "C:".to_string(),
            filesystem: "UNK".to_string(),
        });
    }

    drives
}

fn collection_drive_record(volume: String) -> Option<CollectionDriveRecord> {
    let root = format!("{}\\", volume);
    if !Path::new(&root).exists() {
        return None;
    }

    Some(CollectionDriveRecord {
        volume,
        filesystem: collection_drive_filesystem_badge(&root),
    })
}

fn collection_drive_filesystem_badge(root: &str) -> String {
    detect_collection_drive_filesystem(root).unwrap_or_else(|| "UNK".to_string())
}

#[cfg(windows)]
fn detect_collection_drive_filesystem(root: &str) -> Option<String> {
    let root_wide = encode_wide(root);
    let mut serial_number = 0u32;
    let mut maximum_component_length = 0u32;
    let mut file_system_flags = 0u32;
    let mut file_system_name = [0u16; 64];

    unsafe {
        GetVolumeInformationW(
            PCWSTR(root_wide.as_ptr()),
            None,
            Some(&mut serial_number),
            Some(&mut maximum_component_length),
            Some(&mut file_system_flags),
            Some(&mut file_system_name),
        )
    }
    .ok()?;

    let filesystem = decode_wide(&file_system_name);
    let trimmed = filesystem.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(not(windows))]
fn detect_collection_drive_filesystem(_root: &str) -> Option<String> {
    None
}

fn normalize_collection_output_dir(value: &str, default_dir: &Path) -> PathBuf {
    let Some(path) = normalized_path(value.to_string()) else {
        return default_dir.to_path_buf();
    };

    if looks_like_zip_path(value) {
        return default_dir.to_path_buf();
    }

    path
}

fn looks_like_zip_path(value: &str) -> bool {
    Path::new(value)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
}

fn refresh_collection_output_filename(app: &AppWindow) {
    app.set_collection_output_filename(
        collection_output_filename(app.get_collection_profile()).into(),
    );
}

fn collection_output_filename(profile: i32) -> String {
    let hostname = host_name_for_archive();
    let identity = archive_domain_or_user(&hostname);
    let version = sanitize_archive_component(env!("CARGO_PKG_VERSION"), "unknown-version");
    format!(
        "holo-forensics-{}-{}-{}-{}.zip",
        collection_profile_slug(profile),
        version,
        sanitize_archive_component(&hostname, "unknown-host"),
        identity
    )
}

fn collection_profile_slug(profile: i32) -> &'static str {
    match profile.clamp(0, 2) {
        1 => "triage",
        2 => "custom",
        _ => "full",
    }
}

fn host_name_for_archive() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn archive_domain_or_user(hostname: &str) -> String {
    let hostname_token = sanitize_archive_component(hostname, "unknown-host");

    if let Ok(value) = env::var("USERDNSDOMAIN") {
        if !value.trim().is_empty() {
            return sanitize_archive_component(&value, "unknown-domain");
        }
    }

    if let Ok(value) = env::var("USERDOMAIN") {
        if !value.trim().is_empty() {
            let domain = sanitize_archive_component(&value, "unknown-domain");
            if domain != hostname_token {
                return domain;
            }
        }
    }

    if let Ok(value) = env::var("USERNAME") {
        if !value.trim().is_empty() {
            return sanitize_archive_component(&value, "unknown-user");
        }
    }

    "unknown-user".to_string()
}

fn sanitize_archive_component(value: &str, fallback: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_separator = false;

    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
            continue;
        }

        if matches!(ch, '-' | '_' | '.') {
            if !last_was_separator {
                sanitized.push(ch);
                last_was_separator = true;
            }
            continue;
        }

        if !last_was_separator {
            sanitized.push('-');
            last_was_separator = true;
        }
    }

    let sanitized = sanitized.trim_matches(|ch| ch == '-' || ch == '_' || ch == '.');
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized.to_string()
    }
}

fn schedule_technical_log_refresh(app: slint::Weak<AppWindow>) {
    slint::Timer::single_shot(Duration::from_millis(750), move || {
        let Some(app) = app.upgrade() else {
            return;
        };
        sync_technical_logs(&app);
        schedule_technical_log_refresh(app.as_weak());
    });
}

fn schedule_collection_drive_refresh(app: slint::Weak<AppWindow>, state: Arc<Mutex<DesktopState>>) {
    slint::Timer::single_shot(Duration::from_secs(2), move || {
        let Some(app) = app.upgrade() else {
            return;
        };
        if !app.get_collection_running() {
            refresh_collection_drives(&app, &state);
            refresh_collection_activity(&app, &state);
        }
        schedule_collection_drive_refresh(app.as_weak(), Arc::clone(&state));
    });
}

fn schedule_collection_activity_pulse(app: slint::Weak<AppWindow>) {
    slint::Timer::single_shot(Duration::from_millis(650), move || {
        let Some(app) = app.upgrade() else {
            return;
        };
        if app.get_collection_running() {
            app.set_collection_activity_pulse(!app.get_collection_activity_pulse());
        } else if app.get_collection_activity_pulse() {
            app.set_collection_activity_pulse(false);
        }
        schedule_collection_activity_pulse(app.as_weak());
    });
}

fn schedule_window_chrome_theme_refresh(app: slint::Weak<AppWindow>) {
    #[cfg(windows)]
    schedule_window_chrome_theme_refresh_with_retry(app, 6);
}

#[cfg(windows)]
fn schedule_window_chrome_theme_refresh_with_retry(
    app: slint::Weak<AppWindow>,
    attempts_remaining: u8,
) {
    slint::Timer::single_shot(Duration::from_millis(60), move || {
        let Some(app) = app.upgrade() else {
            return;
        };

        if apply_window_chrome_theme(&app).is_err() && attempts_remaining > 1 {
            schedule_window_chrome_theme_refresh_with_retry(app.as_weak(), attempts_remaining - 1);
        }
    });
}

#[cfg(windows)]
fn apply_window_chrome_theme(app: &AppWindow) -> Result<()> {
    let theme = app.global::<ThemeTokens>();
    let dark_mode = theme.get_dark();
    let caption_color = colorref(theme.get_hero());
    let text_color = colorref(theme.get_hero_foreground());

    let raw_window_handle = app
        .window()
        .window_handle()
        .window_handle()
        .map_err(|error| anyhow!("obtain native window handle: {error}"))?
        .as_raw();

    let hwnd = match raw_window_handle {
        RawWindowHandle::Win32(handle) => HWND(handle.hwnd.get() as *mut core::ffi::c_void),
        _ => return Ok(()),
    };

    let dark_value = BOOL::from(dark_mode);
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark_value as *const _ as _,
            size_of_val(&dark_value) as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            &caption_color as *const _ as _,
            size_of_val(&caption_color) as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_TEXT_COLOR,
            &text_color as *const _ as _,
            size_of_val(&text_color) as u32,
        );
    }

    Ok(())
}

#[cfg(windows)]
fn colorref(color: slint::Color) -> u32 {
    u32::from(color.red()) | (u32::from(color.green()) << 8) | (u32::from(color.blue()) << 16)
}

fn browse_for_directory(initial_dir: &Path) -> Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        let initial_dir = initial_dir.to_path_buf();
        let picker_result = std::thread::spawn(move || {
            browse_for_directory_windows(&initial_dir).map_err(|error| error.to_string())
        })
        .join()
        .map_err(|_| anyhow!("destination folder picker thread panicked"))?;

        return picker_result.map_err(|error| anyhow!(error));
    }

    #[cfg(not(windows))]
    {
        let _ = initial_dir;
        Err(anyhow!(
            "native destination folder picker is only implemented on Windows"
        ))
    }
}

fn open_external_url(url: &str) -> Result<()> {
    #[cfg(windows)]
    {
        return open_external_url_windows(url);
    }

    #[cfg(not(windows))]
    {
        let _ = url;
        Err(anyhow!(
            "opening external links is only implemented on Windows"
        ))
    }
}

#[cfg(windows)]
fn open_external_url_windows(url: &str) -> Result<()> {
    let operation = HSTRING::from("open");
    let target = HSTRING::from(url);
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    if result.0 as isize <= 32 {
        return Err(anyhow!("launch browser for {url}"));
    }

    Ok(())
}

#[cfg(windows)]
fn browse_for_directory_windows(initial_dir: &Path) -> Result<Option<PathBuf>> {
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .context("initialize COM for destination folder picker")?;
    }
    let _com_apartment = ComApartment;

    let dialog: IFileOpenDialog =
        unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
            .context("create Windows Shell folder picker")?;
    let options = unsafe { dialog.GetOptions() }.context("read folder picker options")?
        | FOS_PICKFOLDERS
        | FOS_FORCEFILESYSTEM
        | FOS_PATHMUSTEXIST
        | FOS_NOCHANGEDIR;
    unsafe {
        dialog
            .SetOptions(options)
            .context("configure folder picker")?;
        dialog
            .SetTitle(w!("Select evidence package destination folder"))
            .context("set folder picker title")?;
        dialog
            .SetOkButtonLabel(w!("Use This Folder"))
            .context("set folder picker action label")?;
    }

    if initial_dir.exists() {
        let initial_path = HSTRING::from(display_path(initial_dir));
        if let Ok(initial_item) =
            unsafe { SHCreateItemFromParsingName::<_, _, IShellItem>(&initial_path, None) }
        {
            let _ = unsafe { dialog.SetDefaultFolder(&initial_item) };
            let _ = unsafe { dialog.SetFolder(&initial_item) };
        }
    }

    match unsafe { dialog.Show(None) } {
        Ok(()) => {
            let selected_item = unsafe { dialog.GetResult() }.context("read selected folder")?;
            let selected_name = unsafe { selected_item.GetDisplayName(SIGDN_FILESYSPATH) }
                .context("read selected folder path")?;
            let selected_path =
                unsafe { selected_name.to_string() }.context("decode selected folder path")?;
            unsafe {
                CoTaskMemFree(Some(selected_name.as_ptr() as *const core::ffi::c_void));
            }
            Ok(Some(PathBuf::from(selected_path)))
        }
        Err(error) if is_folder_picker_cancel(&error) => Ok(None),
        Err(error) => Err(error).context("show destination folder picker"),
    }
}

#[cfg(windows)]
struct ComApartment;

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

#[cfg(windows)]
fn is_folder_picker_cancel(error: &WindowsError) -> bool {
    const HRESULT_FROM_WIN32_ERROR_CANCELLED: i32 = 0x800704C7_u32 as i32;
    let code = error.code();
    code == E_ABORT || code.0 == HRESULT_FROM_WIN32_ERROR_CANCELLED
}

fn parse_existing_file(value: String, empty_message: &str) -> Result<PathBuf> {
    let input = normalized_path(value).ok_or_else(|| anyhow!(empty_message.to_string()))?;
    if !input.is_file() {
        return Err(anyhow!(
            "Path does not point to a readable file: {}",
            input.display()
        ));
    }
    Ok(input)
}

fn file_name_or_path(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| display_path(path))
}

fn selected_runtime_collectors_label(request: &CollectionExecutionRequest) -> String {
    let mut labels = Vec::new();
    if request.collect_registry {
        labels.push("registry");
    }
    if request.collect_evtx {
        labels.push("evtx");
    }
    if request.collect_srum {
        labels.push("srum");
    }
    if request.collect_prefetch {
        labels.push("prefetch");
    }
    if request.collect_browser_artifacts {
        labels.push("browser");
    }
    if request.collect_jump_lists {
        labels.push("jump-lists");
    }
    if request.collect_lnk {
        labels.push("lnk");
    }
    if request.collect_mft {
        labels.push("mft");
    }
    if request.collect_logfile {
        labels.push("logfile");
    }
    if request.collect_indx {
        labels.push("indx");
    }
    if request.collect_usn {
        labels.push("usn");
    }
    labels.join(",")
}

fn collection_label(collection_id: &str) -> String {
    collection_catalog::enabled_collection_definitions()
        .into_iter()
        .find(|definition| definition.name == collection_id)
        .map(|definition| definition.artifact.to_string())
        .unwrap_or_else(|| collection_id.to_string())
}

fn build_collection_catalog_records() -> Vec<CollectionCatalogRecord> {
    let mut records = vec![
        CollectionCatalogRecord::new(
            "Windows Event Logs",
            "Auth + execution",
            "Available",
            "Security, System, Application, TaskScheduler, TerminalServices, PowerShell, Defender, Sysmon, WMI, BITS, and archived EVTX logs anchor logons, services, scheduled tasks, remote access, and script activity.",
            "Targets: C:\\Windows\\System32\\winevt\\Logs\\*.evtx, including Archive-*.evtx",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, copies EVTX files from the snapshot rather than live paths, preserves original Windows paths, hashes source and destination bytes with SHA-256, and records failures in the centralized manifest.",
            true,
        ),
        CollectionCatalogRecord::new(
            "Registry Hives",
            "Persistence + config",
            "Available",
            "Core Windows registry hives expose persistence, devices, execution residue, installed software, accounts, user activity, and AmCache program inventory across the host.",
            "Targets: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, COMPONENTS, Amcache.hve, BCD, NTUSER.DAT, USRCLASS.DAT, service-profile hives, and adjacent transaction logs",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, preserves original Windows hive paths, captures user and service-profile hives, includes Amcache.hve and BCD, and collects adjacent .LOG, .LOG1, .LOG2, .blf, and .regtrans-ms files for forensic replay.",
            true,
        ),
        CollectionCatalogRecord::new(
            "Prefetch",
            "Program execution",
            "Available",
            "Prefetch is one of the strongest native Windows execution artifacts and often survives even when the executable is later deleted.",
            "Targets: C:\\Windows\\Prefetch\\*.pf, Layout.ini, and Ag*.db via VSS snapshot",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, copies targeted Prefetch artifacts from the snapshot rather than the live path, streams bytes while hashing, and records source timestamps, file attributes, and snapshot metadata in the centralized manifest.",
            true,
        ),
        CollectionCatalogRecord::new(
            "$MFT",
            "File system timeline",
            "Available",
            "The Master File Table is the foundational NTFS corpus for existing and deleted files, paths, attributes, and MACB timestamps.",
            "Targets: $MFT via VSS raw NTFS extraction, plus SHA-256 and centralized manifest",
            "Included in Create Package today. The live Rust collector opens a VSS snapshot as a raw NTFS device, locates $MFT record 0, streams the unnamed $DATA runs to C/$MFT.bin, hashes the output, and records NTFS geometry and run metadata.",
            true,
        ),
        CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "The USN Change Journal captures create, delete, rename, close, extend, overwrite, and truncation activity with strong sequence value.",
            "Targets: $Extend\\$UsnJrnl ($J) plus centralized collector manifest",
            "Included in Create Package today. The controls above run direct-stream or VSS-backed acquisition and package the journal plus its manifest for preservation and handoff.",
            true,
        )
        .with_configurable(true),
        CollectionCatalogRecord::new(
            "$LogFile",
            "NTFS transaction log",
            "Available",
            "The NTFS transaction log helps reconstruct recent file-system operations when recent change detail matters more than long-term retention.",
            "Targets: $LogFile via VSS raw NTFS extraction, plus SHA-256 and centralized manifest",
            "Included in Create Package today. The live Rust collector opens a VSS snapshot as a raw NTFS device, resolves MFT record 2, streams the unnamed $DATA runs to C/$LogFile.bin, hashes the output, and records NTFS geometry and run metadata.",
            true,
        ),
        CollectionCatalogRecord::new(
            "INDX Records",
            "Directory remnants",
            "Available",
            "Directory index records and slack can preserve deleted file names, sizes, and timestamps after the files themselves are gone.",
            "Targets: $INDEX_ROOT:$I30, $INDEX_ALLOCATION:$I30, and $BITMAP:$I30 from NTFS directory records",
            "Included in Create Package today. The live Rust collector opens a VSS snapshot as a raw NTFS device, walks directory MFT records, preserves raw $I30 index attributes in C/INDX.rawpack, hashes each entry and the pack, and records directory record metadata in the centralized manifest.",
            true,
        ),
        CollectionCatalogRecord::new(
            "LNK Files",
            "User file access",
            "Available",
            "Windows shortcuts are excellent user-interaction artifacts for files, folders, programs, removable media, and network paths.",
            "Targets: per-user Recent, Office Recent, Desktop, user Start Menu, and ProgramData Start Menu .lnk files via VSS snapshot",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, copies raw .lnk files without resolving their targets, preserves logical Windows paths, hashes each file with SHA-256, and records a JSONL artifact manifest plus centralized collector metadata.",
            true,
        ),
        CollectionCatalogRecord::new(
            "Jump Lists",
            "Recent activity",
            "Available",
            "Jump Lists record application-driven recent-file activity and help show what a user opened through a specific app.",
            "Targets: per-user AutomaticDestinations and CustomDestinations under AppData\\Roaming\\Microsoft\\Windows\\Recent, plus JSONL inventory and centralized metadata",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, walks each eligible user profile under Users, copies Automatic and Custom Jump Lists without modifying the originals, hashes each file with SHA-256, and records an artifact-level JSONL manifest plus centralized collector metadata.",
            true,
        ),
        CollectionCatalogRecord::new(
            "Recycle Bin",
            "Deleted data",
            "Planned",
            "Recycle Bin artifacts preserve deleted-file metadata and, depending on version and state, sometimes the deleted content itself.",
            "Targets: C:\\$Recycle.Bin, INFO2, $I, $R",
            "Use this to recover original names, paths, sizes, and deletion times, and to check whether tools or staged data were hidden in the bin root.",
            false,
        ),
        CollectionCatalogRecord::new(
            "Browser Artifacts",
            "Web activity",
            "Available",
            "Browser artifacts capture visited URLs, downloads, cookies, autofill, sessions, extensions, cached content, and cloud-access intent across Chrome, Edge, Firefox, and legacy Edge.",
            "Targets: targeted Chrome/Edge databases, sessions, storage, extension manifests, Firefox Roaming/Local profiles, Edge Legacy/WebCache, DPAPI material, NTUSER.DAT, and SYSTEM/SECURITY/SOFTWARE",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, copies targeted browser artifacts and decryption support material from the snapshot, hashes source and destination bytes with SHA-256, and records failures in the centralized manifest.",
            true,
        ),
        CollectionCatalogRecord::new(
            "RDP and Lateral Movement",
            "Remote access",
            "Planned",
            "Remote Desktop artifacts show which remote hosts were accessed, which users were involved, and how sessions started, reconnected, or disconnected.",
            "Targets: TerminalServices logs, Security logon types, RDP bitmap cache, Terminal Server Client keys",
            "This surface is high-value whenever remote access, lateral movement, or remote operator behavior is part of the investigation.",
            false,
        ),
        CollectionCatalogRecord::new(
            "Scheduled Tasks",
            "Persistence + execution",
            "Planned",
            "Scheduled tasks are a common persistence and execution mechanism with both file-based definitions and event-log history.",
            "Targets: C:\\Windows\\System32\\Tasks, TaskScheduler Operational log, Security events, SchedLgU.txt",
            "Collect this when you need task names, authors, triggers, commands, execution history, and modification time for persistence analysis.",
            false,
        ),
        CollectionCatalogRecord::new(
            "USB and External Devices",
            "Device usage",
            "Planned",
            "USB and device artifacts tie hardware identities, serial numbers, drive letters, and user activity on removable media back to the host.",
            "Targets: USBSTOR, MountedDevices, Windows Portable Devices, DriverFrameworks, Shellbags, LNK, Jump Lists",
            "This is essential in staging and data-theft cases because it links removable devices to filesystem and Explorer activity.",
            false,
        ),
        CollectionCatalogRecord::new(
            "Volume Shadow Copies",
            "Historical recovery",
            "Planned",
            "Shadow copies and restore points provide historical recovery paths for evidence that has rolled over, been deleted, or been overwritten in the live system.",
            "Targets: Volume Shadow Copies, restore points, older hives, logs, files, malware",
            "This surface is critical when the current system no longer retains the needed registry, event log, file, or malware state.",
            false,
        ),
        CollectionCatalogRecord::new(
            "Memory, Hibernation, and Crash Dumps",
            "Volatile evidence",
            "Planned",
            "Volatile and semi-volatile artifacts expose running processes, network connections, loaded modules, credentials, injected code, and in-memory malware state.",
            "Targets: RAM image, hiberfil.sys, pagefile.sys, swapfile.sys, memory.dmp, minidumps, WER",
            "This is the surface for process state, command remnants, tokens, unpacked malware, and memory-resident evidence that never lands cleanly on disk.",
            false,
        ),
        CollectionCatalogRecord::new(
            "SRUM",
            "Usage telemetry",
            "Available",
            "SRUM adds application resource and network usage over time, often with user association that sharpens timeline questions.",
            "Targets: C:\\Windows\\System32\\sru\\* plus SOFTWARE and SYSTEM supporting hives",
            "Included in Create Package today. The live Rust collector uses a VSS snapshot, copies the SRU folder plus SOFTWARE and SYSTEM from the snapshot rather than live paths, hashes source and destination bytes with SHA-256, and records failures in the centralized manifest.",
            true,
        ),
        CollectionCatalogRecord::new(
            "Startup Folders",
            "Startup persistence",
            "Planned",
            "Startup folders remain a simple but high-signal persistence location for dropped executables, scripts, and shortcuts.",
            "Targets: User and ProgramData Startup folders",
            "Collect this surface whenever user-level or system-wide startup persistence is in scope; it is easy to explain and easy to miss if omitted.",
            false,
        ),
    ];

    for record in &mut records {
        record.selected = true;
    }

    records
}

fn default_collection_output_dir(project_root: &Path) -> PathBuf {
    env::current_dir().unwrap_or_else(|_| project_root.to_path_buf())
}

fn default_parse_output_path(project_root: &Path) -> PathBuf {
    project_root.join("output").join("desktop-parse")
}

fn parse_output_path_for_zip(project_root: &Path, zip_path: &Path) -> PathBuf {
    let zip_base = zip_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("collection");
    project_root.join("output").join(zip_base)
}

fn inspection_cache_dir(project_root: &Path, input: &Path) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    input.to_string_lossy().hash(&mut hasher);
    if let Ok(metadata) = fs::metadata(input) {
        metadata.len().hash(&mut hasher);
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                duration.as_secs().hash(&mut hasher);
                duration.subsec_nanos().hash(&mut hasher);
            }
        }
    }
    let stem = sanitize_token(
        input
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("collection"),
    );
    project_root
        .join("output")
        .join(".desktop-inspection")
        .join(format!("{}-{:016x}", stem, hasher.finish()))
}

fn sanitize_token(value: &str) -> String {
    let mut token = String::new();
    let mut last_dash = false;
    for character in value.to_ascii_lowercase().chars() {
        let normalized = if character.is_ascii_alphanumeric() {
            character
        } else {
            '-'
        };
        if normalized == '-' {
            if !last_dash {
                token.push('-');
            }
            last_dash = true;
        } else {
            token.push(normalized);
            last_dash = false;
        }
    }
    token.trim_matches('-').to_string()
}

fn usn_mode_from_index(index: i32) -> usn_journal::UsnDumpMode {
    match index {
        0 => usn_journal::UsnDumpMode::DirectStream,
        1 => usn_journal::UsnDumpMode::VssSnapshot,
        _ => usn_journal::UsnDumpMode::VssRawNtfs,
    }
}

fn usn_chunk_size_mib_from_index(index: i32) -> usize {
    match index {
        0 => 1,
        2 => 8,
        3 => 16,
        4 => 32,
        _ => 4,
    }
}

fn format_elapsed(duration: Duration) -> String {
    format!("Elapsed {}", format_duration(duration))
}

fn format_remaining(duration: Duration, completed_plans: usize, total_plans: usize) -> String {
    if total_plans == 0 || completed_plans == 0 {
        return "Remaining n/a".to_string();
    }

    let elapsed_seconds = duration.as_secs_f64();
    if elapsed_seconds <= 0.0 {
        return "Remaining n/a".to_string();
    }

    let rate = completed_plans as f64 / elapsed_seconds;
    if rate <= 0.0 {
        return "Remaining n/a".to_string();
    }

    let remaining_plans = total_plans.saturating_sub(completed_plans) as f64;
    let remaining = Duration::from_secs_f64(remaining_plans / rate);
    format!("Remaining {}", format_duration(remaining))
}

fn format_rate(duration: Duration, completed_plans: usize) -> String {
    let elapsed_seconds = duration.as_secs_f64();
    if completed_plans == 0 || elapsed_seconds <= 0.0 {
        return "Rate n/a".to_string();
    }
    format!(
        "Rate {:.2} plans/s",
        completed_plans as f64 / elapsed_seconds
    )
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        return format!("{}h {}m {}s", hours, minutes, seconds);
    }
    if minutes > 0 {
        return format!("{}m {}s", minutes, seconds);
    }
    format!("{}s", seconds)
}

fn register_embedded_fonts() {
    let mut collection = slint::fontique_08::shared_collection();
    for font in [
        FIGTREE_REGULAR,
        FIGTREE_MEDIUM,
        TOMORROW_THIN,
        TOMORROW_LIGHT,
        TOMORROW_REGULAR,
    ] {
        let blob = fontique::Blob::new(Arc::new(font.to_vec()));
        collection.register_fonts(blob, None);
    }
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use anyhow::anyhow;

    use super::{
        CollectionActivityTone, CollectionCatalogRecord, CollectionCollectorProgress,
        CollectionDriveRecord, CollectionProgressState, CollectionRuntimePhase,
        build_collection_activity_details, build_collection_activity_snapshot,
        build_collection_catalog_records, build_startup_error_dialog_body, collection_source_state,
        format_error_details, guard_desktop_action, normalized_selected_volumes_or_default,
        panic_payload_message,
    };

    #[test]
    fn collection_activity_snapshot_surfaces_runtime_and_scope_only_rows() {
        let mut runtime = CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "",
            "",
            "",
            true,
        );
        runtime.selected = true;

        let mut planned = CollectionCatalogRecord::new(
            "Windows Event Logs",
            "Auth + execution",
            "Planned",
            "",
            "",
            "",
            false,
        );
        planned.selected = true;

        let (items, summary) = build_collection_activity_snapshot(
            &[planned, runtime],
            CollectionRuntimePhase::Idle,
            1,
            0,
            None,
        );

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "$UsnJrnl");
        assert_eq!(items[0].status, "Ready");
        assert_eq!(items[0].tone, CollectionActivityTone::Ready);
        assert_eq!(items[1].title, "Windows Event Logs");
        assert_eq!(items[1].status, "Scope only");
        assert_eq!(items[1].tone, CollectionActivityTone::ScopeOnly);
        assert!(summary.contains("1 runtime collector ready"));
        assert!(summary.contains("1 selected surface remain scope-only"));
    }

    #[test]
    fn collection_activity_snapshot_marks_live_runtime_as_running() {
        let mut runtime = CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "",
            "",
            "",
            true,
        );
        runtime.selected = true;

        let (items, summary) = build_collection_activity_snapshot(
            &[runtime],
            CollectionRuntimePhase::Running,
            1,
            0,
            None,
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, "Running");
        assert_eq!(items[0].tone, CollectionActivityTone::Running);
        assert!(items[0].active);
        assert!(summary.contains("1 runtime collector in flight"));
    }

    #[test]
    fn collection_activity_snapshot_uses_progress_state_for_active_and_staged_rows() {
        let mut registry = CollectionCatalogRecord::new(
            "Registry Hives",
            "Persistence + config",
            "Available",
            "",
            "",
            "",
            true,
        );
        registry.selected = true;

        let mut usn = CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "",
            "",
            "",
            true,
        );
        usn.selected = true;

        let progress = CollectionProgressState {
            runtime_jobs: 2,
            completed_jobs: 1,
            current_collector: Some("Registry Hives".to_string()),
            collectors: BTreeMap::from([
                (
                    "$UsnJrnl".to_string(),
                    CollectionCollectorProgress {
                        current_volume: Some("C:".to_string()),
                        current_job_progress: 0.0,
                        detail: "Collected and staged the USN Journal from C:.".to_string(),
                        progress_text: "2 staged paths".to_string(),
                        completed_jobs: 1,
                        staged_paths: 2,
                        artifact_paths: vec![
                            "C/$Extend/$UsnJrnl/$J.bin".to_string(),
                            "$metadata/collectors/C/windows_usn_journal/manifest.json".to_string(),
                        ],
                        started: true,
                        active: false,
                    },
                ),
                (
                    "Registry Hives".to_string(),
                    CollectionCollectorProgress {
                        current_volume: Some("C:".to_string()),
                        current_job_progress: 0.58,
                        detail:
                            "Copying transaction-safe registry artifacts from the VSS snapshot."
                                .to_string(),
                        progress_text: "23 / 72 artifacts".to_string(),
                        completed_jobs: 0,
                        staged_paths: 0,
                        artifact_paths: Vec::new(),
                        started: true,
                        active: true,
                    },
                ),
            ]),
            ..Default::default()
        };

        let (items, summary) = build_collection_activity_snapshot(
            &[registry, usn],
            CollectionRuntimePhase::Running,
            1,
            0,
            Some(&progress),
        );

        let registry_item = items
            .iter()
            .find(|item| item.title == "Registry Hives")
            .expect("registry row should exist");
        assert_eq!(registry_item.status, "Running");
        assert_eq!(registry_item.tone, CollectionActivityTone::Running);
        assert!(registry_item.show_progress);
        assert!(registry_item.active);
        assert!(registry_item.progress_value > 0.5);
        assert!(registry_item.progress_text.contains("23 / 72 artifacts"));

        let usn_item = items
            .iter()
            .find(|item| item.title == "$UsnJrnl")
            .expect("usn row should exist");
        assert_eq!(usn_item.status, "Staged");
        assert_eq!(usn_item.tone, CollectionActivityTone::Ready);
        assert!(usn_item.show_progress);
        assert_eq!(usn_item.progress_value, 1.0);
        assert!(usn_item.package_pending);
        assert!(summary.contains("1 of 2 runtime collection tasks complete"));
        assert!(summary.contains("Registry Hives in progress"));
    }

    #[test]
    fn collection_activity_details_show_expected_registry_artifacts_while_running() {
        let record = super::CollectionActivityRecord {
            title: "Registry Hives".to_string(),
            category: "Persistence + config".to_string(),
            detail: "Registry collector is running.".to_string(),
            status: "Running".to_string(),
            tone: CollectionActivityTone::Running,
            active: true,
            show_progress: true,
            progress_value: 0.42,
            progress_text: "Copying".to_string(),
            package_pending: false,
        };
        let progress = CollectionProgressState {
            collectors: BTreeMap::from([(
                "Registry Hives".to_string(),
                CollectionCollectorProgress {
                    active: true,
                    started: true,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let details = build_collection_activity_details(Some(&record), Some(&progress));

        assert!(details.iter().any(|item| item.name.contains("Amcache.hve")));
        assert!(details.iter().any(|item| item.name.contains("NTUSER.DAT")));
        assert!(
            details
                .iter()
                .any(|item| item.name.contains(".regtrans-ms"))
        );
        assert!(details.iter().all(|item| item.state == "In progress"));
    }

    #[test]
    fn collection_activity_details_use_reported_artifacts_after_usn_finishes() {
        let record = super::CollectionActivityRecord {
            title: "$UsnJrnl".to_string(),
            category: "NTFS change log".to_string(),
            detail: "USN collector staged artifacts.".to_string(),
            status: "Staged".to_string(),
            tone: CollectionActivityTone::Ready,
            active: false,
            show_progress: true,
            progress_value: 1.0,
            progress_text: "2 staged paths".to_string(),
            package_pending: true,
        };
        let progress = CollectionProgressState {
            collectors: BTreeMap::from([(
                "$UsnJrnl".to_string(),
                CollectionCollectorProgress {
                    artifact_paths: vec![
                        "C/$Extend/$UsnJrnl/$J.bin".to_string(),
                        "$metadata/collectors/C/windows_usn_journal/manifest.json".to_string(),
                    ],
                    started: true,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let details = build_collection_activity_details(Some(&record), Some(&progress));

        assert_eq!(details.len(), 2);
        assert!(details.iter().all(|item| item.state == "Collected"));
        assert!(details.iter().any(|item| item.name == "$J.bin"));
        assert!(
            details
                .iter()
                .any(|item| item.name == "Collection manifest")
        );
        assert!(details.iter().any(|item| item.detail.contains("raw USN")));
        assert!(details.iter().any(|item| item.detail.contains("manifest")));
    }

    #[test]
    fn collection_activity_snapshot_marks_all_live_collectors_packaged_after_success() {
        let mut registry = CollectionCatalogRecord::new(
            "Registry Hives",
            "Persistence + config",
            "Available",
            "",
            "",
            "",
            true,
        );
        registry.selected = true;

        let mut usn = CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "",
            "",
            "",
            true,
        );
        usn.selected = true;

        let (items, summary) = build_collection_activity_snapshot(
            &[registry, usn],
            CollectionRuntimePhase::Succeeded,
            1,
            0,
            None,
        );

        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| item.status == "Packaged"));
        assert!(
            items
                .iter()
                .all(|item| item.tone == CollectionActivityTone::Complete)
        );
        assert!(summary.contains("2 runtime collectors completed"));
    }

    #[test]
    fn only_usn_exposes_tune_in_collection_catalog() {
        let records = build_collection_catalog_records();

        let registry = records
            .iter()
            .find(|record| record.title == "Registry Hives")
            .expect("registry record should exist");
        assert!(registry.live);
        assert!(!registry.configurable);
        assert!(registry.targets.contains("Amcache.hve"));
        assert!(registry.targets.contains("NTUSER.DAT"));
        assert!(registry.note.contains(".regtrans-ms"));
        assert!(records.iter().all(|record| record.title != "AmCache"));

        let usn = records
            .iter()
            .find(|record| record.title == "$UsnJrnl")
            .expect("usn record should exist");
        assert!(usn.live);
        assert!(usn.configurable);

        let jump_lists = records
            .iter()
            .find(|record| record.title == "Jump Lists")
            .expect("jump lists record should exist");
        assert!(jump_lists.live);
        assert!(!jump_lists.configurable);
        assert!(jump_lists.targets.contains("AutomaticDestinations"));
    }

    #[test]
    fn prefetch_collection_catalog_record_is_live_and_describes_vss_targets() {
        let records = build_collection_catalog_records();

        let prefetch = records
            .iter()
            .find(|record| record.title == "Prefetch")
            .expect("prefetch record should exist");

        assert!(prefetch.live);
        assert_eq!(prefetch.status, "Available");
        assert!(prefetch.targets.contains("Layout.ini"));
        assert!(prefetch.targets.contains("Ag*.db"));
        assert!(prefetch.note.contains("file attributes"));
    }

    #[test]
    fn lnk_collection_catalog_record_is_live_and_describes_raw_snapshot_copy() {
        let records = build_collection_catalog_records();

        let lnk = records
            .iter()
            .find(|record| record.title == "LNK Files")
            .expect("lnk record should exist");

        assert!(lnk.live);
        assert_eq!(lnk.status, "Available");
        assert!(lnk.targets.contains("Office Recent"));
        assert!(lnk.targets.contains("Start Menu"));
        assert!(lnk.note.contains("without resolving their targets"));
        assert!(lnk.note.contains("JSONL artifact manifest"));
    }

    #[test]
    fn prefetch_collection_activity_details_show_expected_prefetch_artifacts() {
        let record = super::CollectionActivityRecord {
            title: "Prefetch".to_string(),
            category: "Program execution".to_string(),
            detail: "Prefetch collector is ready.".to_string(),
            status: "Ready".to_string(),
            tone: CollectionActivityTone::Ready,
            active: false,
            show_progress: false,
            progress_value: 0.0,
            progress_text: String::new(),
            package_pending: false,
        };

        let details = build_collection_activity_details(Some(&record), None);

        assert!(details.iter().any(|item| item.name.contains("*.pf")));
        assert!(details.iter().any(|item| item.name.contains("Layout.ini")));
        assert!(details.iter().any(|item| item.name.contains("Ag*.db")));
        assert!(
            details
                .iter()
                .any(|item| item.name.contains("windows_prefetch/manifest.json"))
        );
    }

    #[test]
    fn lnk_collection_activity_details_show_expected_lnk_artifacts() {
        let record = super::CollectionActivityRecord {
            title: "LNK Files".to_string(),
            category: "User file access".to_string(),
            detail: "LNK collector is ready.".to_string(),
            status: "Ready".to_string(),
            tone: CollectionActivityTone::Ready,
            active: false,
            show_progress: false,
            progress_value: 0.0,
            progress_text: String::new(),
            package_pending: false,
        };

        let details = build_collection_activity_details(Some(&record), None);

        assert!(
            details
                .iter()
                .any(|item| item.name.contains("Recent/*.lnk"))
        );
        assert!(
            details
                .iter()
                .any(|item| item.name.contains("Desktop/*.lnk"))
        );
        assert!(
            details
                .iter()
                .any(|item| item.name.contains("lnk_manifest.jsonl"))
        );
        assert!(
            details
                .iter()
                .any(|item| item.name.contains("windows_lnk/manifest.json"))
        );
    }

    #[test]
    fn normalized_selected_volumes_or_default_prefers_available_drive_record() {
        let drives = vec![
            CollectionDriveRecord {
                volume: "C:".to_string(),
                filesystem: "NTFS".to_string(),
            },
            CollectionDriveRecord {
                volume: "E:".to_string(),
                filesystem: "exFAT".to_string(),
            },
        ];

        assert_eq!(
            normalized_selected_volumes_or_default(
                &["e".to_string(), "C:".to_string(), "e".to_string()],
                &drives
            ),
            vec!["C:".to_string(), "E:".to_string()]
        );
        assert_eq!(
            normalized_selected_volumes_or_default(&["Z:".to_string()], &drives),
            vec!["C:".to_string()]
        );
    }

    #[test]
    fn drive_record_to_ui_item_carries_filesystem_and_selection() {
        let drive = CollectionDriveRecord {
            volume: "E:".to_string(),
            filesystem: "exFAT".to_string(),
        };

        let item = drive.to_ui_item(&["E:".to_string()]);

        assert_eq!(item.volume.to_string(), "E:");
        assert_eq!(item.filesystem.to_string(), "exFAT");
        assert!(item.selected);
    }

    #[test]
    fn collection_activity_snapshot_blocks_runtime_on_unsupported_source() {
        let mut runtime = CollectionCatalogRecord::new(
            "$UsnJrnl",
            "NTFS change log",
            "Available",
            "",
            "",
            "",
            true,
        );
        runtime.selected = true;

        let (items, summary) = build_collection_activity_snapshot(
            &[runtime],
            CollectionRuntimePhase::Idle,
            0,
            1,
            None,
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, "Blocked");
        assert_eq!(items[0].tone, CollectionActivityTone::Failed);
        assert!(summary.contains("NTFS-backed sources"));
        assert!(summary.contains("Some artifacts will be skipped"));
    }

    #[test]
    fn collection_source_state_accepts_ntfs_volume() {
        let drives = vec![CollectionDriveRecord {
            volume: "C:".to_string(),
            filesystem: "NTFS".to_string(),
        }];

        let state = collection_source_state(&["C:".to_string()], &drives);

        assert!(state.supported());
        assert_eq!(state.summary, "C: selected and ready for collection.");
    }

    #[test]
    fn collection_source_state_rejects_non_ntfs_volume() {
        let drives = vec![CollectionDriveRecord {
            volume: "E:".to_string(),
            filesystem: "exFAT".to_string(),
        }];

        let state = collection_source_state(&["E:".to_string()], &drives);

        assert!(!state.supported());
        assert_eq!(
            state.summary,
            "E: (exFAT) selected. Some artifacts will be skipped."
        );
    }

    #[test]
    fn collection_source_state_supports_mixed_multi_selection() {
        let drives = vec![
            CollectionDriveRecord {
                volume: "C:".to_string(),
                filesystem: "NTFS".to_string(),
            },
            CollectionDriveRecord {
                volume: "E:".to_string(),
                filesystem: "exFAT".to_string(),
            },
        ];

        let state = collection_source_state(&["C:".to_string(), "E:".to_string()], &drives);

        assert!(state.supported());
        assert_eq!(state.supported_volumes, vec!["C:".to_string()]);
        assert_eq!(state.unsupported_volumes, vec!["E: (exFAT)".to_string()]);
        assert_eq!(
            state.summary,
            "1 selected source ready. Some artifacts will be skipped on E: (exFAT)."
        );
    }

    #[test]
    fn format_error_details_includes_cause_chain() {
        let error = anyhow!("The system cannot find the path specified.")
            .context("create collection output parent E:\\Evidence Locker");

        let detail = format_error_details(&error);

        assert!(detail.contains("create collection output parent E:\\Evidence Locker"));
        assert!(detail.contains("Caused by:"));
        assert!(detail.contains("The system cannot find the path specified."));
    }

    #[test]
    fn panic_payload_message_prefers_string_payloads() {
        assert_eq!(
            panic_payload_message(Box::new(String::from("boom"))),
            "boom"
        );
    }

    #[test]
    fn guard_desktop_action_turns_panics_into_errors() {
        let error = guard_desktop_action("Run parse workflow", || -> anyhow::Result<()> {
            panic!("unexpected parse state");
        })
        .expect_err("panic should be surfaced as an error");

        let detail = format_error_details(&error);

        assert!(detail.contains("Run parse workflow panicked unexpectedly."));
        assert!(detail.contains("unexpected parse state"));
    }

    #[test]
    fn startup_error_dialog_body_includes_detail_and_log_hint() {
        let body = build_startup_error_dialog_body(
            "The desktop UI failed during startup.",
            "Launch desktop UI panicked unexpectedly. boom",
            Some(r"C:\Users\Analyst\.holo-forensics\holo-forensics.log"),
        );

        assert!(body.contains("The desktop UI failed during startup."));
        assert!(body.contains("Details:"));
        assert!(body.contains("Launch desktop UI panicked unexpectedly. boom"));
        assert!(body.contains(r"C:\Users\Analyst\.holo-forensics\holo-forensics.log"));
    }
}
