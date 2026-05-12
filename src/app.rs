use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::collection;
use crate::collection_metadata;
use crate::collections::windows::{
    browser_artifacts, evtx, indx, logfile, mft, registry, srum, usn_journal, vss,
};
use crate::manifest::{Manifest, ManifestEntry, write_manifest};
use crate::opensearch::{
    Config as OpenSearchConfig, ExportMetadata, OpenSearchClient, build_url, default_index_name,
};
use crate::parser_catalog;
use crate::parsers;
use crate::runtime_support;

#[derive(Debug, Clone, Default)]
pub struct ParseRunOptions {
    pub project_root: Option<PathBuf>,
    pub selected_plan_ids: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct ParseInspectionOptions {
    pub project_root: Option<PathBuf>,
    pub extraction_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ParseRunSummary {
    pub output_dir: PathBuf,
    pub extracted_dir: PathBuf,
    pub results_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedPlan {
    pub id: String,
    pub parser: String,
    pub collection: String,
    pub artifact: String,
}

#[derive(Debug, Clone)]
pub struct ParseInspectionSummary {
    pub zip_base: String,
    pub extracted_dir: PathBuf,
    pub detected_plans: Vec<DetectedPlan>,
}

#[derive(Debug, Clone)]
pub struct UsnCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub mode: usn_journal::UsnDumpMode,
    pub sparse: bool,
    pub chunk_size_mib: usize,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub method: registry::RegistryCollectMethod,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct EvtxCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct SrumCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct BrowserArtifactsCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct MftCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub mode: mft::MftAcquisitionMode,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct LogFileCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub mode: logfile::LogFileAcquisitionMode,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct IndxCollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    pub mode: indx::IndxAcquisitionMode,
    pub include_deleted_dirs: bool,
    pub max_directories: Option<usize>,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnCollectionOptions {
    pub mode: usn_journal::UsnDumpMode,
    pub sparse: bool,
    pub chunk_size_mib: usize,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCollectionOptions {
    pub method: registry::RegistryCollectMethod,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxCollectionOptions {
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrumCollectionOptions {
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifactsCollectionOptions {
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftCollectionOptions {
    pub mode: mft::MftAcquisitionMode,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileCollectionOptions {
    pub mode: logfile::LogFileAcquisitionMode,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndxCollectionOptions {
    pub mode: indx::IndxAcquisitionMode,
    pub include_deleted_dirs: bool,
    pub max_directories: Option<usize>,
    pub elevate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionArchiveRequest {
    pub volumes: Vec<String>,
    pub output_zip: PathBuf,
    pub staging_root: Option<PathBuf>,
    #[serde(default)]
    pub usn: Option<UsnCollectionOptions>,
    #[serde(default)]
    pub registry: Option<RegistryCollectionOptions>,
    #[serde(default)]
    pub evtx: Option<EvtxCollectionOptions>,
    #[serde(default)]
    pub srum: Option<SrumCollectionOptions>,
    #[serde(default)]
    pub browser_artifacts: Option<BrowserArtifactsCollectionOptions>,
    #[serde(default)]
    pub mft: Option<MftCollectionOptions>,
    #[serde(default)]
    pub logfile: Option<LogFileCollectionOptions>,
    #[serde(default)]
    pub indx: Option<IndxCollectionOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionArchiveSummary {
    pub output_zip: PathBuf,
    pub staging_dir: PathBuf,
    pub staged_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CollectionEvent {
    RunStarting {
        runtime_collectors: usize,
        runtime_jobs: usize,
        output_zip: PathBuf,
    },
    CollectorStarted {
        collection_title: String,
        volume: String,
        progress_value: f32,
        detail: String,
        progress_text: String,
    },
    CollectorProgress {
        collection_title: String,
        volume: String,
        progress_value: f32,
        detail: String,
        progress_text: String,
    },
    CollectorFinished {
        collection_title: String,
        volume: String,
        progress_value: f32,
        detail: String,
        progress_text: String,
        staged_paths: usize,
        #[serde(default)]
        artifact_paths: Vec<String>,
    },
    PackagingStarting {
        output_zip: PathBuf,
        entry_count: usize,
    },
    Completed {
        output_zip: PathBuf,
        staged_paths: usize,
    },
}

#[derive(Debug, Clone, Args)]
pub struct CollectionArchiveWorkerCli {
    #[arg(long, help = "Serialized collection request JSON path")]
    pub request: PathBuf,

    #[arg(long, help = "Serialized collection summary JSON path")]
    pub summary: PathBuf,

    #[arg(long, help = "Collection event log JSONL path")]
    pub event_log: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ParseEvent {
    Starting {
        input: PathBuf,
        output_dir: PathBuf,
    },
    Extracting {
        input: PathBuf,
        destination: PathBuf,
    },
    PlansResolved {
        family_count: usize,
        total_plans: usize,
    },
    ParserFamilyStarted {
        name: String,
        index: usize,
        total: usize,
        planned_items: usize,
    },
    PlanStarted {
        parser: String,
        artifact: String,
        index: usize,
        total: usize,
    },
    PlanFinished {
        parser: String,
        artifact: String,
        status: String,
        output_path: Option<PathBuf>,
        log_path: Option<PathBuf>,
        exported_records: Option<usize>,
        error: Option<String>,
    },
    ManifestWritten {
        path: PathBuf,
    },
    Completed {
        manifest_path: PathBuf,
        total_entries: usize,
        exported_records: Option<usize>,
    },
}

#[derive(Debug, Parser)]
#[command(name = "holo-forensics")]
#[command(about = "Holo Forensics offline artifact parsing for forensic collections")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub parse: ParseCli,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(name = "collect-usn-journal")]
    CollectUsnJournal(usn_journal::UsnDumpCli),

    #[command(name = "collect-registry")]
    CollectRegistry(registry::RegistryCollectCli),

    #[command(name = "collect-collection-archive-worker", hide = true)]
    CollectCollectionArchiveWorker(CollectionArchiveWorkerCli),
}

#[derive(Debug, Args)]
pub struct ParseCli {
    #[arg(long)]
    pub input: Option<PathBuf>,

    #[arg(long)]
    pub output: Option<PathBuf>,

    #[arg(long = "opensearch-url")]
    pub opensearch_url: Option<String>,

    #[arg(long = "opensearch-username")]
    pub opensearch_username: Option<String>,

    #[arg(long = "opensearch-password")]
    pub opensearch_password: Option<String>,

    #[arg(long = "opensearch-index")]
    pub opensearch_index: Option<String>,

    #[arg(long = "opensearch-insecure", default_value_t = false)]
    pub opensearch_insecure: bool,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        return match command {
            Command::CollectUsnJournal(args) => usn_journal::run(&args),
            Command::CollectRegistry(args) => registry::run(&args),
            Command::CollectCollectionArchiveWorker(args) => run_collection_archive_worker(&args),
        };
    }

    let summary = run_parse_request(cli.parse, ParseRunOptions::default(), |_| {})?;
    println!(
        "Holo Forensics completed. Manifest: {}",
        summary.manifest_path.display()
    );
    Ok(())
}

pub fn inspect_parse_archive(
    input: &Path,
    options: ParseInspectionOptions,
) -> Result<ParseInspectionSummary> {
    let project_root = resolve_project_root(options.project_root)?;
    let parser_families = resolve_enabled_parser_families()?;
    let zip_base = zip_base(input);
    let extracted_dir = options.extraction_root.unwrap_or_else(|| {
        project_root
            .join("output")
            .join(".parse-inspection")
            .join(&zip_base)
    });

    prepare_clean_directory(&extracted_dir)?;
    collection::extract_full(input, &extracted_dir)?;

    let detected_plans = build_planned_families(&extracted_dir, &parser_families)?
        .into_iter()
        .flat_map(|(_, plans)| plans.unwrap_or_default())
        .map(|plan| DetectedPlan {
            id: plan_id(&plan),
            parser: plan.parser,
            collection: plan.collection,
            artifact: plan.artifact,
        })
        .collect::<Vec<_>>();

    Ok(ParseInspectionSummary {
        zip_base,
        extracted_dir,
        detected_plans,
    })
}

pub fn collect_collection_archive(
    request: &CollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    let mut reporter = |_| {};
    collect_collection_archive_with_reporter(request, &mut reporter)
}

pub fn collect_collection_archive_with_reporter(
    request: &CollectionArchiveRequest,
    reporter: &mut dyn FnMut(CollectionEvent),
) -> Result<CollectionArchiveSummary> {
    #[cfg(target_os = "windows")]
    if collection_archive_requests_elevation(request) && !is_process_elevated()? {
        return relaunch_collection_archive_worker(request, reporter);
    }

    collect_collection_archive_direct(request, reporter)
}

fn collect_collection_archive_direct(
    request: &CollectionArchiveRequest,
    reporter: &mut dyn FnMut(CollectionEvent),
) -> Result<CollectionArchiveSummary> {
    let normalized_volumes = normalize_collection_volumes(&request.volumes)?;
    if request.usn.is_none()
        && request.registry.is_none()
        && request.evtx.is_none()
        && request.srum.is_none()
        && request.browser_artifacts.is_none()
        && request.mft.is_none()
        && request.logfile.is_none()
        && request.indx.is_none()
    {
        return Err(anyhow!(
            "select at least one available evidence group before creating a package"
        ));
    }
    if let Some(usn_options) = request.usn.as_ref()
        && usn_options.chunk_size_mib == 0
    {
        return Err(anyhow!("collection chunk size must be greater than zero"));
    }

    reporter(CollectionEvent::RunStarting {
        runtime_collectors: selected_runtime_collector_count(request),
        runtime_jobs: planned_runtime_job_count(request, &normalized_volumes),
        output_zip: request.output_zip.clone(),
    });

    let output_parent = request
        .output_zip
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("output zip path must include a parent directory"))?;
    fs::create_dir_all(&output_parent).with_context(|| {
        format!(
            "create collection output parent {}",
            output_parent.display()
        )
    })?;

    let staging_dir = request.staging_root.clone().unwrap_or_else(|| {
        let stem = request
            .output_zip
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("usn-collection");
        output_parent.join(format!("{stem}-staging"))
    });
    prepare_clean_directory(&staging_dir)?;

    let mut staged_paths = Vec::new();
    let mut archive_entries = Vec::new();
    for normalized_volume in &normalized_volumes {
        if should_share_vss_snapshot(request) {
            reporter(CollectionEvent::CollectorProgress {
                collection_title: "Volume Shadow Copy".to_string(),
                volume: normalized_volume.clone(),
                progress_value: 0.10,
                detail: format!("Creating shared VSS snapshot for {normalized_volume}."),
                progress_text: "Creating snapshot".to_string(),
            });
            let shadow_copy = vss::create_shadow_copy(normalized_volume)
                .with_context(|| format!("create shared VSS snapshot for {normalized_volume}"))?;
            reporter(CollectionEvent::CollectorProgress {
                collection_title: "Volume Shadow Copy".to_string(),
                volume: normalized_volume.clone(),
                progress_value: 1.0,
                detail: format!("Shared VSS snapshot ready for {normalized_volume}."),
                progress_text: "Snapshot ready".to_string(),
            });

            let collection_result = (|| -> Result<()> {
                if let Some(evtx_options) = request.evtx.as_ref() {
                    stage_evtx_collection(
                        normalized_volume,
                        &staging_dir,
                        evtx_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(srum_options) = request.srum.as_ref() {
                    stage_srum_collection(
                        normalized_volume,
                        &staging_dir,
                        srum_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(browser_options) = request.browser_artifacts.as_ref() {
                    stage_browser_artifacts_collection(
                        normalized_volume,
                        &staging_dir,
                        browser_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(mft_options) = request.mft.as_ref() {
                    stage_mft_collection(
                        normalized_volume,
                        &staging_dir,
                        mft_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(logfile_options) = request.logfile.as_ref() {
                    stage_logfile_collection(
                        normalized_volume,
                        &staging_dir,
                        logfile_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(indx_options) = request.indx.as_ref() {
                    stage_indx_collection(
                        normalized_volume,
                        &staging_dir,
                        indx_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(usn_options) = request.usn.as_ref() {
                    stage_usn_collection(
                        normalized_volume,
                        &staging_dir,
                        usn_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                if let Some(registry_options) = request.registry.as_ref() {
                    stage_registry_collection(
                        normalized_volume,
                        &staging_dir,
                        registry_options,
                        Some(&shadow_copy),
                        reporter,
                        &mut archive_entries,
                        &mut staged_paths,
                    )?;
                }
                Ok(())
            })();

            reporter(CollectionEvent::CollectorProgress {
                collection_title: "Volume Shadow Copy".to_string(),
                volume: normalized_volume.clone(),
                progress_value: 1.0,
                detail: format!("Deleting shared VSS snapshot for {normalized_volume}."),
                progress_text: "Cleaning up".to_string(),
            });
            let delete_result = vss::delete_shadow_copy(&shadow_copy.id)
                .with_context(|| format!("delete shared VSS snapshot {}", shadow_copy.id));
            match (collection_result, delete_result) {
                (Ok(()), Ok(())) => {}
                (Ok(()), Err(delete_error)) => return Err(delete_error),
                (Err(collection_error), Ok(())) => return Err(collection_error),
                (Err(collection_error), Err(delete_error)) => {
                    return Err(collection_error.context(format!(
                        "also failed to delete shared VSS snapshot {}: {delete_error:#}",
                        shadow_copy.id
                    )));
                }
            }
            continue;
        }

        if let Some(usn_options) = request.usn.as_ref() {
            stage_usn_collection(
                normalized_volume,
                &staging_dir,
                usn_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(evtx_options) = request.evtx.as_ref() {
            stage_evtx_collection(
                normalized_volume,
                &staging_dir,
                evtx_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(srum_options) = request.srum.as_ref() {
            stage_srum_collection(
                normalized_volume,
                &staging_dir,
                srum_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(browser_options) = request.browser_artifacts.as_ref() {
            stage_browser_artifacts_collection(
                normalized_volume,
                &staging_dir,
                browser_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(mft_options) = request.mft.as_ref() {
            stage_mft_collection(
                normalized_volume,
                &staging_dir,
                mft_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(logfile_options) = request.logfile.as_ref() {
            stage_logfile_collection(
                normalized_volume,
                &staging_dir,
                logfile_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(indx_options) = request.indx.as_ref() {
            stage_indx_collection(
                normalized_volume,
                &staging_dir,
                indx_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
        if let Some(registry_options) = request.registry.as_ref() {
            stage_registry_collection(
                normalized_volume,
                &staging_dir,
                registry_options,
                None,
                reporter,
                &mut archive_entries,
                &mut staged_paths,
            )?;
        }
    }

    reporter(CollectionEvent::PackagingStarting {
        output_zip: request.output_zip.clone(),
        entry_count: archive_entries.len(),
    });
    collection::create_zip(&request.output_zip, &archive_entries)?;

    let summary = CollectionArchiveSummary {
        output_zip: request.output_zip.clone(),
        staging_dir,
        staged_paths,
    };
    reporter(CollectionEvent::Completed {
        output_zip: summary.output_zip.clone(),
        staged_paths: summary.staged_paths.len(),
    });
    Ok(summary)
}

pub fn run_collection_archive_worker(args: &CollectionArchiveWorkerCli) -> Result<()> {
    let bytes = fs::read(&args.request)
        .with_context(|| format!("read collection worker request {}", args.request.display()))?;
    let request: CollectionArchiveRequest = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "decode collection worker request {}",
            args.request.display()
        )
    })?;
    let mut reporter = |event| {
        let _ = write_collection_archive_worker_event(&args.event_log, &event);
    };
    let summary = collect_collection_archive_with_reporter(&request, &mut reporter)?;
    if let Some(parent) = args.summary.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection worker directory {}", parent.display()))?;
    }
    let summary_bytes = serde_json::to_vec_pretty(&summary)?;
    fs::write(&args.summary, summary_bytes)
        .with_context(|| format!("write collection worker summary {}", args.summary.display()))
}

pub fn collect_usn_archive(
    request: &UsnCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: Some(UsnCollectionOptions {
            mode: request.mode,
            sparse: request.sparse,
            chunk_size_mib: request.chunk_size_mib,
            elevate: request.elevate,
        }),
        registry: None,
        evtx: None,
        srum: None,
        browser_artifacts: None,
        mft: None,
        logfile: None,
        indx: None,
    })
}

pub fn collect_registry_archive(
    request: &RegistryCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: Some(RegistryCollectionOptions {
            method: request.method,
            elevate: request.elevate,
        }),
        evtx: None,
        srum: None,
        browser_artifacts: None,
        mft: None,
        logfile: None,
        indx: None,
    })
}

pub fn collect_evtx_archive(
    request: &EvtxCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: Some(EvtxCollectionOptions {
            elevate: request.elevate,
        }),
        srum: None,
        browser_artifacts: None,
        mft: None,
        logfile: None,
        indx: None,
    })
}

pub fn collect_mft_archive(
    request: &MftCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: None,
        srum: None,
        browser_artifacts: None,
        mft: Some(MftCollectionOptions {
            mode: request.mode,
            elevate: request.elevate,
        }),
        logfile: None,
        indx: None,
    })
}

pub fn collect_logfile_archive(
    request: &LogFileCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: None,
        srum: None,
        browser_artifacts: None,
        mft: None,
        logfile: Some(LogFileCollectionOptions {
            mode: request.mode,
            elevate: request.elevate,
        }),
        indx: None,
    })
}

pub fn collect_indx_archive(
    request: &IndxCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: None,
        srum: None,
        browser_artifacts: None,
        mft: None,
        logfile: None,
        indx: Some(IndxCollectionOptions {
            mode: request.mode,
            include_deleted_dirs: request.include_deleted_dirs,
            max_directories: request.max_directories,
            elevate: request.elevate,
        }),
    })
}

pub fn collect_srum_archive(
    request: &SrumCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: None,
        srum: Some(SrumCollectionOptions {
            elevate: request.elevate,
        }),
        browser_artifacts: None,
        mft: None,
        logfile: None,
        indx: None,
    })
}

pub fn collect_browser_artifacts_archive(
    request: &BrowserArtifactsCollectionArchiveRequest,
) -> Result<CollectionArchiveSummary> {
    collect_collection_archive(&CollectionArchiveRequest {
        volumes: request.volumes.clone(),
        output_zip: request.output_zip.clone(),
        staging_root: request.staging_root.clone(),
        usn: None,
        registry: None,
        evtx: None,
        srum: None,
        browser_artifacts: Some(BrowserArtifactsCollectionOptions {
            elevate: request.elevate,
        }),
        mft: None,
        logfile: None,
        indx: None,
    })
}

pub fn run_parse_request<F>(
    cli: ParseCli,
    options: ParseRunOptions,
    mut reporter: F,
) -> Result<ParseRunSummary>
where
    F: FnMut(ParseEvent),
{
    let input = cli
        .input
        .ok_or_else(|| anyhow!("--input is required unless a subcommand is used"))?;

    let project_root = resolve_project_root(options.project_root)?;
    let parser_families = resolve_enabled_parser_families()?;
    let zip_base = zip_base(&input);

    let resolved_output = cli
        .output
        .unwrap_or_else(|| project_root.join("output").join(&zip_base));
    let extracted_dir = resolved_output.join("extracted");
    let results_dir = resolved_output.join("results");
    prepare_clean_directory(&extracted_dir)?;
    prepare_clean_directory(&results_dir)?;

    reporter(ParseEvent::Starting {
        input: input.clone(),
        output_dir: resolved_output.clone(),
    });

    let opensearch_client = resolve_opensearch_client(
        cli.opensearch_url.as_deref(),
        cli.opensearch_username.as_deref(),
        cli.opensearch_password.as_deref(),
        cli.opensearch_index.as_deref(),
        cli.opensearch_insecure,
        parser_catalog::DEFAULT_PARSE_MODE,
        &zip_base,
    )?;

    reporter(ParseEvent::Extracting {
        input: input.clone(),
        destination: extracted_dir.clone(),
    });
    collection::extract_full(&input, &extracted_dir)?;

    let selection_active = options.selected_plan_ids.is_some();
    let selected_plan_ids = options.selected_plan_ids.as_ref();
    let planned_families = build_planned_families(&extracted_dir, &parser_families)?
        .into_iter()
        .map(|(family, plans)| {
            let filtered_plans = plans.map(|plans| {
                plans
                    .into_iter()
                    .filter(|plan| {
                        selected_plan_ids
                            .map(|ids| ids.contains(&plan_id(plan)))
                            .unwrap_or(true)
                    })
                    .collect::<Vec<_>>()
            });
            (family, filtered_plans)
        })
        .collect::<Vec<_>>();
    let total_plans = planned_families
        .iter()
        .map(|(_, plans)| plans.as_ref().map_or(0, Vec::len))
        .sum::<usize>();
    if selection_active && total_plans == 0 {
        return Err(anyhow!(
            "No supported artifacts matched the current parse selection"
        ));
    }

    let selected_parser_family_names = planned_families
        .iter()
        .filter(|(_, plans)| plans.as_ref().is_some_and(|plans| !plans.is_empty()))
        .map(|(family, _)| family.name.clone())
        .collect::<Vec<_>>();
    let selected_collection_names = planned_families
        .iter()
        .filter(|(_, plans)| plans.as_ref().is_some_and(|plans| !plans.is_empty()))
        .map(|(family, _)| family.collection.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let reported_family_count = if selection_active {
        planned_families
            .iter()
            .filter(|(_, plans)| plans.as_ref().is_some_and(|plans| !plans.is_empty()))
            .count()
    } else {
        planned_families.len()
    };
    reporter(ParseEvent::PlansResolved {
        family_count: reported_family_count,
        total_plans,
    });

    let mut run_manifest = Manifest {
        input_zip: input.display().to_string(),
        parser_families: if selection_active {
            selected_parser_family_names
        } else {
            parser_families
                .iter()
                .filter(|family| family.enabled)
                .map(|family| family.name.clone())
                .collect::<Vec<_>>()
        },
        collections: if selection_active {
            selected_collection_names
        } else {
            parser_families
                .iter()
                .filter(|family| family.enabled)
                .map(|family| family.collection.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        },
        extracted_dir: extracted_dir.display().to_string(),
        results_dir: results_dir.display().to_string(),
        entries: Vec::new(),
        opensearch_url: opensearch_client
            .as_ref()
            .map(|client| client.base_url().to_string()),
        opensearch_index: opensearch_client
            .as_ref()
            .map(|client| client.index().to_string()),
        exported_records: None,
    };

    let mut total_exported_records = 0usize;

    let mut completed_plans = 0usize;
    let family_count = if selection_active {
        planned_families
            .iter()
            .filter(|(_, plans)| plans.as_ref().is_some_and(|plans| !plans.is_empty()))
            .count()
    } else {
        planned_families.len()
    };
    let mut started_families = 0usize;

    for (parser_family, plans) in planned_families {
        if selection_active {
            match plans.as_ref() {
                Some(plans) if !plans.is_empty() => {}
                _ => continue,
            }
        }

        started_families += 1;
        reporter(ParseEvent::ParserFamilyStarted {
            name: parser_family.name.clone(),
            index: started_families,
            total: family_count,
            planned_items: plans.as_ref().map_or(0, Vec::len),
        });

        let Some(plans) = plans else {
            if selection_active {
                continue;
            }
            run_manifest.entries.push(ManifestEntry {
                parser: parser_family.name.clone(),
                collection: parser_family.collection.clone(),
                artifact: String::new(),
                args: BTreeMap::new(),
                output_path: None,
                log_path: None,
                status: "skipped".to_string(),
                error: Some("parser adapter not registered".to_string()),
                exported_records: None,
            });
            continue;
        };

        if plans.is_empty() {
            if selection_active {
                continue;
            }
            run_manifest.entries.push(ManifestEntry {
                parser: parser_family.name.clone(),
                collection: parser_family.collection.clone(),
                artifact: String::new(),
                args: BTreeMap::new(),
                output_path: None,
                log_path: None,
                status: "skipped".to_string(),
                error: Some("no matching inputs found in extracted collection".to_string()),
                exported_records: None,
            });
            continue;
        }

        let parser_output_dir = results_dir.join(&parser_family.name);
        for plan in plans {
            reporter(ParseEvent::PlanStarted {
                parser: plan.parser.clone(),
                artifact: plan.artifact.clone(),
                index: completed_plans + 1,
                total: total_plans.max(1),
            });

            let mut entry = ManifestEntry {
                parser: plan.parser.clone(),
                collection: plan.collection.clone(),
                artifact: plan.artifact.clone(),
                args: plan.args.clone(),
                output_path: None,
                log_path: None,
                status: "ok".to_string(),
                error: None,
                exported_records: None,
            };

            let collect_result = parsers::collect_local(&plan, &parser_output_dir);

            match collect_result {
                Ok((output_path, log_path)) => {
                    entry.output_path = Some(output_path.display().to_string());
                    entry.log_path = Some(log_path.display().to_string());
                    if let Some(client) = opensearch_client.as_ref() {
                        match client.index_jsonl_file(
                            &output_path,
                            &ExportMetadata {
                                parser: plan.parser.clone(),
                                artifact: plan.artifact.clone(),
                                input_zip: input.display().to_string(),
                            },
                        ) {
                            Ok(exported_records) => {
                                if exported_records > 0 {
                                    entry.exported_records = Some(exported_records);
                                    total_exported_records += exported_records;
                                }
                            }
                            Err(error) => {
                                entry.status = "error".to_string();
                                entry.error = Some(error.to_string());
                            }
                        }
                    }
                }
                Err(error) => {
                    entry.status = "error".to_string();
                    entry.error = Some(error.to_string());
                }
            }

            completed_plans += 1;
            reporter(ParseEvent::PlanFinished {
                parser: entry.parser.clone(),
                artifact: entry.artifact.clone(),
                status: entry.status.clone(),
                output_path: entry.output_path.as_ref().map(PathBuf::from),
                log_path: entry.log_path.as_ref().map(PathBuf::from),
                exported_records: entry.exported_records,
                error: entry.error.clone(),
            });
            run_manifest.entries.push(entry);
        }
    }

    if let Some(client) = opensearch_client.as_ref() {
        client.refresh()?;
        run_manifest.exported_records = Some(total_exported_records);
    }

    let manifest_path = resolved_output.join("manifest.json");
    write_manifest(&manifest_path, &run_manifest)?;

    reporter(ParseEvent::ManifestWritten {
        path: manifest_path.clone(),
    });
    reporter(ParseEvent::Completed {
        manifest_path: manifest_path.clone(),
        total_entries: run_manifest.entries.len(),
        exported_records: run_manifest.exported_records,
    });

    Ok(ParseRunSummary {
        output_dir: resolved_output,
        extracted_dir,
        results_dir,
        manifest_path,
        manifest: run_manifest,
    })
}

fn resolve_opensearch_client(
    flag_url: Option<&str>,
    flag_username: Option<&str>,
    flag_password: Option<&str>,
    flag_index: Option<&str>,
    flag_insecure: bool,
    parse_mode: &str,
    zip_base: &str,
) -> Result<Option<OpenSearchClient>> {
    let resolved_url = if let Some(url) = first_non_empty([flag_url]) {
        Some(url.to_string())
    } else {
        build_url(
            first_non_empty([
                std::env::var("OPENSEARCH_HOST").ok().as_deref(),
                std::env::var("ELASTIC_SEARCH_HOST").ok().as_deref(),
            ]),
            first_non_empty([
                std::env::var("OPENSEARCH_PORT").ok().as_deref(),
                std::env::var("ELASTIC_SEARCH_PORT").ok().as_deref(),
            ]),
        )?
    };

    let Some(url) = resolved_url else {
        return Ok(None);
    };

    let index = first_non_empty([flag_index])
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_index_name(parse_mode, zip_base));

    Ok(Some(OpenSearchClient::new(OpenSearchConfig {
        url,
        username: first_non_empty([
            flag_username,
            std::env::var("OPENSEARCH_USERNAME").ok().as_deref(),
            std::env::var("ELASTIC_SEARCH_USERNAME").ok().as_deref(),
        ])
        .map(ToOwned::to_owned),
        password: first_non_empty([
            flag_password,
            std::env::var("OPENSEARCH_PASSWORD").ok().as_deref(),
            std::env::var("ELASTIC_SEARCH_PASSWORD").ok().as_deref(),
        ])
        .map(ToOwned::to_owned),
        index,
        insecure: flag_insecure
            || env_bool("OPENSEARCH_INSECURE")
            || env_bool("ELASTIC_SEARCH_INSECURE"),
        batch_size: 500,
    })?))
}

fn env_bool(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .ok()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn _display_path(path: &Path) -> String {
    path.display().to_string()
}

fn resolve_project_root(project_root: Option<PathBuf>) -> Result<PathBuf> {
    match project_root {
        Some(path) => Ok(path),
        None => parser_catalog::find_project_root(),
    }
}

fn resolve_enabled_parser_families() -> Result<Vec<parser_catalog::ParserFamily>> {
    let parser_families = parser_catalog::enabled_parser_families();
    parser_catalog::validate_enabled_parser_families(&parser_families)?;
    Ok(parser_families)
}

fn build_planned_families(
    extracted_dir: &Path,
    parser_families: &[parser_catalog::ParserFamily],
) -> Result<Vec<(parser_catalog::ParserFamily, Option<Vec<parsers::Plan>>)>> {
    parser_families
        .iter()
        .filter(|family| family.enabled)
        .map(|family| {
            let plans = parsers::build_plans(extracted_dir, family)?;
            Ok((family.clone(), plans))
        })
        .collect::<Result<Vec<_>>>()
}

fn zip_base(input: &Path) -> String {
    input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("collection")
        .to_string()
}

fn normalize_collection_volumes(volumes: &[String]) -> Result<Vec<String>> {
    let mut normalized_volumes = Vec::new();
    for volume in volumes {
        let normalized = usn_journal::normalize_volume(volume)?;
        if !normalized_volumes
            .iter()
            .any(|existing| existing == &normalized)
        {
            normalized_volumes.push(normalized);
        }
    }

    if normalized_volumes.is_empty() {
        return Err(anyhow!(
            "select at least one source volume before creating a package"
        ));
    }

    Ok(normalized_volumes)
}

fn collection_archive_requests_elevation(request: &CollectionArchiveRequest) -> bool {
    request
        .usn
        .as_ref()
        .map(|options| options.elevate)
        .unwrap_or(false)
        || request
            .registry
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .evtx
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .srum
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .browser_artifacts
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .mft
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .logfile
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
        || request
            .indx
            .as_ref()
            .map(|options| options.elevate)
            .unwrap_or(false)
}

fn should_share_vss_snapshot(request: &CollectionArchiveRequest) -> bool {
    let usn_uses_vss = request
        .usn
        .as_ref()
        .map(|options| {
            matches!(
                options.mode,
                usn_journal::UsnDumpMode::VssSnapshot | usn_journal::UsnDumpMode::VssRawNtfs
            )
        })
        .unwrap_or(false);
    let registry_uses_vss = request
        .registry
        .as_ref()
        .map(|options| matches!(options.method, registry::RegistryCollectMethod::VssSnapshot))
        .unwrap_or(false);
    let evtx_uses_vss = request.evtx.is_some();
    let srum_uses_vss = request.srum.is_some();
    let browser_artifacts_uses_vss = request.browser_artifacts.is_some();
    let mft_uses_vss = request
        .mft
        .as_ref()
        .map(|options| matches!(options.mode, mft::MftAcquisitionMode::Vss))
        .unwrap_or(false);
    let logfile_uses_vss = request
        .logfile
        .as_ref()
        .map(|options| matches!(options.mode, logfile::LogFileAcquisitionMode::Vss))
        .unwrap_or(false);
    let indx_uses_vss = request
        .indx
        .as_ref()
        .map(|options| matches!(options.mode, indx::IndxAcquisitionMode::Vss))
        .unwrap_or(false);
    [
        usn_uses_vss,
        registry_uses_vss,
        evtx_uses_vss,
        srum_uses_vss,
        browser_artifacts_uses_vss,
        mft_uses_vss,
        logfile_uses_vss,
        indx_uses_vss,
    ]
    .into_iter()
    .filter(|uses_vss| *uses_vss)
    .count()
        > 1
}

fn stage_usn_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &UsnCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let volume_prefix = normalized_volume.trim_end_matches(':');
    let raw_path = staging_dir.join(format!("{}_usn_journal_J.bin", volume_prefix));
    let archive_raw_path = usn_archive_raw_path(normalized_volume)?;
    let archive_metadata_path = collection_metadata::collector_manifest_archive_path(
        normalized_volume,
        collection_metadata::WINDOWS_USN_JOURNAL_COLLECTOR,
    )?;
    let metadata_path = staging_dir.join(&archive_metadata_path);
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "$UsnJrnl".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing USN Journal collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: usn_journal::UsnProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "$UsnJrnl".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let args = usn_journal::UsnDumpCli {
        volume: normalized_volume.to_string(),
        out: raw_path.clone(),
        metadata: Some(metadata_path.clone()),
        mode: options.mode,
        sparse: options.sparse,
        chunk_size_mib: options.chunk_size_mib,
        diagnostic_log: None,
        elevate: options.elevate,
    };
    if let Some(shadow_copy) = shared_shadow_copy {
        usn_journal::run_with_progress_using_shadow_copy(
            &args,
            shadow_copy,
            &mut progress_reporter,
        )?;
    } else {
        usn_journal::run_with_progress(&args, &mut progress_reporter)?;
    }

    archive_entries.push(collection::ArchiveEntry {
        source_path: raw_path.clone(),
        archive_path: archive_raw_path.clone(),
    });
    archive_entries.push(collection::ArchiveEntry {
        source_path: metadata_path.clone(),
        archive_path: archive_metadata_path.clone(),
    });
    staged_paths.push(raw_path);
    staged_paths.push(metadata_path);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "$UsnJrnl".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged the USN Journal from {normalized_volume}."),
        progress_text: "Ready for packaging".to_string(),
        staged_paths: 2,
        artifact_paths: vec![
            normalize_archive_path_string(&archive_raw_path),
            normalize_archive_path_string(&archive_metadata_path),
        ],
    });
    Ok(())
}

fn stage_registry_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &RegistryCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "Registry Hives".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing registry collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: registry::RegistryProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "Registry Hives".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = registry::RegistryCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        manifest: Some(registry::default_manifest_path(
            staging_dir,
            normalized_volume,
        )?),
        collection_log: Some(registry::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        method: options.method,
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        registry::collect_with_progress_using_shadow_copy(
            &request,
            shadow_copy,
            &mut progress_reporter,
        )?
    } else {
        registry::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = registry_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "Registry Hives".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged registry artifacts from {normalized_volume}."),
        progress_text: format!("{staged_count} staged files"),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn stage_evtx_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &EvtxCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "Windows Event Logs".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing EVTX collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: evtx::EvtxProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "Windows Event Logs".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = evtx::EvtxCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        manifest: Some(evtx::default_manifest_path(staging_dir, normalized_volume)?),
        collection_log: Some(evtx::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        evtx::collect_with_progress_using_shadow_copy(
            &request,
            shadow_copy,
            &mut progress_reporter,
        )?
    } else {
        evtx::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = evtx_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "Windows Event Logs".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged EVTX logs from {normalized_volume}."),
        progress_text: format!(
            "{} copied, {} failed",
            summary.file_records.len(),
            summary.failures.len()
        ),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn stage_srum_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &SrumCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "SRUM".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing SRUM collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: srum::SrumProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "SRUM".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = srum::SrumCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        manifest: Some(srum::default_manifest_path(staging_dir, normalized_volume)?),
        collection_log: Some(srum::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        srum::collect_with_progress_using_shadow_copy(
            &request,
            shadow_copy,
            &mut progress_reporter,
        )?
    } else {
        srum::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = srum_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "SRUM".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged SRUM files from {normalized_volume}."),
        progress_text: format!(
            "{} copied, {} failed",
            summary.file_records.len(),
            summary.failures.len()
        ),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn stage_browser_artifacts_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &BrowserArtifactsCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "Browser Artifacts".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing browser artifact collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: browser_artifacts::BrowserArtifactsProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "Browser Artifacts".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = browser_artifacts::BrowserArtifactsCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        manifest: Some(browser_artifacts::default_manifest_path(
            staging_dir,
            normalized_volume,
        )?),
        collection_log: Some(browser_artifacts::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        browser_artifacts::collect_with_progress_using_shadow_copy(
            &request,
            shadow_copy,
            &mut progress_reporter,
        )?
    } else {
        browser_artifacts::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = browser_artifacts_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "Browser Artifacts".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged browser artifacts from {normalized_volume}."),
        progress_text: format!(
            "{} copied, {} failed",
            summary.file_records.len(),
            summary.failures.len()
        ),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn stage_mft_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &MftCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "$MFT".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing $MFT collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: mft::MftProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "$MFT".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = mft::MftCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        mode: options.mode,
        manifest: Some(mft::default_manifest_path(staging_dir, normalized_volume)?),
        collection_log: Some(mft::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        if matches!(options.mode, mft::MftAcquisitionMode::Vss) {
            mft::collect_with_progress_using_shadow_copy(
                &request,
                shadow_copy,
                &mut progress_reporter,
            )?
        } else {
            mft::collect_with_progress(&request, &mut progress_reporter)?
        }
    } else {
        mft::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = mft_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "$MFT".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged $MFT from {normalized_volume}."),
        progress_text: format!("{} collected", summary.bytes_written),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn mft_collection_artifact_paths(summary: &mft::MftCollectSummary) -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(relative_artifact) = summary.artifact_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_artifact));
    } else {
        paths.push(summary.archive_path.clone());
    }
    if let Ok(relative_sha256) = summary.sha256_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_sha256));
    }
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn stage_logfile_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &LogFileCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "$LogFile".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing $LogFile collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: logfile::LogFileProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "$LogFile".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = logfile::LogFileCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        mode: options.mode,
        manifest: Some(logfile::default_manifest_path(
            staging_dir,
            normalized_volume,
        )?),
        collection_log: Some(logfile::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        if matches!(options.mode, logfile::LogFileAcquisitionMode::Vss) {
            logfile::collect_with_progress_using_shadow_copy(
                &request,
                shadow_copy,
                &mut progress_reporter,
            )?
        } else {
            logfile::collect_with_progress(&request, &mut progress_reporter)?
        }
    } else {
        logfile::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = logfile_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "$LogFile".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged $LogFile from {normalized_volume}."),
        progress_text: format!("{} collected", summary.bytes_written),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn logfile_collection_artifact_paths(summary: &logfile::LogFileCollectSummary) -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(relative_artifact) = summary.artifact_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_artifact));
    } else {
        paths.push(summary.archive_path.clone());
    }
    if let Ok(relative_sha256) = summary.sha256_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_sha256));
    }
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn stage_indx_collection(
    normalized_volume: &str,
    staging_dir: &Path,
    options: &IndxCollectionOptions,
    shared_shadow_copy: Option<&vss::ShadowCopy>,
    reporter: &mut dyn FnMut(CollectionEvent),
    archive_entries: &mut Vec<collection::ArchiveEntry>,
    staged_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    reporter(CollectionEvent::CollectorStarted {
        collection_title: "INDX Records".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 0.02,
        detail: format!("Preparing INDX collection on {normalized_volume}."),
        progress_text: "Starting".to_string(),
    });
    let mut progress_reporter = |progress: indx::IndxProgress| {
        reporter(CollectionEvent::CollectorProgress {
            collection_title: "INDX Records".to_string(),
            volume: normalized_volume.to_string(),
            progress_value: progress.progress_value,
            detail: progress.detail,
            progress_text: progress.progress_text,
        });
    };
    let request = indx::IndxCollectRequest {
        volume: normalized_volume.to_string(),
        out_dir: staging_dir.to_path_buf(),
        mode: options.mode,
        manifest: Some(indx::default_manifest_path(staging_dir, normalized_volume)?),
        collection_log: Some(indx::default_collection_log_path(
            staging_dir,
            normalized_volume,
        )?),
        diagnostic_log: None,
        elevate: options.elevate,
        include_deleted_dirs: options.include_deleted_dirs,
        max_directories: options.max_directories,
    };
    let summary = if let Some(shadow_copy) = shared_shadow_copy {
        if matches!(options.mode, indx::IndxAcquisitionMode::Vss) {
            indx::collect_with_progress_using_shadow_copy(
                &request,
                shadow_copy,
                &mut progress_reporter,
            )?
        } else {
            indx::collect_with_progress(&request, &mut progress_reporter)?
        }
    } else {
        indx::collect_with_progress(&request, &mut progress_reporter)?
    };

    add_staged_paths_as_archive_entries(staging_dir, &summary.staged_paths, archive_entries)?;
    let staged_count = summary.staged_paths.len();
    let artifact_paths = indx_collection_artifact_paths(&summary);
    staged_paths.extend(summary.staged_paths);
    reporter(CollectionEvent::CollectorFinished {
        collection_title: "INDX Records".to_string(),
        volume: normalized_volume.to_string(),
        progress_value: 1.0,
        detail: format!("Collected and staged INDX records from {normalized_volume}."),
        progress_text: format!("{} collected", summary.bytes_written),
        staged_paths: staged_count,
        artifact_paths,
    });
    Ok(())
}

fn indx_collection_artifact_paths(summary: &indx::IndxCollectSummary) -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(relative_artifact) = summary.artifact_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_artifact));
    } else {
        paths.push(summary.archive_path.clone());
    }
    if let Ok(relative_sha256) = summary.sha256_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_sha256));
    }
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn evtx_collection_artifact_paths(summary: &evtx::EvtxCollectSummary) -> Vec<String> {
    let mut paths = summary
        .file_records
        .iter()
        .map(|record| record.archive_path.clone())
        .collect::<Vec<_>>();
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn registry_collection_artifact_paths(summary: &registry::RegistryCollectSummary) -> Vec<String> {
    let mut paths = summary
        .file_records
        .iter()
        .map(|record| record.archive_path.clone())
        .collect::<Vec<_>>();
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn srum_collection_artifact_paths(summary: &srum::SrumCollectSummary) -> Vec<String> {
    let mut paths = summary
        .file_records
        .iter()
        .map(|record| record.archive_path.clone())
        .collect::<Vec<_>>();
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn browser_artifacts_collection_artifact_paths(
    summary: &browser_artifacts::BrowserArtifactsCollectSummary,
) -> Vec<String> {
    let mut paths = summary
        .file_records
        .iter()
        .map(|record| record.archive_path.clone())
        .collect::<Vec<_>>();
    if let Ok(relative_manifest) = summary.manifest_path.strip_prefix(&summary.output_root) {
        paths.push(normalize_archive_path_string(relative_manifest));
    }
    if let Ok(relative_log) = summary
        .collection_log_path
        .strip_prefix(&summary.output_root)
    {
        paths.push(normalize_archive_path_string(relative_log));
    }
    paths
}

fn add_staged_paths_as_archive_entries(
    staging_dir: &Path,
    paths: &[PathBuf],
    archive_entries: &mut Vec<collection::ArchiveEntry>,
) -> Result<()> {
    let mut existing_archive_paths = archive_entries
        .iter()
        .map(|entry| normalize_archive_path_string(&entry.archive_path))
        .collect::<BTreeSet<_>>();
    for source_path in paths {
        let archive_path = source_path.strip_prefix(staging_dir).with_context(|| {
            format!(
                "resolve staged artifact {} relative to staging root {}",
                source_path.display(),
                staging_dir.display()
            )
        })?;
        let normalized_archive_path = normalize_archive_path_string(archive_path);
        if !existing_archive_paths.insert(normalized_archive_path) {
            continue;
        }
        archive_entries.push(collection::ArchiveEntry {
            source_path: source_path.clone(),
            archive_path: archive_path.to_path_buf(),
        });
    }
    Ok(())
}

fn normalize_archive_path_string(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn prepare_clean_directory(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("remove directory {}", path.display()))?;
    }
    fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))
}

// Map the NTFS stream to a regular file path so the archive extracts cleanly on Windows.
fn usn_archive_raw_path(volume: &str) -> Result<PathBuf> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    Ok(PathBuf::from(normalized_volume.trim_end_matches(':'))
        .join("$Extend")
        .join("$UsnJrnl")
        .join("$J.bin"))
}

fn plan_id(plan: &parsers::Plan) -> String {
    format!("{}::{}", plan.parser, plan.artifact)
}

#[cfg(target_os = "windows")]
fn relaunch_collection_archive_worker(
    request: &CollectionArchiveRequest,
    reporter: &mut dyn FnMut(CollectionEvent),
) -> Result<CollectionArchiveSummary> {
    let (request_path, summary_path, event_log_path) = collection_archive_worker_paths()?;
    let write_result = write_collection_archive_worker_request(&request_path, request);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&request_path);
        let _ = fs::remove_file(&summary_path);
        let _ = fs::remove_file(&event_log_path);
        return Err(error);
    }

    let result = relaunch_collection_archive_worker_process(
        &request_path,
        &summary_path,
        &event_log_path,
        reporter,
    )
    .and_then(|_| load_collection_archive_worker_summary(&summary_path));

    match result {
        Ok(summary) => {
            let _ = fs::remove_file(&request_path);
            let _ = fs::remove_file(&summary_path);
            let _ = fs::remove_file(&event_log_path);
            Ok(summary)
        }
        Err(error) => Err(error.context(format!(
            "collection worker traces preserved for inspection: request={}, summary={}, events={}",
            request_path.display(),
            summary_path.display(),
            event_log_path.display()
        ))),
    }
}

#[cfg(target_os = "windows")]
fn write_collection_archive_worker_request(
    path: &Path,
    request: &CollectionArchiveRequest,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection worker directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(request)?;
    fs::write(path, bytes)
        .with_context(|| format!("write collection worker request {}", path.display()))
}

#[cfg(target_os = "windows")]
fn load_collection_archive_worker_summary(path: &Path) -> Result<CollectionArchiveSummary> {
    let bytes = fs::read(path)
        .with_context(|| format!("read collection worker summary {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decode collection worker summary {}", path.display()))
}

#[cfg(target_os = "windows")]
fn collection_archive_worker_paths() -> Result<(PathBuf, PathBuf, PathBuf)> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let dir = runtime_support::forensics_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("create collection worker directory {}", dir.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let base = format!("collection-archive-worker-{}-{stamp}", std::process::id());
    Ok((
        dir.join(format!("{base}.request.json")),
        dir.join(format!("{base}.summary.json")),
        dir.join(format!("{base}.events.jsonl")),
    ))
}

#[cfg(target_os = "windows")]
fn relaunch_collection_archive_worker_process(
    request_path: &Path,
    summary_path: &Path,
    event_log_path: &Path,
    reporter: &mut dyn FnMut(CollectionEvent),
) -> Result<()> {
    use std::mem::size_of;

    use anyhow::bail;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::{PCWSTR, w};

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    let current_exe = std::env::current_exe().context("resolve current executable path")?;
    let current_dir = std::env::current_dir().context("resolve current working directory")?;
    let parameters = vec![
        "collect-collection-archive-worker".to_string(),
        "--request".to_string(),
        request_path.display().to_string(),
        "--summary".to_string(),
        summary_path.display().to_string(),
        "--event-log".to_string(),
        event_log_path.display().to_string(),
    ]
    .into_iter()
    .map(|value| quote_windows_argument(&value))
    .collect::<Vec<_>>()
    .join(" ");

    let current_exe_wide = encode_wide_os(current_exe.as_os_str());
    let current_dir_wide = encode_wide_os(current_dir.as_os_str());
    let parameters_wide = encode_wide(&parameters);

    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(current_exe_wide.as_ptr()),
        lpParameters: PCWSTR(parameters_wide.as_ptr()),
        lpDirectory: PCWSTR(current_dir_wide.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut execute) }
        .context("launch elevated collection archive worker")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a collection worker process handle");
    }

    let process = ProcessHandle(execute.hProcess);
    let mut event_offset = 0u64;
    loop {
        let wait_status = unsafe { WaitForSingleObject(process.0, 200) };
        replay_collection_archive_worker_events(event_log_path, &mut event_offset, reporter)?;
        if wait_status == WAIT_TIMEOUT {
            continue;
        }
        if wait_status != WAIT_OBJECT_0 {
            bail!("unexpected wait status from elevated collection archive worker");
        }
        break;
    }

    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
        .context("read elevated collection archive worker exit code")?;
    if exit_code != 0 {
        bail!("elevated collection archive worker exited with status {exit_code}");
    }
    Ok(())
}

fn selected_runtime_collector_count(request: &CollectionArchiveRequest) -> usize {
    usize::from(request.usn.is_some())
        + usize::from(request.registry.is_some())
        + usize::from(request.evtx.is_some())
        + usize::from(request.srum.is_some())
        + usize::from(request.browser_artifacts.is_some())
        + usize::from(request.mft.is_some())
        + usize::from(request.logfile.is_some())
        + usize::from(request.indx.is_some())
}

fn planned_runtime_job_count(
    request: &CollectionArchiveRequest,
    normalized_volumes: &[String],
) -> usize {
    let collectors = selected_runtime_collector_count(request);
    collectors.saturating_mul(normalized_volumes.len())
}

#[cfg(target_os = "windows")]
fn write_collection_archive_worker_event(path: &Path, event: &CollectionEvent) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create collection worker event directory {}",
                parent.display()
            )
        })?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open collection worker event log {}", path.display()))?;
    let mut bytes = serde_json::to_vec(event)?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .with_context(|| format!("write collection worker event log {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush collection worker event log {}", path.display()))
}

#[cfg(target_os = "windows")]
fn replay_collection_archive_worker_events(
    path: &Path,
    offset: &mut u64,
    reporter: &mut dyn FnMut(CollectionEvent),
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let bytes = fs::read(path)
        .with_context(|| format!("read collection worker event log {}", path.display()))?;
    if (*offset as usize) >= bytes.len() {
        return Ok(());
    }

    let slice = &bytes[*offset as usize..];
    for line in slice.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let event: CollectionEvent = serde_json::from_slice(line)
            .with_context(|| format!("decode collection worker event from {}", path.display()))?;
        reporter(event);
    }
    *offset = bytes.len() as u64;
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_process_elevated() -> Result<bool> {
    use std::ffi::c_void;
    use std::mem::size_of;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    let mut raw_token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) }
        .context("open current process token for elevation check")?;
    let token = TokenHandle(raw_token);

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .context("query token elevation state")?;

    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(target_os = "windows")]
fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn encode_wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty() && !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }

    let mut output = String::from("\"");
    let mut backslash_count = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslash_count += 1,
            '"' => {
                output.push_str(&"\\".repeat((backslash_count * 2) + 1));
                output.push('"');
                backslash_count = 0;
            }
            _ => {
                if backslash_count > 0 {
                    output.push_str(&"\\".repeat(backslash_count));
                    backslash_count = 0;
                }
                output.push(character);
            }
        }
    }

    if backslash_count > 0 {
        output.push_str(&"\\".repeat(backslash_count * 2));
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use serde_json::json;

    use super::{
        BrowserArtifactsCollectionOptions, CollectionArchiveRequest, EvtxCollectionOptions,
        IndxCollectionOptions, LogFileCollectionOptions, MftCollectionOptions,
        RegistryCollectionOptions, SrumCollectionOptions, UsnCollectionOptions,
        add_staged_paths_as_archive_entries, collection_archive_requests_elevation,
        should_share_vss_snapshot, usn_archive_raw_path,
    };
    use crate::collection;
    use crate::collection_metadata;
    use crate::collections::windows::{indx, logfile, mft, registry, usn_journal};

    #[test]
    fn usn_archive_raw_path_preserves_logical_usn_parents() -> Result<()> {
        assert_eq!(
            usn_archive_raw_path("c:")?,
            PathBuf::from("C")
                .join("$Extend")
                .join("$UsnJrnl")
                .join("$J.bin")
        );
        Ok(())
    }

    #[test]
    fn usn_archive_metadata_path_uses_central_collector_manifest_root() -> Result<()> {
        assert_eq!(
            collection_metadata::collector_manifest_archive_path(
                r"\\?\c:",
                collection_metadata::WINDOWS_USN_JOURNAL_COLLECTOR,
            )?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_usn_journal")
                .join("manifest.json")
        );
        Ok(())
    }

    #[test]
    fn staged_archive_entries_skip_duplicate_archive_paths() -> Result<()> {
        let staging_dir = PathBuf::from(r"C:\evidence\staging");
        let mut entries = vec![collection::ArchiveEntry {
            source_path: staging_dir
                .join("C")
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE"),
            archive_path: PathBuf::from("C")
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE"),
        }];
        let paths = vec![
            staging_dir
                .join("C")
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE"),
            staging_dir
                .join("C")
                .join("Windows")
                .join("System32")
                .join("sru")
                .join("SRUDB.dat"),
        ];

        add_staged_paths_as_archive_entries(&staging_dir, &paths, &mut entries)?;

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1].archive_path,
            PathBuf::from("C")
                .join("Windows")
                .join("System32")
                .join("sru")
                .join("SRUDB.dat")
        );
        Ok(())
    }

    #[test]
    fn collection_archive_requests_elevation_when_any_collector_requires_it() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: Some(UsnCollectionOptions {
                mode: usn_journal::UsnDumpMode::VssRawNtfs,
                sparse: false,
                chunk_size_mib: 4,
                elevate: false,
            }),
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: true,
            }),
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(collection_archive_requests_elevation(&request));
    }

    #[test]
    fn collection_archive_requests_elevation_is_false_when_all_collectors_are_unelevated() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: Some(UsnCollectionOptions {
                mode: usn_journal::UsnDumpMode::DirectStream,
                sparse: false,
                chunk_size_mib: 4,
                elevate: false,
            }),
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::RegSave,
                elevate: false,
            }),
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(!collection_archive_requests_elevation(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_usn_and_registry_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: Some(UsnCollectionOptions {
                mode: usn_journal::UsnDumpMode::VssRawNtfs,
                sparse: false,
                chunk_size_mib: 4,
                elevate: false,
            }),
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: false,
            }),
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_evtx_and_registry_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: false,
            }),
            evtx: Some(EvtxCollectionOptions { elevate: false }),
            srum: None,
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_mft_and_evtx_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: None,
            evtx: Some(EvtxCollectionOptions { elevate: false }),
            srum: None,
            browser_artifacts: None,
            mft: Some(MftCollectionOptions {
                mode: mft::MftAcquisitionMode::Vss,
                elevate: false,
            }),
            logfile: None,
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_logfile_and_mft_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: None,
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: Some(MftCollectionOptions {
                mode: mft::MftAcquisitionMode::Vss,
                elevate: false,
            }),
            logfile: Some(LogFileCollectionOptions {
                mode: logfile::LogFileAcquisitionMode::Vss,
                elevate: false,
            }),
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_indx_and_mft_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: None,
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: Some(MftCollectionOptions {
                mode: mft::MftAcquisitionMode::Vss,
                elevate: false,
            }),
            logfile: None,
            indx: Some(IndxCollectionOptions {
                mode: indx::IndxAcquisitionMode::Vss,
                include_deleted_dirs: false,
                max_directories: None,
                elevate: false,
            }),
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_srum_and_registry_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: false,
            }),
            evtx: None,
            srum: Some(SrumCollectionOptions { elevate: false }),
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_shares_vss_when_browser_artifacts_and_registry_are_vss_backed() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: None,
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: false,
            }),
            evtx: None,
            srum: None,
            browser_artifacts: Some(BrowserArtifactsCollectionOptions { elevate: false }),
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_does_not_share_vss_when_usn_is_direct_stream() {
        let request = CollectionArchiveRequest {
            volumes: vec!["C:".to_string()],
            output_zip: PathBuf::from(r"C:\temp\bundle.zip"),
            staging_root: None,
            usn: Some(UsnCollectionOptions {
                mode: usn_journal::UsnDumpMode::DirectStream,
                sparse: false,
                chunk_size_mib: 4,
                elevate: false,
            }),
            registry: Some(RegistryCollectionOptions {
                method: registry::RegistryCollectMethod::VssSnapshot,
                elevate: false,
            }),
            evtx: None,
            srum: None,
            browser_artifacts: None,
            mft: None,
            logfile: None,
            indx: None,
        };

        assert!(!should_share_vss_snapshot(&request));
    }

    #[test]
    fn collection_archive_request_json_round_trips_worker_options() -> Result<()> {
        let value = json!({
            "volumes": ["C:"],
            "output_zip": r"C:\temp\bundle.zip",
            "staging_root": r"C:\temp\bundle.staging",
            "usn": {
                "mode": "vss_raw_ntfs",
                "sparse": true,
                "chunk_size_mib": 8,
                "elevate": true
            },
            "registry": {
                "method": "vss_snapshot",
                "elevate": true
            },
            "evtx": {
                "elevate": true
            },
            "srum": {
                "elevate": true
            },
            "browser_artifacts": {
                "elevate": true
            },
            "mft": {
                "mode": "vss",
                "elevate": true
            },
            "logfile": {
                "mode": "vss",
                "elevate": true
            },
            "indx": {
                "mode": "vss",
                "include_deleted_dirs": false,
                "max_directories": 100,
                "elevate": true
            }
        });

        let request: CollectionArchiveRequest = serde_json::from_value(value)?;

        assert_eq!(request.volumes, vec!["C:".to_string()]);
        assert_eq!(request.output_zip, PathBuf::from(r"C:\temp\bundle.zip"));
        assert_eq!(
            request.staging_root,
            Some(PathBuf::from(r"C:\temp\bundle.staging"))
        );
        assert_eq!(
            request.usn.as_ref().map(|options| options.mode),
            Some(usn_journal::UsnDumpMode::VssRawNtfs)
        );
        assert_eq!(
            request.registry.as_ref().map(|options| options.method),
            Some(registry::RegistryCollectMethod::VssSnapshot)
        );
        assert_eq!(
            request.evtx.as_ref().map(|options| options.elevate),
            Some(true)
        );
        assert_eq!(
            request.srum.as_ref().map(|options| options.elevate),
            Some(true)
        );
        assert_eq!(
            request
                .browser_artifacts
                .as_ref()
                .map(|options| options.elevate),
            Some(true)
        );
        assert_eq!(
            request.mft.as_ref().map(|options| options.mode),
            Some(mft::MftAcquisitionMode::Vss)
        );
        assert_eq!(
            request.logfile.as_ref().map(|options| options.mode),
            Some(logfile::LogFileAcquisitionMode::Vss)
        );
        assert_eq!(
            request.indx.as_ref().map(|options| options.mode),
            Some(indx::IndxAcquisitionMode::Vss)
        );
        assert_eq!(
            request
                .indx
                .as_ref()
                .and_then(|options| options.max_directories),
            Some(100)
        );
        Ok(())
    }
}
