use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use holo_forensics::app::{self, ParseCli, ParseRunOptions};
use holo_forensics::collections::windows::{
    browser_artifacts, evtx, indx, jump_lists, logfile, mft, registry, srum, usn_journal,
};
use holo_forensics::desktop::{DesktopLaunchOptions, DesktopScreenshotState, DesktopThemeOverride};

#[derive(Debug, Clone, ValueEnum)]
enum ScreenshotState {
    Main,
    About,
    Settings,
    Scope,
    UsnSettings,
    CollectionProgress,
}

#[derive(Debug, Clone, ValueEnum)]
enum ThemeOverride {
    Auto,
    Dark,
    Light,
}

impl From<ScreenshotState> for DesktopScreenshotState {
    fn from(value: ScreenshotState) -> Self {
        match value {
            ScreenshotState::Main => DesktopScreenshotState::Main,
            ScreenshotState::About => DesktopScreenshotState::About,
            ScreenshotState::Settings => DesktopScreenshotState::Settings,
            ScreenshotState::Scope => DesktopScreenshotState::Scope,
            ScreenshotState::UsnSettings => DesktopScreenshotState::UsnSettings,
            ScreenshotState::CollectionProgress => DesktopScreenshotState::CollectionProgress,
        }
    }
}

impl From<ThemeOverride> for DesktopThemeOverride {
    fn from(value: ThemeOverride) -> Self {
        match value {
            ThemeOverride::Auto => DesktopThemeOverride::Auto,
            ThemeOverride::Dark => DesktopThemeOverride::Dark,
            ThemeOverride::Light => DesktopThemeOverride::Light,
        }
    }
}

#[derive(Debug, Clone, Args, Default)]
struct UiCli {
    #[arg(long)]
    validate_parse: Option<PathBuf>,

    #[arg(long)]
    validate_output: Option<PathBuf>,

    #[arg(long, value_enum)]
    screenshot_state: Option<ScreenshotState>,

    #[arg(long, value_enum)]
    theme: Option<ThemeOverride>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "collect-usn-journal")]
    CollectUsnJournal(usn_journal::UsnDumpCli),

    #[command(name = "collect-registry")]
    CollectRegistry(registry::RegistryCollectCli),

    #[command(name = "collect-evtx")]
    CollectEvtx(evtx::EvtxCollectCli),

    #[command(name = "collect-mft")]
    CollectMft(mft::MftCollectCli),

    #[command(name = "collect-logfile")]
    CollectLogFile(logfile::LogFileCollectCli),

    #[command(name = "collect-indx")]
    CollectIndx(indx::IndxCollectCli),

    #[command(name = "collect-srum")]
    CollectSrum(srum::SrumCollectCli),

    #[command(name = "collect-browser-artifacts")]
    CollectBrowserArtifacts(browser_artifacts::BrowserArtifactsCollectCli),

    #[command(name = "collect-jump-lists")]
    CollectJumpLists(jump_lists::JumpListsCollectCli),

    #[command(name = "collect-collection-archive-worker", hide = true)]
    CollectCollectionArchiveWorker(app::CollectionArchiveWorkerCli),

    #[command(name = "ui")]
    Ui(UiCli),
}

#[derive(Debug, Parser)]
#[command(name = "holo-forensics")]
#[command(about = "Holo Forensics offline artifact parsing and desktop collection UI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    parse: ParseCli,
}

fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();

    if should_launch_gui_by_default(&args) {
        maybe_detach_owned_console();
        if let Err(error) = launch_ui(UiCli::default()) {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
        return;
    }

    let cli = Cli::parse_from(args);
    let result = match cli.command {
        Some(Command::CollectUsnJournal(args)) => usn_journal::run(&args),
        Some(Command::CollectRegistry(args)) => registry::run(&args),
        Some(Command::CollectEvtx(args)) => evtx::run(&args),
        Some(Command::CollectMft(args)) => mft::run(&args),
        Some(Command::CollectLogFile(args)) => logfile::run(&args),
        Some(Command::CollectIndx(args)) => indx::run(&args),
        Some(Command::CollectSrum(args)) => srum::run(&args),
        Some(Command::CollectBrowserArtifacts(args)) => browser_artifacts::run(&args),
        Some(Command::CollectJumpLists(args)) => jump_lists::run(&args),
        Some(Command::CollectCollectionArchiveWorker(args)) => {
            app::run_collection_archive_worker(&args)
        }
        Some(Command::Ui(ui)) => launch_ui(ui),
        None => {
            if parse_cli_requested(&cli.parse) {
                run_parse(cli.parse)
            } else {
                print_help();
                Ok(())
            }
        }
    };

    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run_parse(parse: ParseCli) -> anyhow::Result<()> {
    let summary = app::run_parse_request(parse, ParseRunOptions::default(), |_| {})?;
    println!(
        "Holo Forensics completed. Manifest: {}",
        summary.manifest_path.display()
    );
    Ok(())
}

fn launch_ui(ui: UiCli) -> anyhow::Result<()> {
    if let Some(input) = ui.validate_parse {
        holo_forensics::desktop::validate_offline_parse(input, ui.validate_output)
    } else {
        holo_forensics::desktop::launch_with_options(DesktopLaunchOptions {
            screenshot_state: ui.screenshot_state.map(Into::into),
            theme_override: ui.theme.map(Into::into),
        })
    }
}

fn parse_cli_requested(parse: &ParseCli) -> bool {
    parse.input.is_some()
        || parse.output.is_some()
        || parse.opensearch_url.is_some()
        || parse.opensearch_username.is_some()
        || parse.opensearch_password.is_some()
        || parse.opensearch_index.is_some()
        || parse.opensearch_insecure
}

fn print_help() {
    let mut command = Cli::command();
    command.print_help().expect("print CLI help");
    println!();
}

fn should_launch_gui_by_default(args: &[std::ffi::OsString]) -> bool {
    should_launch_gui(args.len(), launched_from_existing_console())
}

fn should_launch_gui(args_len: usize, existing_console: bool) -> bool {
    args_len == 1 && !existing_console
}

#[cfg(target_os = "windows")]
fn launched_from_existing_console() -> bool {
    use windows::Win32::System::Console::GetConsoleProcessList;

    let mut processes = [0u32; 2];
    unsafe { GetConsoleProcessList(&mut processes) > 1 }
}

#[cfg(not(target_os = "windows"))]
fn launched_from_existing_console() -> bool {
    true
}

#[cfg(target_os = "windows")]
fn maybe_detach_owned_console() {
    use windows::Win32::System::Console::FreeConsole;

    let _ = unsafe { FreeConsole() };
}

#[cfg(not(target_os = "windows"))]
fn maybe_detach_owned_console() {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::{
        Cli, Command, UiCli, indx, logfile, mft, parse_cli_requested, registry, should_launch_gui,
    };

    #[test]
    fn no_arg_double_click_path_prefers_gui() {
        assert!(should_launch_gui(1, false));
        assert!(!should_launch_gui(1, true));
        assert!(!should_launch_gui(2, false));
    }

    #[test]
    fn parses_ui_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "ui",
            "--theme",
            "dark",
            "--screenshot-state",
            "settings",
        ])
        .expect("ui subcommand should parse");

        match cli.command {
            Some(Command::Ui(UiCli {
                theme: Some(_),
                screenshot_state: Some(_),
                ..
            })) => {}
            _ => panic!("ui subcommand was not parsed"),
        }
    }

    #[test]
    fn parses_collect_usn_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-usn-journal",
            "--volume",
            "C:",
            "--out",
            r"C:\temp\C_usn_journal_J.bin",
        ])
        .expect("collect-usn-journal should parse");

        match cli.command {
            Some(Command::CollectUsnJournal(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out, PathBuf::from(r"C:\temp\C_usn_journal_J.bin"));
            }
            _ => panic!("collect-usn-journal was not parsed"),
        }
    }

    #[test]
    fn parses_collect_registry_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-registry",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\registry",
        ])
        .expect("collect-registry should parse");

        match cli.command {
            Some(Command::CollectRegistry(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\registry"));
                assert_eq!(args.method, registry::RegistryCollectMethod::VssSnapshot);
            }
            _ => panic!("collect-registry was not parsed"),
        }
    }

    #[test]
    fn parses_collect_evtx_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-evtx",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\evtx",
        ])
        .expect("collect-evtx should parse");

        match cli.command {
            Some(Command::CollectEvtx(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\evtx"));
            }
            _ => panic!("collect-evtx was not parsed"),
        }
    }

    #[test]
    fn parses_collect_mft_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-mft",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\mft",
        ])
        .expect("collect-mft should parse");

        match cli.command {
            Some(Command::CollectMft(args)) => {
                assert_eq!(args.volume.as_deref(), Some("C:"));
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\mft"));
                assert_eq!(args.mode, mft::MftAcquisitionMode::Vss);
            }
            _ => panic!("collect-mft was not parsed"),
        }
    }

    #[test]
    fn parses_collect_logfile_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-logfile",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\logfile",
        ])
        .expect("collect-logfile should parse");

        match cli.command {
            Some(Command::CollectLogFile(args)) => {
                assert_eq!(args.volume.as_deref(), Some("C:"));
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\logfile"));
                assert_eq!(args.mode, logfile::LogFileAcquisitionMode::Vss);
            }
            _ => panic!("collect-logfile was not parsed"),
        }
    }

    #[test]
    fn parses_collect_indx_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-indx",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\indx",
        ])
        .expect("collect-indx should parse");

        match cli.command {
            Some(Command::CollectIndx(args)) => {
                assert_eq!(args.volume.as_deref(), Some("C:"));
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\indx"));
                assert_eq!(args.mode, indx::IndxAcquisitionMode::Vss);
            }
            _ => panic!("collect-indx was not parsed"),
        }
    }

    #[test]
    fn parses_collect_srum_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-srum",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\srum",
        ])
        .expect("collect-srum should parse");

        match cli.command {
            Some(Command::CollectSrum(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\srum"));
            }
            _ => panic!("collect-srum was not parsed"),
        }
    }

    #[test]
    fn parses_collect_browser_artifacts_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-browser-artifacts",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\browser",
        ])
        .expect("collect-browser-artifacts should parse");

        match cli.command {
            Some(Command::CollectBrowserArtifacts(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\browser"));
            }
            _ => panic!("collect-browser-artifacts was not parsed"),
        }
    }

    #[test]
    fn parses_collect_jump_lists_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-jump-lists",
            "--volume",
            "C:",
            "--out-dir",
            r"C:\temp\jump-lists",
        ])
        .expect("collect-jump-lists should parse");

        match cli.command {
            Some(Command::CollectJumpLists(args)) => {
                assert_eq!(args.volume, "C:");
                assert_eq!(args.out_dir, PathBuf::from(r"C:\temp\jump-lists"));
                assert!(args.artifact_manifest.is_none());
            }
            _ => panic!("collect-jump-lists was not parsed"),
        }
    }

    #[test]
    fn parses_hidden_collection_archive_worker_subcommand() {
        let cli = Cli::try_parse_from([
            "holo-forensics",
            "collect-collection-archive-worker",
            "--request",
            r"C:\temp\request.json",
            "--summary",
            r"C:\temp\summary.json",
            "--event-log",
            r"C:\temp\events.jsonl",
        ])
        .expect("collect-collection-archive-worker should parse");

        match cli.command {
            Some(Command::CollectCollectionArchiveWorker(args)) => {
                assert_eq!(args.request, PathBuf::from(r"C:\temp\request.json"));
                assert_eq!(args.summary, PathBuf::from(r"C:\temp\summary.json"));
                assert_eq!(args.event_log, PathBuf::from(r"C:\temp\events.jsonl"));
            }
            _ => panic!("collect-collection-archive-worker was not parsed"),
        }
    }

    #[test]
    fn recognizes_parse_flags_as_cli_mode() {
        let cli =
            Cli::try_parse_from(["holo-forensics", "--input", "sample.zip"]).expect("parse flags");
        assert!(parse_cli_requested(&cli.parse));
    }
}
