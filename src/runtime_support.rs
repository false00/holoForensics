use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use directories::BaseDirs;

const LOG_TAIL_BYTES: u64 = 64 * 1024;

pub fn forensics_dir() -> PathBuf {
    BaseDirs::new()
        .map(|dirs| forensics_dir_from_home(dirs.home_dir()))
        .unwrap_or_else(|| {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".holo-forensics")
        })
}

pub fn technical_log_path() -> PathBuf {
    technical_log_path_from_dir(&forensics_dir())
}

pub fn app_settings_path() -> PathBuf {
    app_settings_path_from_dir(&forensics_dir())
}

pub fn shadow_copy_tracker_path() -> PathBuf {
    shadow_copy_tracker_path_from_dir(&forensics_dir())
}

pub fn append_technical_log(source: &str, message: impl AsRef<str>) -> Result<()> {
    let path = technical_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create runtime directory {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open technical log {}", path.display()))?;

    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    for line in message.as_ref().lines() {
        writeln!(
            file,
            "[{timestamp}] pid={} source={} {}",
            std::process::id(),
            source,
            line
        )
        .with_context(|| format!("write technical log {}", path.display()))?;
    }
    file.flush()
        .with_context(|| format!("flush technical log {}", path.display()))
}

pub fn read_technical_log_tail(max_lines: usize) -> Result<String> {
    read_log_tail(&technical_log_path(), max_lines, LOG_TAIL_BYTES)
}

fn read_log_tail(path: &Path, max_lines: usize, max_bytes: u64) -> Result<String> {
    if max_lines == 0 || !path.exists() {
        return Ok(String::new());
    }

    let mut file =
        File::open(path).with_context(|| format!("open technical log {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("read technical log metadata {}", path.display()))?
        .len();
    let start = file_len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seek technical log {}", path.display()))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read technical log {}", path.display()))?;

    let starts_mid_line = start > 0 && !matches!(bytes.first(), Some(b'\n' | b'\r'));
    let content = String::from_utf8_lossy(&bytes);
    let mut lines = content.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    if starts_mid_line && !lines.is_empty() {
        lines.remove(0);
    }
    if lines.len() > max_lines {
        let drain_count = lines.len() - max_lines;
        lines.drain(0..drain_count);
    }
    Ok(lines.join("\n"))
}

fn forensics_dir_from_home(home: &Path) -> PathBuf {
    home.join(".holo-forensics")
}

fn technical_log_path_from_dir(dir: &Path) -> PathBuf {
    dir.join("holo-forensics.log")
}

fn app_settings_path_from_dir(dir: &Path) -> PathBuf {
    dir.join("app-settings.json")
}

fn shadow_copy_tracker_path_from_dir(dir: &Path) -> PathBuf {
    dir.join("vss-shadow-copies.json")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        app_settings_path_from_dir, forensics_dir_from_home, read_log_tail,
        shadow_copy_tracker_path_from_dir, technical_log_path_from_dir,
    };

    #[test]
    fn forensics_dir_uses_hidden_home_subdirectory() {
        let home = PathBuf::from(r"C:\Users\Analyst");
        assert_eq!(
            forensics_dir_from_home(&home),
            PathBuf::from(r"C:\Users\Analyst\.holo-forensics")
        );
    }

    #[test]
    fn technical_and_settings_paths_use_forensics_directory() {
        let dir = forensics_dir_from_home(Path::new(r"C:\Users\Analyst"));
        assert_eq!(
            technical_log_path_from_dir(&dir),
            PathBuf::from(r"C:\Users\Analyst\.holo-forensics\holo-forensics.log")
        );
        assert_eq!(
            app_settings_path_from_dir(&dir),
            PathBuf::from(r"C:\Users\Analyst\.holo-forensics\app-settings.json")
        );
        assert_eq!(
            shadow_copy_tracker_path_from_dir(&dir),
            PathBuf::from(r"C:\Users\Analyst\.holo-forensics\vss-shadow-copies.json")
        );
    }

    #[test]
    fn read_log_tail_keeps_only_requested_lines() -> Result<()> {
        let temp = tempdir()?;
        let log_path = temp.path().join("holo-forensics.log");
        fs::write(&log_path, "one\ntwo\nthree\nfour\n")?;

        let tail = read_log_tail(&log_path, 2, 1024)?;

        assert_eq!(tail, "three\nfour");
        Ok(())
    }
}
