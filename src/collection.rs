#![allow(dead_code)]

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub source_path: PathBuf,
    pub archive_path: PathBuf,
}

pub fn create_zip(zip_path: &Path, entries: &[ArchiveEntry]) -> Result<()> {
    if let Some(parent) = zip_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create zip parent {}", parent.display()))?;
    }

    let file =
        File::create(zip_path).with_context(|| format!("create zip {}", zip_path.display()))?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    for entry in entries {
        let archive_path = normalize_archive_path(&entry.archive_path)?;
        let mut source = File::open(&entry.source_path)
            .with_context(|| format!("open source {}", entry.source_path.display()))?;

        writer
            .start_file(&archive_path, options)
            .with_context(|| format!("start zip entry {archive_path}"))?;
        io::copy(&mut source, &mut writer)
            .with_context(|| format!("write zip entry {archive_path}"))?;
    }

    writer
        .finish()
        .with_context(|| format!("finish zip {}", zip_path.display()))?;
    Ok(())
}

pub fn extract_full(zip_path: &Path, destination: &Path) -> Result<()> {
    let file =
        File::open(zip_path).with_context(|| format!("open zip archive {}", zip_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("read zip archive {}", zip_path.display()))?;

    fs::create_dir_all(destination)
        .with_context(|| format!("create extraction directory {}", destination.display()))?;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let relative_path = entry
            .enclosed_name()
            .map(|path| path.to_path_buf())
            .ok_or_else(|| anyhow!("zip entry escapes destination: {}", entry.name()))?;
        let out_path = destination.join(relative_path);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut output = File::create(&out_path)?;
        io::copy(&mut entry, &mut output)?;
    }

    Ok(())
}

fn normalize_archive_path(path: &Path) -> Result<String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!(
                    "zip entry escapes archive root: {}",
                    path.display()
                ));
            }
        }
    }

    let normalized = normalized
        .to_string_lossy()
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();
    if normalized.is_empty() {
        return Err(anyhow!("zip entry path is empty"));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use zip::CompressionMethod;
    use zip::ZipArchive;
    use zip::write::SimpleFileOptions;

    use super::{ArchiveEntry, create_zip, extract_full};

    #[test]
    fn create_zip_writes_files_with_normalized_paths() {
        let temp = tempdir().unwrap();
        let source_dir = temp.path().join("source");
        let zip_path = temp.path().join("bundle.zip");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("alpha.txt"), b"alpha").unwrap();
        std::fs::write(source_dir.join("beta.txt"), b"beta").unwrap();

        create_zip(
            &zip_path,
            &[
                ArchiveEntry {
                    source_path: source_dir.join("alpha.txt"),
                    archive_path: PathBuf::from("C/alpha.txt"),
                },
                ArchiveEntry {
                    source_path: source_dir.join("beta.txt"),
                    archive_path: PathBuf::from("beta.txt"),
                },
            ],
        )
        .unwrap();

        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        {
            let alpha = archive.by_name("C/alpha.txt").unwrap();
            assert_eq!(alpha.size(), 5);
        }

        {
            let beta = archive.by_name("beta.txt").unwrap();
            assert_eq!(beta.size(), 4);
        }
    }

    #[test]
    fn create_zip_rejects_escape_paths() {
        let temp = tempdir().unwrap();
        let source_path = temp.path().join("alpha.txt");
        let zip_path = temp.path().join("bundle.zip");
        std::fs::write(&source_path, b"alpha").unwrap();

        let error = create_zip(
            &zip_path,
            &[ArchiveEntry {
                source_path,
                archive_path: PathBuf::from("../escape.txt"),
            }],
        )
        .unwrap_err();

        assert!(error.to_string().contains("zip entry escapes archive root"));
    }

    #[test]
    fn extract_full_writes_regular_entries() {
        let temp = tempdir().unwrap();
        let zip_path = temp.path().join("sample.zip");
        let destination = temp.path().join("out");

        let file = File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.add_directory("nested/", options).unwrap();
        writer.start_file("nested/file.txt", options).unwrap();
        writer.write_all(b"hello world").unwrap();
        writer.finish().unwrap();

        extract_full(&zip_path, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("nested").join("file.txt")).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn extract_full_rejects_path_escape_entries() {
        let temp = tempdir().unwrap();
        let zip_path = temp.path().join("escape.zip");
        let destination = temp.path().join("out");

        let file = File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("../escape.txt", options).unwrap();
        writer.write_all(b"blocked").unwrap();
        writer.finish().unwrap();

        let error = extract_full(&zip_path, &destination).unwrap_err();
        assert!(error.to_string().contains("zip entry escapes destination"));
        assert!(!destination.join("escape.txt").exists());
    }
}
