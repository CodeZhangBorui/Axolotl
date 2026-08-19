use super::model::Integrity;
use crate::util::io::{self, IOError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;
use tokio::fs::File;
use tokio::sync::Mutex as AsyncMutex;

static IN_FLIGHT_DOWNLOADS: LazyLock<
	dashmap::DashMap<String, Weak<AsyncMutex<()>>>,
> = LazyLock::new(dashmap::DashMap::new);

const STALE_PARTIAL_DOWNLOAD_MAX_AGE: Duration =
	Duration::from_secs(7 * 24 * 60 * 60);

pub(crate) fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
	let mut value = path.as_os_str().to_os_string();
	value.push(suffix);
	PathBuf::from(value)
}

pub(crate) async fn remove_if_exists(path: &Path) -> crate::Result<()> {
	match io::retry_windows_sharing_violation(path, "removing", || {
		tokio::fs::remove_file(path)
	})
	.await
	{
		Ok(()) => Ok(()),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(io::io_error_with_lock_info(error, path).into()),
	}
}

pub(crate) async fn create_download_file(path: &Path) -> Result<File, IOError> {
	io::retry_windows_sharing_violation(path, "creating download file", || {
		File::create(path)
	})
	.await
	.map_err(|error| io::io_error_with_lock_info(error, path))
}

pub(crate) async fn open_download_file_for_append(
	path: &Path,
) -> Result<File, IOError> {
	io::retry_windows_sharing_violation(path, "opening download file", || async {
		tokio::fs::OpenOptions::new().append(true).open(path).await
	})
	.await
	.map_err(|error| io::io_error_with_lock_info(error, path))
}

pub(crate) async fn preserve_or_remove_partial(
	part_path: &Path,
	integrity: &Integrity,
	routes_can_resume: bool,
) -> crate::Result<()> {
	let resumable = routes_can_resume
		&& integrity.supports_resume()
		&& tokio::fs::metadata(part_path)
			.await
			.is_ok_and(|metadata| metadata.len() > 0);
	if !resumable {
		remove_if_exists(part_path).await?;
	}
	Ok(())
}

pub(crate) async fn part_resume_expected(part_path: &Path) -> bool {
	tokio::fs::metadata(part_path)
		.await
		.map(|metadata| metadata.len() > 0)
		.unwrap_or(false)
}

fn is_partial_download_file_name(name: &str) -> bool {
	name.ends_with(".part")
		|| name
			.rsplit_once(".segment-")
			.is_some_and(|(prefix, index)| {
				prefix.ends_with(".part")
					&& !index.is_empty()
					&& index.bytes().all(|byte| byte.is_ascii_digit())
			})
}

pub fn cleanup_stale_partial_downloads(directories: Vec<PathBuf>) {
	tokio::task::spawn_blocking(move || {
		let Some(cutoff) = std::time::SystemTime::now()
			.checked_sub(STALE_PARTIAL_DOWNLOAD_MAX_AGE)
		else {
			return;
		};
		let mut pending = directories;
		let mut removed = 0_u64;
		while let Some(directory) = pending.pop() {
			let Ok(entries) = std::fs::read_dir(&directory) else {
				continue;
			};
			for entry in entries.flatten() {
				let Ok(file_type) = entry.file_type() else {
					continue;
				};
				if file_type.is_dir() {
					pending.push(entry.path());
					continue;
				}
				if !file_type.is_file()
					|| !is_partial_download_file_name(&entry.file_name().to_string_lossy())
				{
					continue;
				}
				let stale = entry
					.metadata()
					.and_then(|metadata| metadata.modified())
					.is_ok_and(|modified| modified < cutoff);
				if stale && std::fs::remove_file(entry.path()).is_ok() {
					removed += 1;
				}
			}
		}
		if removed > 0 {
			tracing::info!(removed, "Removed stale partial download files");
		}
	});
}

fn download_lock_key(destination: &Path) -> String {
	let path = destination.display().to_string();
	if cfg!(windows) {
		path.to_uppercase()
	} else {
		path
	}
}

pub(crate) fn in_flight_download_lock(destination: &Path) -> Arc<AsyncMutex<()>> {
	use dashmap::mapref::entry::Entry;
	if IN_FLIGHT_DOWNLOADS.len() > 4_096 {
		IN_FLIGHT_DOWNLOADS.retain(|_, lock| lock.strong_count() > 0);
	}
	let key = download_lock_key(destination);
	match IN_FLIGHT_DOWNLOADS.entry(key) {
		Entry::Occupied(mut entry) => entry.get().upgrade().unwrap_or_else(|| {
			let lock = Arc::new(AsyncMutex::new(()));
			entry.insert(Arc::downgrade(&lock));
			lock
		}),
		Entry::Vacant(entry) => {
			let lock = Arc::new(AsyncMutex::new(()));
			entry.insert(Arc::downgrade(&lock));
			lock
		}
	}
}

pub(crate) async fn finalize_download(
	part_path: &Path,
	destination: &Path,
) -> crate::Result<()> {
	if io::retry_windows_sharing_violation(destination, "checking", || {
		tokio::fs::try_exists(destination)
	})
	.await
	.map_err(|error| io::io_error_with_lock_info(error, destination))?
	{
		remove_if_exists(destination).await?;
	}
	io::retry_windows_sharing_violation(destination, "finalizing download", || {
		tokio::fs::rename(part_path, destination)
	})
	.await
	.map_err(|error| {
		io::io_error_with_lock_info_for_paths(
			error,
			destination,
			&[destination, part_path],
		)
	})?;
	Ok(())
}
