use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const SEGMENTED_DOWNLOAD_THRESHOLD: u64 = 4 * 1024 * 1024;
pub(crate) const MIN_SEGMENT_SIZE: u64 = 256 * 1024;
pub(crate) const INITIAL_SEGMENT_CONCURRENCY: usize = 4;
pub(crate) const SEGMENT_EXPANSION_SAMPLE_COUNT: usize = 3;
pub(crate) const SEGMENT_EXPANSION_INTERVAL: Duration =
	Duration::from_millis(1500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedContentRange {
	pub(crate) start: u64,
	pub(crate) end: u64,
	pub(crate) total: Option<u64>,
}

pub(crate) fn parse_content_range(
	response: &reqwest::Response,
) -> Option<ParsedContentRange> {
	let value = response
		.headers()
		.get(reqwest::header::CONTENT_RANGE)?
		.to_str()
		.ok()?
		.strip_prefix("bytes ")?;
	let (range, total) = value.split_once('/')?;
	let (start, end) = range.split_once('-')?;
	Some(ParsedContentRange {
		start: start.parse().ok()?,
		end: end.parse().ok()?,
		total: if total == "*" {
			None
		} else {
			Some(total.parse().ok()?)
		},
	})
}

pub(crate) fn initial_segment_count(
	size: u64,
	available_permits: usize,
) -> usize {
	let size_limit = usize::try_from(size / MIN_SEGMENT_SIZE)
		.unwrap_or(usize::MAX)
		.max(1);
	INITIAL_SEGMENT_CONCURRENCY
		.min(available_permits.min(4))
		.min(size_limit)
}

pub(crate) fn create_initial_ranges(size: u64, count: usize) -> Vec<DownloadRange> {
	let base_size = size / count as u64;
	let remainder = size % count as u64;
	let mut start = 0_u64;
	(0..count)
		.map(|index| {
			let range_size = base_size + u64::from(index < remainder as usize);
			let end = start + range_size - 1;
			let range = DownloadRange::new(index, start, end);
			start = end + 1;
			range
		})
		.collect()
}

pub(crate) fn expansion_block_reason(
	snapshot: crate::util::download_manager::SpeedSnapshot,
	active_ranges: usize,
	concurrency_cap: usize,
	available_permits: usize,
	remaining_bytes: u64,
	elapsed_since_expansion: Duration,
) -> Option<&'static str> {
	if active_ranges >= concurrency_cap {
		return Some("effective concurrency cap reached");
	}
	if available_permits == 0 {
		return Some("no global permit available");
	}
	if elapsed_since_expansion < SEGMENT_EXPANSION_INTERVAL {
		return Some("expansion cooldown active");
	}
	if snapshot.sample_count < SEGMENT_EXPANSION_SAMPLE_COUNT {
		return Some("insufficient aggregate speed samples");
	}
	if remaining_bytes < MIN_SEGMENT_SIZE.saturating_mul(active_ranges as u64 + 1) {
		return Some("too little data remains");
	}
	None
}

pub(crate) fn should_use_segmented_download(
	size: u64,
	resumable_part_bytes: u64,
) -> bool {
	size >= SEGMENTED_DOWNLOAD_THRESHOLD && resumable_part_bytes < size / 2
}

#[derive(Clone)]
pub(crate) struct DownloadRange {
	pub(crate) index: usize,
	pub(crate) start: u64,
	pub(crate) state: Arc<Mutex<DownloadRangeState>>,
}

pub(crate) struct DownloadRangeState {
	pub(crate) end: u64,
	pub(crate) downloaded: u64,
	pub(crate) active: bool,
}

impl DownloadRange {
	pub(crate) fn new(index: usize, start: u64, end: u64) -> Self {
		Self {
			index,
			start,
			state: Arc::new(Mutex::new(DownloadRangeState {
				end,
				downloaded: 0,
				active: true,
			})),
		}
	}
	pub(crate) fn end(&self) -> u64 {
		self.state.lock().end
	}
	pub(crate) fn remaining(&self) -> u64 {
		let state = self.state.lock();
		state
			.end
			.saturating_add(1)
			.saturating_sub(self.start.saturating_add(state.downloaded))
	}
	pub(crate) fn is_active(&self) -> bool {
		self.state.lock().active
	}
	pub(crate) fn split_tail(&self, index: usize) -> Option<Self> {
		let mut state = self.state.lock();
		let remaining = state
			.end
			.saturating_add(1)
			.saturating_sub(self.start.saturating_add(state.downloaded));
		if remaining < 256 * 1024 {
			return None;
		}
		let split_size = remaining.saturating_mul(40) / 100;
		let split_start = state.end.saturating_add(1).saturating_sub(split_size);
		if split_start <= self.start.saturating_add(state.downloaded) {
			return None;
		}
		let split_end = state.end;
		state.end = split_start - 1;
		drop(state);
		Some(Self::new(index, split_start, split_end))
	}
	pub(crate) fn accept_chunk(&self, chunk_size: usize) -> (usize, bool) {
		let mut state = self.state.lock();
		let remaining = state
			.end
			.saturating_add(1)
			.saturating_sub(self.start.saturating_add(state.downloaded));
		let accepted = usize::try_from(remaining)
			.unwrap_or(usize::MAX)
			.min(chunk_size);
		state.downloaded += accepted as u64;
		(accepted, state.downloaded == state.end - self.start + 1)
	}
	pub(crate) fn finish(&self) -> bool {
		let mut state = self.state.lock();
		state.active = false;
		state.downloaded == state.end - self.start + 1
	}
}

pub(crate) struct DownloadRangeGuard(pub(crate) Arc<Mutex<DownloadRangeState>>);
impl Drop for DownloadRangeGuard {
	fn drop(&mut self) {
		self.0.lock().active = false;
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceValidator {
	pub(crate) etag: Option<String>,
	pub(crate) last_modified: Option<String>,
}

pub(crate) fn response_validator(
	response: &reqwest::Response,
) -> ResourceValidator {
	ResourceValidator {
		etag: response
			.headers()
			.get(reqwest::header::ETAG)
			.and_then(|value| value.to_str().ok())
			.map(str::to_owned),
		last_modified: response
			.headers()
			.get(reqwest::header::LAST_MODIFIED)
			.and_then(|value| value.to_str().ok())
			.map(str::to_owned),
	}
}

pub(crate) fn validate_resource_version(
	expected: &Mutex<Option<ResourceValidator>>,
	response: &reqwest::Response,
) -> bool {
	let candidate = response_validator(response);
	let mut expected = expected.lock();
	match expected.as_ref() {
		Some(expected) => {
			(expected.etag.is_none() || expected.etag == candidate.etag)
				&& (expected.last_modified.is_none()
					|| expected.last_modified == candidate.last_modified)
		}
		None => {
			*expected = Some(candidate);
			true
		}
	}
}

pub(crate) fn segment_path(part_path: &Path, index: usize) -> PathBuf {
	let mut name = part_path
		.file_name()
		.map(|name| name.to_os_string())
		.unwrap_or_default();
	name.push(format!(".segment-{index}"));
	part_path.with_file_name(name)
}

pub(crate) fn tail_candidate_path(
	part_path: &Path,
	range_index: usize,
	candidate_index: usize,
) -> PathBuf {
	let mut name = part_path
		.file_name()
		.map(|name| name.to_os_string())
		.unwrap_or_default();
	name.push(format!(".segment-{range_index}.tail-{candidate_index}"));
	part_path.with_file_name(name)
}

pub(crate) struct TailCandidateCleanupGuard {
	pub(crate) path: PathBuf,
	pub(crate) armed: bool,
}

impl TailCandidateCleanupGuard {
	pub(crate) fn new(path: PathBuf) -> Self {
		Self { path, armed: true }
	}
	pub(crate) fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for TailCandidateCleanupGuard {
	fn drop(&mut self) {
		if self.armed {
			let _ = std::fs::remove_file(&self.path);
		}
	}
}

pub(crate) struct TailCandidateCompletion {
	pub(crate) path: PathBuf,
	pub(crate) final_url: String,
	pub(crate) remote_addr: Option<std::net::SocketAddr>,
	pub(crate) http_version: reqwest::Version,
}

impl Drop for TailCandidateCompletion {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.path);
	}
}

pub(crate) async fn cleanup_segment_files(
	part_path: &Path,
	segment_count: usize,
) -> crate::Result<()> {
	for index in 0..segment_count {
		super::partial::remove_if_exists(&segment_path(part_path, index)).await?;
		for candidate in 0..2 {
			super::partial::remove_if_exists(&tail_candidate_path(
				part_path,
				index,
				candidate,
			))
			.await?;
		}
	}
	Ok(())
}

pub(crate) enum SegmentDownloadError {
	Protocol(&'static str),
	Transport,
	Fatal(crate::Error),
}

pub(crate) struct SegmentDownloadCompletion {
	pub(crate) final_url: String,
	pub(crate) is_first_range: bool,
	pub(crate) ttfb: std::time::Duration,
	pub(crate) remote_addr: Option<std::net::SocketAddr>,
	pub(crate) http_version: Option<reqwest::Version>,
}

pub(crate) struct SegmentedDownloadSuccess {
	pub(crate) size: u64,
	pub(crate) final_url: String,
	pub(crate) ttfb: std::time::Duration,
	pub(crate) transfer_elapsed: std::time::Duration,
	pub(crate) remote_addr: Option<std::net::SocketAddr>,
	pub(crate) http_version: Option<reqwest::Version>,
}

pub(crate) struct SegmentCleanupGuard {
	part_path: PathBuf,
	segment_count: usize,
	armed: bool,
	part_dirty: bool,
}

impl SegmentCleanupGuard {
	pub(crate) fn new(part_path: &Path, segment_count: usize) -> Self {
		Self {
			part_path: part_path.to_path_buf(),
			segment_count,
			armed: true,
			part_dirty: false,
		}
	}
	pub(crate) fn mark_part_dirty(&mut self) {
		self.part_dirty = true;
	}
	pub(crate) fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for SegmentCleanupGuard {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}
		if self.part_dirty {
			let _ = std::fs::remove_file(&self.part_path);
		}
		for index in 0..self.segment_count {
			let _ = std::fs::remove_file(segment_path(&self.part_path, index));
			for candidate in 0..2 {
				let _ = std::fs::remove_file(tail_candidate_path(
					&self.part_path,
					index,
					candidate,
				));
			}
		}
	}
}
