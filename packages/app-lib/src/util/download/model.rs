use crate::install::InstallProgressReporter;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
	Metadata,
	MinecraftAsset,
	MinecraftLibrary,
	Loader,
	Java,
	Modrinth,
	CurseForge,
	Modpack,
	#[default]
	Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadRouteSource {
	Official,
	Bmclapi,
	Mcim,
	Tianpao,
	Alternate,
}

impl DownloadRouteSource {
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Official => "official",
			Self::Bmclapi => "bmclapi",
			Self::Mcim => "mcim",
			Self::Tianpao => "tianpao",
			Self::Alternate => "alternate",
		}
	}
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyPolicy {
	#[default]
	System,
	Direct,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DownloadRoute {
	pub url: String,
	pub source: DownloadRouteSource,
	pub is_mirror: bool,
	pub allow_sensitive_headers: bool,
	pub supports_range: bool,
	pub proxy: ProxyPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentValidation {
	#[default]
	None,
	Json,
	Jar,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Integrity {
	pub size: Option<u64>,
	pub sha1: Option<String>,
	pub sha512: Option<String>,
	pub sha256: Option<String>,
	pub md5: Option<String>,
	pub content: ContentValidation,
}

impl Integrity {
	pub fn sha1(hash: impl Into<String>) -> Self {
		Self {
			sha1: Some(hash.into()),
			..Self::default()
		}
	}
	pub fn with_size(mut self, size: u64) -> Self {
		self.size = Some(size);
		self
	}
	pub fn with_content_validation(
		mut self,
		content: ContentValidation,
	) -> Self {
		self.content = content;
		self
	}
	pub(crate) fn is_empty(&self) -> bool {
		self.size.is_none() && self.sha1.is_none() && self.sha512.is_none()
			&& self.sha256.is_none() && self.md5.is_none()
			&& self.content == ContentValidation::None
	}
	pub(crate) fn supports_resume(&self) -> bool {
		self.size.is_some() && self.has_hash()
	}
	pub(crate) fn has_hash(&self) -> bool {
		self.sha1.is_some() || self.sha512.is_some() || self.sha256.is_some() || self.md5.is_some()
	}
}

#[derive(Clone, Debug)]
pub(crate) struct DownloadInstallTracking {
	pub(crate) reporter: InstallProgressReporter,
	pub(crate) item_id: String,
	pub(crate) item_name: String,
}

#[derive(Clone, Debug)]
pub struct DownloadRequest {
	pub url: String,
	pub resource: ResourceClass,
	pub integrity: Integrity,
	pub download_meta: Option<DownloadMeta>,
	pub header: Option<(String, String)>,
	pub candidate_urls: Vec<String>,
	pub allow_segmented_download: bool,
	pub(crate) install_tracking: Option<DownloadInstallTracking>,
}

impl DownloadRequest {
	pub fn new(url: impl Into<String>, resource: ResourceClass) -> Self {
		Self {
			url: url.into(),
			resource,
			integrity: Integrity::default(),
			download_meta: None,
			header: None,
			candidate_urls: Vec::new(),
			allow_segmented_download: true,
			install_tracking: None,
		}
	}
	pub fn with_segmented_download(mut self, allow: bool) -> Self {
		self.allow_segmented_download = allow;
		self
	}
	pub fn with_integrity(mut self, integrity: Integrity) -> Self {
		self.integrity = integrity;
		self
	}
	pub fn with_download_meta(mut self, meta: DownloadMeta) -> Self {
		self.download_meta = Some(meta);
		self
	}
	pub fn with_header(
		mut self,
		name: impl Into<String>,
		value: impl Into<String>,
	) -> Self {
		self.header = Some((name.into(), value.into()));
		self
	}
	pub fn with_candidate_urls<I, S>(mut self, urls: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		self.candidate_urls.extend(urls.into_iter().map(Into::into));
		self
	}
	pub fn with_install_tracking(
		mut self,
		reporter: InstallProgressReporter,
		item_id: impl Into<String>,
		item_name: impl Into<String>,
	) -> Self {
		self.install_tracking = Some(DownloadInstallTracking {
			reporter,
			item_id: item_id.into(),
			item_name: item_name.into(),
		});
		self
	}
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DownloadResult {
	pub path: PathBuf,
	pub url: String,
	pub source: DownloadRouteSource,
	pub size: u64,
	pub attempts: usize,
	pub fallback_count: usize,
}

#[derive(Debug, derive_more::Display, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[display(rename_all = "snake_case")]
pub enum DownloadReason {
	Standalone,
	Dependency,
	Modpack,
	Update,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadMeta {
	pub reason: DownloadReason,
	pub game_version: String,
	pub loader: String,
	pub dependent_on: Option<String>,
}
impl DownloadMeta {
	pub fn to_header_value(&self) -> String {
		serde_json::to_string(self).unwrap_or_default()
	}
}

#[derive(Debug)]
pub struct IoSemaphore(pub Semaphore);
#[derive(Debug)]
pub struct FetchSemaphore(pub Semaphore);
