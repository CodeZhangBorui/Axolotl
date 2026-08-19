use super::model::{DownloadRouteSource, ProxyPolicy};
use crate::ErrorKind;
use std::collections::VecDeque;

const MAX_HISTORY: usize = 12;
const MAX_CONTEXT_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub(crate) struct DownloadAttemptDiagnostic {
	attempt: usize,
	source: DownloadRouteSource,
	url: String,
	proxy: ProxyPolicy,
	dns_candidates: Vec<std::net::IpAddr>,
	remote_addr: Option<std::net::SocketAddr>,
	http_version: Option<reqwest::Version>,
	status: Option<u16>,
	category: &'static str,
	decision: &'static str,
	detail: String,
}

pub(crate) type DownloadAttemptHistory = VecDeque<DownloadAttemptDiagnostic>;

fn bounded_text(value: impl AsRef<str>, max_chars: usize) -> String {
	value.as_ref().chars().take(max_chars).collect()
}

pub(crate) fn error_category(error: &crate::Error) -> &'static str {
	match error.raw.as_ref() {
		ErrorKind::FetchError(source) => {
			let detail = format!("{source:?}").to_ascii_lowercase();
			if source.status().is_some() {
				"http"
			} else if source.is_timeout() && source.is_body() {
				"stall"
			} else if source.is_timeout() {
				"timeout"
			} else if source.is_connect()
				&& ["certificate", "tls", "ssl"]
					.iter()
					.any(|needle| detail.contains(needle))
			{
				"tls"
			} else if source.is_connect()
				&& ["dns", "lookup", "resolve"]
					.iter()
					.any(|needle| detail.contains(needle))
			{
				"dns"
			} else if source.is_connect() {
				"connect"
			} else {
				"network"
			}
		}
		ErrorKind::NetworkError(message) => {
			if message.contains("no response received") {
				"timeout"
			} else {
				"network"
			}
		}
		ErrorKind::LabrinthError(_) | ErrorKind::HttpError { .. } => "http",
		ErrorKind::HashError(_, _) | ErrorKind::JSONError(_) => "integrity",
		ErrorKind::IOError(_) | ErrorKind::StdIOError(_) => "io",
		ErrorKind::OtherError(message) => {
			let message = message.to_ascii_lowercase();
			if message.contains("content-range") || message.contains("range") {
				"range"
			} else if message.contains("integrity")
				|| message.contains("checksum")
				|| message.contains("validation")
			{
				"integrity"
			} else if message.contains("truncated") {
				"stall"
			} else {
				"other"
			}
		}
		_ => "other",
	}
}

pub(crate) fn error_detail(error: &crate::Error) -> String {
	match error.raw.as_ref() {
		ErrorKind::FetchError(source) => source.status().map_or_else(
			|| format!("{} failure", error_category(error)),
			|status| format!("HTTP {}", status.as_u16()),
		),
		ErrorKind::LabrinthError(error) => error.status.map_or_else(
			|| "API response failure".to_string(),
			|status| format!("HTTP {status}"),
		),
		ErrorKind::HttpError { status, .. } => format!("HTTP {status}"),
		ErrorKind::HashError(_, _) => "hash mismatch".to_string(),
		ErrorKind::JSONError(_) => "JSON validation failed".to_string(),
		ErrorKind::IOError(_) | ErrorKind::StdIOError(_) => {
			"I/O failure".to_string()
		}
		ErrorKind::OtherError(_) | ErrorKind::NetworkError(_) => {
			format!("{} failure", error_category(error))
		}
		_ => bounded_text(error.to_string(), 256),
	}
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push(
	history: &mut DownloadAttemptHistory,
	attempt: usize,
	source: DownloadRouteSource,
	url: &str,
	proxy: ProxyPolicy,
	dns_candidates: Vec<std::net::IpAddr>,
	category: &'static str,
	decision: &'static str,
	detail: impl AsRef<str>,
	status: Option<reqwest::StatusCode>,
	remote_addr: Option<std::net::SocketAddr>,
	http_version: Option<reqwest::Version>,
) {
	if history.len() == MAX_HISTORY {
		history.pop_front();
	}
	history.push_back(DownloadAttemptDiagnostic {
		attempt,
		source,
		url: bounded_text(url, 512),
		proxy,
		dns_candidates: dns_candidates.into_iter().take(8).collect(),
		remote_addr,
		http_version,
		status: status.map(|status| status.as_u16()),
		category,
		decision,
		detail: bounded_text(detail, 256),
	});
}

pub(crate) fn attach(
	error: crate::Error,
	history: &DownloadAttemptHistory,
	attempts: usize,
	attempt_budget: usize,
) -> crate::Error {
	let mut context = format!(
		"Download failed after {attempts}/{attempt_budget} attempts. Recent attempt history:"
	);
	for item in history {
		let line = format!(
			"\n- attempt={}; source={}; url={}; proxy={:?}; dns={:?}; remote={:?}; http={:?}; status={:?}; category={}; decision={}; detail={}",
			item.attempt,
			item.source.as_str(),
			item.url,
			item.proxy,
			item.dns_candidates,
			item.remote_addr,
			item.http_version,
			item.status,
			item.category,
			item.decision,
			item.detail,
		);
		if context.len() + line.len() > MAX_CONTEXT_BYTES {
			context.push_str("\n- older diagnostic details omitted");
			break;
		}
		context.push_str(&line);
	}
	error.with_context(context)
}
