use super::model::{DownloadMeta, DownloadRoute, ProxyPolicy};
use crate::{ErrorKind, LabrinthError};
use reqwest::Method;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use url::Url;

const MAX_REDIRECTS: usize = 5;
const MAX_REDIRECT_LOCATION_BYTES: usize = 8 * 1024;
pub const DOWNLOAD_META_HEADER: &str = "modrinth-download-meta";

pub(crate) trait DownloadRequestHooks {
	fn authority(&self, url: &str) -> Option<String>;
	fn forget_effective_authority(&self, route: &DownloadRoute, failed: &Url);
	fn remember_effective_authority(&self, route: &DownloadRoute, final_url: &str);
	fn canonical_redirect(
		&self,
		original: &Url,
		next: Url,
		location: &str,
	) -> crate::Result<Url>;
	fn is_official_download_url(&self, url: &str) -> bool;
}

const H2_FALLBACK_TTL: Duration = Duration::from_secs(600);
static H2_FALLBACK_AUTHORITIES: LazyLock<Mutex<HashMap<String, Instant>>> =
	LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn authority_uses_http1_fallback(authority: &str) -> bool {
	let mut fallbacks = H2_FALLBACK_AUTHORITIES.lock();
	match fallbacks.get(authority) {
		Some(until) if *until > Instant::now() => true,
		Some(_) => {
			fallbacks.remove(authority);
			false
		}
		None => false,
	}
}

pub(crate) fn record_authority_h2_failure(authority: &str) {
	let now = Instant::now();
	let mut fallbacks = H2_FALLBACK_AUTHORITIES.lock();
	fallbacks.retain(|_, until| *until > now);
	fallbacks.insert(authority.to_string(), now + H2_FALLBACK_TTL);
}

pub(crate) fn is_h2_protocol_failure(error: &reqwest::Error) -> bool {
	let mut chain = String::new();
	let mut source = error.source();
	while let Some(next) = source {
		if !chain.is_empty() {
			chain.push(' ');
		}
		chain.push_str(&next.to_string());
		source = next.source();
	}
	let chain = chain.to_ascii_lowercase();
	[
		"http2",
		"http/2",
		"goaway",
		"stream error",
		"protocol error",
		"refused stream",
	]
	.iter()
	.any(|marker| chain.contains(marker))
}

#[cfg(test)]
pub(crate) fn clear_h2_fallbacks_for_test() {
	H2_FALLBACK_AUTHORITIES.lock().clear();
}

pub(crate) fn sanitize_url_for_log(url: &str) -> String {
	if let Ok(mut url) = Url::parse(url) {
		let _ = url.set_username("");
		let _ = url.set_password(None);
		url.set_query(None);
		url.set_fragment(None);
		return url.into();
	}
	url.split(['?', '#']).next().unwrap_or(url).to_string()
}

pub(crate) fn is_sensitive_header(name: &str) -> bool {
	name.eq_ignore_ascii_case("authorization")
		|| name.eq_ignore_ascii_case("proxy-authorization")
		|| name.eq_ignore_ascii_case("cookie")
		|| name.eq_ignore_ascii_case("x-api-key")
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
	left.scheme() == right.scheme()
		&& left.host_str() == right.host_str()
		&& left.port_or_known_default() == right.port_or_known_default()
}

pub(crate) fn is_allowed_download_redirect(url: &Url) -> bool {
	if url.scheme() == "https" {
		return true;
	}
	#[cfg(test)]
	if url.scheme() == "http"
		&& url
			.host_str()
			.is_some_and(|host| host == "localhost" || host == "127.0.0.1")
	{
		return true;
	}
	false
}

pub(crate) fn byte_range_header_value(
	range_start: Option<u64>,
	range_end: Option<u64>,
) -> Option<String> {
	range_start.map(|start| {
		range_end.map_or_else(
			|| format!("bytes={start}-"),
			|end| format!("bytes={start}-{end}"),
		)
	})
}

pub(crate) async fn response_status_error(
	response: reqwest::Response,
	method: &Method,
	request_url: &str,
) -> crate::Error {
	let status = response.status();
	if let Ok(mut error) = response.json::<LabrinthError>().await {
		error.status = Some(status.as_u16());
		error.method = Some(method.as_str().to_string());
		error.url = Some(sanitize_url_for_log(request_url));
		ErrorKind::LabrinthError(error).into()
	} else {
		ErrorKind::HttpError {
			status: status.as_u16(),
			method: method.as_str().to_string(),
			url: sanitize_url_for_log(request_url),
		}
		.into()
	}
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_path_request_with_clients<H: DownloadRequestHooks>(
	hooks: &H,
	route: &DownloadRoute,
	custom_header: Option<&(String, String)>,
	credentials: Option<&crate::state::ModrinthCredentials>,
	download_meta: Option<&DownloadMeta>,
	range_start: Option<u64>,
	range_end: Option<u64>,
	system_client: &reqwest::Client,
	direct_client: &reqwest::Client,
	http1_system_client: &reqwest::Client,
	http1_direct_client: &reqwest::Client,
	redirect_target: Option<&tokio::sync::Mutex<Option<Url>>>,
) -> crate::Result<(reqwest::Response, String)> {
	let original = Url::parse(&route.url)?;
	let mut current = match redirect_target {
		Some(target) => target.lock().await.as_ref().cloned()
			.unwrap_or_else(|| original.clone()),
		None => original.clone(),
	};
	let mut reused_redirect_target = current != original;
	for redirect_count in 0..=MAX_REDIRECTS {
		let fallback_to_http1 = hooks.authority(current.as_str())
			.is_some_and(|authority| authority_uses_http1_fallback(&authority));
		let (system, direct) = if fallback_to_http1 {
			(http1_system_client, http1_direct_client)
		} else {
			(system_client, direct_client)
		};
		let client = if route.proxy == ProxyPolicy::Direct { direct } else { system };
		let same_as_original = same_origin(&original, &current);
		let allow_sensitive = route.allow_sensitive_headers && same_as_original;
		let mut request = client.get(current.clone());
		if let Some((name, value)) = custom_header
			&& (allow_sensitive || !is_sensitive_header(name))
			&& (!name.eq_ignore_ascii_case("x-api-key")
				|| original.host_str() == Some("api.curseforge.com"))
		{
			request = request.header(name, value);
		}
		if allow_sensitive && let Some(credentials) = credentials {
			request = request.header("Authorization", &credentials.session);
		}
		if !route.is_mirror && same_as_original
			&& hooks.is_official_download_url(original.as_str())
			&& let Some(download_meta) = download_meta
		{
			request = request.header(
				DOWNLOAD_META_HEADER,
				download_meta.to_header_value(),
			);
		}
		if let Some(range) = byte_range_header_value(range_start, range_end) {
			request = request.header(reqwest::header::RANGE, range)
				.header(reqwest::header::ACCEPT_ENCODING, "identity");
		}
		let response = match request.send().await {
			Ok(response) => response,
			Err(error) => {
				if !fallback_to_http1 && redirect_count < MAX_REDIRECTS
					&& is_h2_protocol_failure(&error)
					&& let Some(authority) = hooks.authority(current.as_str())
				{
					tracing::warn!(authority, error = %error.without_url(),
						"HTTP/2 download request failed; retrying over HTTP/1.1");
					record_authority_h2_failure(&authority);
					continue;
				}
				return Err(error.into());
			}
		};
		if !response.status().is_redirection() {
			if reused_redirect_target
				&& (response.status().is_client_error()
					|| response.status().is_server_error())
			{
				hooks.forget_effective_authority(route, &current);
				if let Some(target) = redirect_target {
					let mut cached = target.lock().await;
					if cached.as_ref() == Some(&current) { *cached = None; }
				}
				current = original.clone();
				reused_redirect_target = false;
				continue;
			}
			hooks.remember_effective_authority(route, current.as_str());
			if response.status().is_success() && current != original
				&& let Some(target) = redirect_target
			{
				let mut cached = target.lock().await;
				if cached.is_none() { *cached = Some(current.clone()); }
			}
			tracing::debug!(original_url = %sanitize_url_for_log(&route.url),
				final_host = current.host_str().unwrap_or_default(),
				reused_redirect_target, http1_fallback = fallback_to_http1,
				"Resolved file download route");
			return Ok((response, current.into()));
		}
		if redirect_count == MAX_REDIRECTS {
			return Err(ErrorKind::OtherError(format!(
				"Too many redirects while downloading {}", route.url
			)).into());
		}
		let location = response.headers().get(reqwest::header::LOCATION)
			.map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
			.ok_or_else(|| ErrorKind::OtherError(format!(
				"Redirect from {current} did not include a valid Location header")))?;
		if location.len() > MAX_REDIRECT_LOCATION_BYTES
			|| location.chars().any(char::is_control)
		{
			return Err(ErrorKind::OtherError(format!(
				"Redirect from {current} included an unsafe Location header"
			)).into());
		}
		let next = current.join(&location)?;
		if !is_allowed_download_redirect(&next) {
			return Err(ErrorKind::OtherError(format!(
				"Refusing insecure redirect from {current} to {next}"
			)).into());
		}
		current = hooks.canonical_redirect(&original, next, &location)?;
	}
	unreachable!()
}
