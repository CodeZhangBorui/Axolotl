use crate::{ErrorKind, LabrinthError};
use reqwest::Method;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use url::Url;

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
