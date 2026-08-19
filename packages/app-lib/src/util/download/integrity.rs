use super::model::{ContentValidation, Integrity};
use crate::ErrorKind;
use crate::util::io::IOError;
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;
use std::sync::LazyLock;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, SemaphorePermit};

static FILE_VALIDATION_SEMAPHORE: LazyLock<Semaphore> =
	LazyLock::new(|| Semaphore::new(4));

async fn acquire_native_validation_permit()
-> crate::Result<Option<SemaphorePermit<'static>>> {
	if super::active_engine() == super::DownloadEngine::XmclCompat {
		return Ok(None);
	}
	Ok(Some(FILE_VALIDATION_SEMAPHORE.acquire().await?))
}

#[derive(Default)]
pub(crate) struct IntegrityHashers {
	sha1: Option<sha1_smol::Sha1>,
	sha512: Option<Sha512>,
	sha256: Option<Sha256>,
	md5: Option<md5::Context>,
}

#[derive(Default)]
pub(crate) struct ComputedIntegrity {
	pub(crate) size: u64,
	pub(crate) sha1: Option<String>,
	pub(crate) sha512: Option<String>,
	pub(crate) sha256: Option<String>,
	pub(crate) md5: Option<String>,
}

impl IntegrityHashers {
	pub(crate) fn new_integrity_hashers(integrity: &Integrity) -> Self {
		Self {
			sha1: integrity.sha1.as_ref().map(|_| sha1_smol::Sha1::new()),
			sha512: integrity.sha512.as_ref().map(|_| Sha512::new()),
			sha256: integrity.sha256.as_ref().map(|_| Sha256::new()),
			md5: integrity.md5.as_ref().map(|_| md5::Context::new()),
		}
	}

	pub(crate) fn update(&mut self, bytes: &[u8]) {
		if let Some(hasher) = &mut self.sha1 {
			hasher.update(bytes);
		}
		if let Some(hasher) = &mut self.sha512 {
			hasher.update(bytes);
		}
		if let Some(hasher) = &mut self.sha256 {
			hasher.update(bytes);
		}
		if let Some(hasher) = &mut self.md5 {
			hasher.consume(bytes);
		}
	}

	pub(crate) fn finish(self, size: u64) -> ComputedIntegrity {
		ComputedIntegrity {
			size,
			sha1: self.sha1.map(|hasher| hasher.digest().to_string()),
			sha512: self
				.sha512
				.map(|hasher| format!("{:x}", hasher.finalize())),
			sha256: self
				.sha256
				.map(|hasher| format!("{:x}", hasher.finalize())),
			md5: self.md5.map(|hasher| format!("{:x}", hasher.finalize())),
		}
	}
}

pub(crate) async fn hash_existing_part_prefix(
	path: &Path,
	integrity: &Integrity,
	expected_len: u64,
) -> Option<IntegrityHashers> {
	let mut file = File::open(path).await.ok()?;
	let mut hashers = IntegrityHashers::new_integrity_hashers(integrity);
	let mut size = 0_u64;
	let mut buffer = vec![0_u8; 256 * 1024];
	loop {
		let read = file.read(&mut buffer).await.ok()?;
		if read == 0 {
			break;
		}
		hashers.update(&buffer[..read]);
		size += read as u64;
	}
	(size == expected_len).then_some(hashers)
}

async fn compute_file_integrity(
	path: &Path,
	integrity: &Integrity,
) -> crate::Result<ComputedIntegrity> {
	let _permit = acquire_native_validation_permit().await?;
	let mut file = File::open(path)
		.await
		.map_err(|error| IOError::with_path(error, path))?;
	let mut hashers = IntegrityHashers::new_integrity_hashers(integrity);
	let mut size = 0;
	let mut buffer = vec![0_u8; 256 * 1024];
	loop {
		let read = file
			.read(&mut buffer)
			.await
			.map_err(|error| IOError::with_path(error, path))?;
		if read == 0 {
			break;
		}
		hashers.update(&buffer[..read]);
		size += read as u64;
	}
	Ok(hashers.finish(size))
}

pub(crate) fn verify_computed_integrity(
	expected: &Integrity,
	actual: &ComputedIntegrity,
) -> crate::Result<()> {
	if let Some(size) = expected.size && actual.size != size {
		if !expected.has_hash() {
			return Err(ErrorKind::OtherError(format!(
				"Incorrect size for download: {size} != {}",
				actual.size
			))
			.into());
		}
		tracing::warn!(expected_size = size, actual_size = actual.size, "Downloaded size differs from the expected size; relying on content hash verification");
	}
	for (algorithm, expected, actual) in [
		("sha1", expected.sha1.as_ref(), actual.sha1.as_ref()),
		("sha512", expected.sha512.as_ref(), actual.sha512.as_ref()),
		("sha256", expected.sha256.as_ref(), actual.sha256.as_ref()),
		("md5", expected.md5.as_ref(), actual.md5.as_ref()),
	] {
		if let Some(expected) = expected
			&& actual.is_none_or(|actual| !actual.eq_ignore_ascii_case(expected))
		{
			return Err(ErrorKind::OtherError(format!(
				"Incorrect {algorithm} hash for download: {expected} != {}",
				actual.map(String::as_str).unwrap_or("not computed")
			))
			.into());
		}
	}
	Ok(())
}

pub(crate) fn is_integrity_error(error: &crate::Error) -> bool {
	match error.raw.as_ref() {
		ErrorKind::HashError(..) => true,
		ErrorKind::OtherError(message) => {
			message.starts_with("Incorrect ")
				&& message.contains(" hash for download")
		}
		_ => false,
	}
}

pub(crate) async fn validate_file_content(
	path: &Path,
	validation: ContentValidation,
) -> crate::Result<()> {
	if validation == ContentValidation::None {
		return Ok(());
	}
	let _permit = acquire_native_validation_permit().await?;
	let path = path.to_path_buf();
	tokio::task::spawn_blocking(move || -> crate::Result<()> {
		let file = std::fs::File::open(&path)
			.map_err(|error| IOError::with_path(error, &path))?;
		match validation {
			ContentValidation::None => {}
			ContentValidation::Json => {
				serde_json::from_reader::<_, serde_json::Value>(file)?;
			}
			ContentValidation::Jar => {
				zip::ZipArchive::new(file).map_err(|error| {
					ErrorKind::OtherError(format!(
						"Invalid JAR archive {}: {error}",
						path.display()
					))
				})?;
			}
		}
		Ok(())
	}).await??;
	Ok(())
}

pub(crate) async fn verify_file(path: &Path, integrity: &Integrity) -> crate::Result<u64> {
	let computed = compute_file_integrity(path, integrity).await?;
	verify_computed_integrity(integrity, &computed)?;
	validate_file_content(path, integrity.content).await?;
	Ok(computed.size)
}
