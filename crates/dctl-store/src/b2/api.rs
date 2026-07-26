//! B2 API request/response DTOs and cached authorization state.

use serde::Deserialize;

/// Cached result of `b2_authorize_account` (+ resolved bucket id).
#[derive(Clone)]
pub(crate) struct AuthState {
    pub api_url: String,
    pub download_url: String,
    pub auth_token: String,
    pub bucket_id: String,
    pub recommended_part_size: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorizeResponse {
    pub account_id: String,
    pub authorization_token: String,
    pub api_url: String,
    pub download_url: String,
    pub recommended_part_size: u64,
    pub allowed: Allowed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Allowed {
    pub bucket_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListBucketsResponse {
    pub buckets: Vec<BucketItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BucketItem {
    pub bucket_id: String,
    pub bucket_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetUploadUrlResponse {
    pub upload_url: String,
    pub authorization_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadFileResponse {
    pub content_sha1: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartLargeFileResponse {
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetUploadPartUrlResponse {
    pub upload_url: String,
    pub authorization_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadPartResponse {
    pub content_sha1: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FinishLargeFileResponse {
    #[allow(dead_code)]
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListFileNamesResponse {
    pub files: Vec<FileItem>,
    pub next_file_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileItem {
    pub file_name: String,
    pub content_length: u64,
    pub upload_timestamp: i64,
    pub action: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListFileVersionsResponse {
    pub files: Vec<VersionItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionItem {
    pub file_name: String,
    pub file_id: String,
}

#[derive(Deserialize)]
pub(crate) struct DeleteFileVersionResponse {
    #[allow(dead_code)]
    #[serde(rename = "fileId")]
    pub file_id: String,
}
