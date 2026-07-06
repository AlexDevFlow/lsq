//! LocalSend protocol v2.1 wire models.
//! Field shapes follow the LocalSend v2.1 protocol; unknown fields are ignored
//! and unknown enum values fall back gracefully (spec §7.1).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: &str = "2.1";
pub const DEFAULT_PORT: u16 = 53317;
pub const MULTICAST_ADDR: &str = "224.0.0.167";
/// Discovery always happens on this fixed group port, even when the HTTP
/// server runs elsewhere (so lsq can share a host with the desktop app).
pub const MULTICAST_PORT: u16 = 53317;
pub const API_BASE: &str = "/api/localsend/v2";

/// The desktop app sends `port: -1` as a "no port" sentinel, which a plain
/// `Option<u16>` rejects. Accept any integer (or null) and treat anything
/// outside the valid TCP range as absent.
fn lenient_port<'de, D>(d: D) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<i64>::deserialize(d)?;
    Ok(raw.and_then(|n| u16::try_from(n).ok()).filter(|&p| p != 0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Mobile,
    #[default]
    Desktop,
    Web,
    Headless,
    Server,
    // Spec: implementations must handle unknown values.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    #[default]
    Https,
}

/// Multicast announcement / reply (spec §3.1).
///
/// The official `MulticastDto` marks `version`, `port`, and `protocol` nullable
/// and carries both the v2 `announce` and legacy v1 `announcement` flags, with
/// the receiver substituting its own fallbacks when a field is absent. We match
/// that so minimal/legacy peers are still discovered and answered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announce {
    pub alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: Option<DeviceType>,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "lenient_port")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub download: bool,
    #[serde(default)]
    pub announce: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement: Option<bool>,
}

impl Announce {
    /// Reply when either the v2 `announce` or the v1 `announcement` flag is set.
    pub fn should_reply(&self) -> bool {
        self.announce || self.announcement.unwrap_or(false)
    }
    pub fn port_or(&self, default: u16) -> u16 {
        self.port.unwrap_or(default)
    }
    pub fn protocol_or_default(&self) -> Protocol {
        self.protocol.unwrap_or_default()
    }
}

/// Body of POST /register and the `info` object in prepare-upload (spec §3.2, §4.1).
///
/// Per the official `InfoRegisterDto`, only `alias` is required; `version` and
/// `fingerprint` in particular are nullable (fingerprint is null for v1 peers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: Option<DeviceType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "lenient_port")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub download: bool,
}

impl DeviceInfo {
    pub fn fingerprint_or_default(&self) -> String {
        self.fingerprint.clone().unwrap_or_default()
    }
    /// Convert a /register or prepare-upload `info` body into an Announce for
    /// the peer registry, applying the documented port fallback.
    pub fn to_announce(&self) -> Announce {
        Announce {
            alias: self.alias.clone(),
            version: self.version.clone(),
            device_model: self.device_model.clone(),
            device_type: self.device_type,
            fingerprint: self.fingerprint_or_default(),
            port: Some(self.port.unwrap_or(DEFAULT_PORT)),
            protocol: self.protocol,
            download: self.download,
            announce: false,
            announcement: None,
        }
    }
}

/// Register response (spec §3.2), like DeviceInfo but without port/protocol required.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub alias: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: Option<DeviceType>,
    pub fingerprint: String,
    #[serde(default)]
    pub download: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
}

/// File descriptor in prepare-upload (spec §4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDto {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadRequest {
    pub info: DeviceInfo,
    // BTreeMap for deterministic ordering in tests and logs.
    pub files: BTreeMap<String, FileDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadResponse {
    pub session_id: String,
    /// fileId -> file-specific upload token
    pub files: BTreeMap<String, String>,
}

/// Response of POST /prepare-download (spec §5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareDownloadResponse {
    pub info: DeviceInfo,
    pub session_id: String,
    pub files: BTreeMap<String, FileDto>,
}

/// GET /info response (spec §6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    pub alias: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: Option<DeviceType>,
    pub fingerprint: String,
    #[serde(default)]
    pub download: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Announcement example from spec §3.1, verbatim (minus json5 comments).
    #[test]
    fn parses_spec_announce_example() {
        let json = r#"{
          "alias": "Nice Orange",
          "version": "2.0",
          "deviceModel": "Samsung",
          "deviceType": "mobile",
          "fingerprint": "random string",
          "port": 53317,
          "protocol": "https",
          "download": true,
          "announce": true
        }"#;
        let a: Announce = serde_json::from_str(json).unwrap();
        assert_eq!(a.alias, "Nice Orange");
        assert_eq!(a.device_type, Some(DeviceType::Mobile));
        assert_eq!(a.protocol_or_default(), Protocol::Https);
        assert_eq!(a.port_or(1), 53317);
        assert!(a.announce);
        assert!(a.should_reply());
    }

    #[test]
    fn announce_tolerates_nullable_fields_and_v1_flag() {
        // Minimal/legacy peer: no version/port/protocol, only the v1 flag.
        let json = r#"{"alias":"Legacy","fingerprint":"f","announcement":true}"#;
        let a: Announce = serde_json::from_str(json).unwrap();
        assert_eq!(a.version, None);
        assert_eq!(a.port_or(53317), 53317);
        assert_eq!(a.protocol_or_default(), Protocol::Https);
        assert!(a.should_reply(), "must reply to a v1 `announcement`");
    }

    #[test]
    fn parses_desktop_app_prepare_upload_with_port_minus_one() {
        // Captured from the LocalSend desktop app v1.17.0. It sends port:-1 in
        // info, which must not reject the whole request.
        let json = r#"{"info":{"alias":"-","version":"2.1","deviceModel":"Linux",
          "deviceType":"desktop","fingerprint":"1D0034EA","port":-1,
          "protocol":"https","download":false},
          "files":{"885ab628":{"id":"885ab628","fileName":"galaxy2.jpg",
          "size":4155972,"fileType":"image/jpeg",
          "metadata":{"modified":"2026-01-27T13:51:15.000Z"}}}}"#;
        let req: PrepareUploadRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.info.port, None);
        assert_eq!(req.files["885ab628"].file_name, "galaxy2.jpg");
        assert_eq!(req.files["885ab628"].size, 4155972);
    }

    #[test]
    fn lenient_port_handles_negative_zero_and_oversize() {
        for (raw, want) in [("-1", None), ("0", None), ("53317", Some(53317u16)),
                            ("70000", None), ("null", None)] {
            let json = format!(r#"{{"alias":"x","port":{raw}}}"#);
            let d: DeviceInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(d.port, want, "port {raw}");
        }
    }

    #[test]
    fn device_info_allows_absent_fingerprint_and_version() {
        // v1-compatible prepare-upload info: only alias present.
        let json = r#"{"alias":"Old Peer"}"#;
        let d: DeviceInfo = serde_json::from_str(json).unwrap();
        assert_eq!(d.fingerprint_or_default(), "");
        assert_eq!(d.version, None);
        assert_eq!(d.to_announce().port, Some(53317));
    }

    #[test]
    fn unknown_device_type_falls_back() {
        let json = r#"{"alias":"x","version":"2.0","fingerprint":"f",
                       "port":1,"protocol":"http","deviceType":"fridge"}"#;
        let a: Announce = serde_json::from_str(json).unwrap();
        assert_eq!(a.device_type, Some(DeviceType::Unknown));
    }

    #[test]
    fn optional_fields_may_be_absent() {
        // download + announce are optional (spec: "optional, default: false")
        let json = r#"{"alias":"x","version":"2.1","fingerprint":"f",
                       "port":53317,"protocol":"https"}"#;
        let a: Announce = serde_json::from_str(json).unwrap();
        assert!(!a.download);
        assert!(!a.announce);
        assert_eq!(a.device_type, None);
    }

    /// prepare-download response example from spec §5.2 (minus json5 comments).
    #[test]
    fn parses_spec_prepare_download_example() {
        let json = r#"{
          "info": {
            "alias": "Nice Orange", "version": "2.0", "deviceModel": "Samsung",
            "deviceType": "mobile", "fingerprint": "random string", "download": true
          },
          "sessionId": "mySessionId",
          "files": {
            "some file id": {
              "id": "some file id", "fileName": "my image.png",
              "size": 324242, "fileType": "image/jpeg",
              "sha256": null, "preview": null
            }
          }
        }"#;
        let r: PrepareDownloadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.session_id, "mySessionId");
        assert!(r.info.download);
        assert_eq!(r.files["some file id"].file_name, "my image.png");
        // camelCase round-trip
        let out = serde_json::to_string(&r).unwrap();
        assert!(out.contains("\"sessionId\""));
        assert!(out.contains("\"fileName\""));
    }

    #[test]
    fn prepare_upload_roundtrip_matches_spec_shape() {
        let json = r#"{
          "info": {
            "alias": "Nice Orange", "version": "2.0", "deviceModel": "Samsung",
            "deviceType": "mobile", "fingerprint": "random string",
            "port": 53317, "protocol": "https", "download": true
          },
          "files": {
            "some file id": {
              "id": "some file id", "fileName": "my image.png",
              "size": 324242, "fileType": "image/jpeg",
              "sha256": null, "preview": null,
              "metadata": { "modified": "2021-01-01T12:34:56Z", "accessed": null }
            }
          }
        }"#;
        let req: PrepareUploadRequest = serde_json::from_str(json).unwrap();
        let f = &req.files["some file id"];
        assert_eq!(f.file_name, "my image.png");
        assert_eq!(f.size, 324242);
        assert_eq!(
            f.metadata.as_ref().unwrap().modified.as_deref(),
            Some("2021-01-01T12:34:56Z")
        );
        // camelCase round-trip
        let out = serde_json::to_string(&req).unwrap();
        assert!(out.contains("\"fileName\""));
        assert!(out.contains("\"deviceType\":\"mobile\""));
    }
}
