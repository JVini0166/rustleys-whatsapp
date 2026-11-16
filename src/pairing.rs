//! Client payloads and authenticated pairing primitives (partial socket facade).
use crate::{
    auth::{Bytes, Credentials},
    auth_store,
    binary::{Content, Node},
    crypto, jid, proto,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidJid,
    InvalidCredentials,
    InvalidStanza,
    InvalidProtobuf,
    MissingIdentity,
    InvalidHmac,
    InvalidAccountSignature,
    IdentityConflict,
    TooLarge,
    Storage,
    StaleUpdate,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pairing: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientConfig {
    pub version: [u32; 3],
    pub browser: [String; 3],
    pub country_code: String,
    pub sync_full_history: bool,
    pub push_name: Option<String>,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            version: [2, 3000, 1043857760],
            browser: ["Mac OS".into(), "Chrome".into(), "14.4.1".into()],
            country_code: "US".into(),
            sync_full_history: false,
            push_name: None,
        }
    }
}
impl ClientConfig {
    fn validate(&self) -> Result<()> {
        if self.browser[0].is_empty()
            || self.browser[1].is_empty()
            || self.browser.iter().any(|s| s.len() > 1024)
            || self.country_code.len() > 16
            || self.push_name.as_ref().is_some_and(|s| s.len() > 4096)
        {
            Err(Error::InvalidConfig)
        } else {
            Ok(())
        }
    }
}
fn base(config: &ClientConfig) -> Result<proto::ClientPayload> {
    config.validate()?;
    let android = config.browser[1].to_lowercase().contains("android");
    let web = if config.sync_full_history && config.browser[1] == "Desktop" {
        match config.browser[0].as_str() {
            "Mac OS" => Some(proto::client_payload::web_info::WebSubPlatform::Darwin),
            "Windows" => Some(proto::client_payload::web_info::WebSubPlatform::WinHybrid),
            _ => None,
        }
    } else {
        None
    }
    .unwrap_or(proto::client_payload::web_info::WebSubPlatform::WebBrowser);
    Ok(proto::ClientPayload {
        connect_type: Some(proto::client_payload::ConnectType::WifiUnknown as i32),
        connect_reason: Some(proto::client_payload::ConnectReason::UserActivated as i32),
        user_agent: Some(proto::client_payload::UserAgent {
            app_version: Some(proto::client_payload::user_agent::AppVersion {
                primary: Some(config.version[0]),
                secondary: Some(config.version[1]),
                tertiary: Some(config.version[2]),
                ..Default::default()
            }),
            platform: Some(if android {
                proto::client_payload::user_agent::Platform::Android
            } else {
                proto::client_payload::user_agent::Platform::Web
            } as i32),
            release_channel: Some(
                proto::client_payload::user_agent::ReleaseChannel::Release as i32,
            ),
            os_version: Some("0.1".into()),
            device: Some("Desktop".into()),
            os_build_number: Some("0.1".into()),
            locale_language_iso6391: Some("en".into()),
            mnc: Some("000".into()),
            mcc: Some("000".into()),
            locale_country_iso31661_alpha2: Some(config.country_code.clone()),
            ..Default::default()
        }),
        web_info: (!android).then_some(proto::client_payload::WebInfo {
            web_sub_platform: Some(web as i32),
            ..Default::default()
        }),
        push_name: config.push_name.as_ref().filter(|s| !s.is_empty()).cloned(),
        ..Default::default()
    })
}
pub fn registration_payload(
    creds: &Credentials,
    config: &ClientConfig,
) -> Result<proto::ClientPayload> {
    creds.validate().map_err(|_| Error::InvalidCredentials)?;
    if creds.signed_pre_key.key_id > 0xff_ffff {
        return Err(Error::InvalidCredentials);
    }
    let name = config.browser[1].to_uppercase();
    let platform = if name == "ANDROID" {
        proto::device_props::PlatformType::AndroidPhone
    } else {
        proto::device_props::PlatformType::from_str_name(&name)
            .filter(|p| *p != proto::device_props::PlatformType::Unknown)
            .unwrap_or(proto::device_props::PlatformType::Chrome)
    };
    let props = proto::DeviceProps {
        os: Some(config.browser[0].clone()),
        platform_type: Some(platform as i32),
        require_full_sync: Some(config.sync_full_history),
        version: Some(proto::device_props::AppVersion {
            primary: Some(10),
            secondary: Some(15),
            tertiary: Some(7),
            ..Default::default()
        }),
        history_sync_config: Some(proto::device_props::HistorySyncConfig {
            storage_quota_mb: Some(10240),
            inline_initial_payload_in_e2_ee_msg: Some(true),
            support_call_log_history: Some(false),
            support_bot_user_agent_chat_history: Some(true),
            support_cag_reactions_and_polls: Some(true),
            support_biz_hosted_msg: Some(true),
            support_recent_sync_chunk_message_count_tuning: Some(true),
            support_hosted_group_msg: Some(true),
            support_fbid_bot_chat_history: Some(true),
            support_message_association: Some(true),
            support_group_history: Some(false),
            ..Default::default()
        }),
    };
    let version = config
        .version
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let mut payload = base(config)?;
    payload.passive = Some(false);
    payload.pull = Some(false);
    payload.device_pairing_data = Some(proto::client_payload::DevicePairingRegistrationData {
        build_hash: Some(crypto::md5(version.as_bytes()).to_vec()),
        device_props: Some(props.encode_to_vec()),
        e_regid: Some(u32::from(creds.registration_id).to_be_bytes().to_vec()),
        e_keytype: Some(vec![5]),
        e_ident: Some(creds.signed_identity_key.public.expose().to_vec()),
        e_skey_id: Some(creds.signed_pre_key.key_id.to_be_bytes()[1..].to_vec()),
        e_skey_val: Some(creds.signed_pre_key.key_pair.public.expose().to_vec()),
        e_skey_sig: Some(creds.signed_pre_key.signature.expose().to_vec()),
    });
    Ok(payload)
}
pub fn login_payload(user_jid: &str, config: &ClientConfig) -> Result<proto::ClientPayload> {
    let parsed = jid::jid_decode(user_jid).map_err(|_| Error::InvalidJid)?;
    if !matches!(
        parsed.server,
        "s.whatsapp.net" | "lid" | "hosted" | "hosted.lid"
    ) || parsed.user.is_empty()
        || !parsed.user.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::InvalidJid);
    }
    let user = parsed.user.parse::<u64>().map_err(|_| Error::InvalidJid)?;
    // Avoid silently emulating JavaScript's lossy Number coercion.
    if user > 9_007_199_254_740_991 {
        return Err(Error::InvalidJid);
    }
    let mut payload = base(config)?;
    payload.passive = Some(true);
    payload.pull = Some(true);
    payload.username = Some(user);
    payload.device = parsed.device;
    payload.lid_db_migrated = Some(false);
    Ok(payload)
}
pub fn client_payload(creds: &Credentials, config: &ClientConfig) -> Result<proto::ClientPayload> {
    creds.validate().map_err(|_| Error::InvalidCredentials)?;
    match creds.me.as_ref() {
        None | Some(Value::Null) => registration_payload(creds, config),
        Some(me) => login_payload(
            me.get("id")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidJid)?,
            config,
        ),
    }
}
pub fn companion_web_client_type(browser: &[String; 3]) -> u8 {
    match browser[1].as_str() {
        "Desktop" => {
            if browser[0] == "Windows" {
                8
            } else {
                7
            }
        }
        "Chrome" => 1,
        "Edge" => 2,
        "Firefox" => 3,
        "IE" => 4,
        "Opera" => 5,
        "Safari" => 6,
        _ => 9,
    }
}
pub struct QrData(Zeroizing<String>);
impl QrData {
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for QrData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QrData([redacted])")
    }
}
pub fn pairing_qr_data(
    reference: &str,
    creds: &Credentials,
    browser: &[String; 3],
) -> Result<QrData> {
    creds.validate().map_err(|_| Error::InvalidCredentials)?;
    if reference.is_empty() || reference.len() > 4096 || reference.contains([',', '\n', '\r']) {
        return Err(Error::InvalidStanza);
    }
    Ok(QrData(Zeroizing::new(format!(
        "https://wa.me/settings/linked_devices#{},{},{},{},{}",
        reference,
        STANDARD.encode(creds.noise_key.public.expose()),
        STANDARD.encode(creds.signed_identity_key.public.expose()),
        creds.adv_secret_key,
        companion_web_client_type(browser)
    ))))
}
fn attr<'a>(node: &'a Node, key: &str) -> Result<Option<&'a str>> {
    let mut fields = node.attrs.iter().filter(|(k, _)| k == key);
    let value = fields.next().map(|(_, v)| v.as_str());
    if fields.next().is_some() {
        return Err(Error::InvalidStanza);
    }
    Ok(value)
}
fn child<'a>(node: &'a Node, tag: &str) -> Result<Option<&'a Node>> {
    let Some(Content::Nodes(children)) = &node.content else {
        return Ok(None);
    };
    let mut found = children.iter().filter(|c| c.tag == tag);
    let value = found.next();
    if found.next().is_some() {
        return Err(Error::InvalidStanza);
    }
    Ok(value)
}
fn bytes(node: &Node) -> Result<&[u8]> {
    match &node.content {
        Some(Content::Bytes(bytes)) if !bytes.is_empty() && bytes.len() <= 1024 * 1024 => Ok(bytes),
        _ => Err(Error::InvalidStanza),
    }
}
fn known_type(value: Option<i32>) -> Result<i32> {
    match value {
        None | Some(0) => Ok(0),
        Some(1) => Ok(1),
        _ => Err(Error::InvalidProtobuf),
    }
}
pub fn encode_signed_device_identity(
    account: &proto::AdvSignedDeviceIdentity,
    include_key: bool,
) -> Vec<u8> {
    let mut account = account.clone();
    if !include_key
        || account
            .account_signature_key
            .as_ref()
            .is_some_and(Vec::is_empty)
    {
        account.account_signature_key = None;
    }
    account.encode_to_vec()
}
/// A verified update. Its acknowledgement is released only after persistence.
pub struct PairingUpdate {
    expected: [u8; 32],
    credentials: Credentials,
    reply: Node,
}
impl std::fmt::Debug for PairingUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingUpdate([redacted])")
    }
}
impl PairingUpdate {
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
    pub fn persist_and_reply(
        self,
        store: &auth_store::MultiFileStore,
        current: &mut Credentials,
    ) -> Result<Node> {
        self.commit_and_reply(current, |expected, updated| {
            store
                .compare_and_save_credentials(expected, updated)
                .map_err(|error| {
                    if matches!(error, auth_store::Error::Conflict) {
                        Error::StaleUpdate
                    } else {
                        Error::Storage
                    }
                })
        })
    }
    /// A custom backend must return success only after its durable commit.
    pub fn commit_and_reply(
        self,
        current: &mut Credentials,
        persist: impl FnOnce(&Credentials, &Credentials) -> Result<()>,
    ) -> Result<Node> {
        let snapshot = current.to_json().map_err(|_| Error::InvalidCredentials)?;
        if !bool::from(self.expected.ct_eq(&crypto::sha256(&snapshot))) {
            return Err(Error::StaleUpdate);
        }
        persist(current, &self.credentials)?;
        *current = self.credentials;
        Ok(self.reply)
    }
}
pub fn configure_successful_pairing(stanza: &Node, creds: &Credentials) -> Result<PairingUpdate> {
    creds.validate().map_err(|_| Error::InvalidCredentials)?;
    if stanza.tag != "iq" {
        return Err(Error::InvalidStanza);
    }
    let msg_id = attr(stanza, "id")?
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .ok_or(Error::InvalidStanza)?;
    let success = child(stanza, "pair-success")?.ok_or(Error::MissingIdentity)?;
    let identity = child(success, "device-identity")?.ok_or(Error::MissingIdentity)?;
    let device = child(success, "device")?.ok_or(Error::MissingIdentity)?;
    let pn = attr(device, "jid")?.ok_or(Error::InvalidJid)?;
    let lid = attr(device, "lid")?.ok_or(Error::InvalidJid)?;
    let parsed = jid::jid_decode(pn).map_err(|_| Error::InvalidJid)?;
    let parsed_lid = jid::jid_decode(lid).map_err(|_| Error::InvalidJid)?;
    if parsed.user.is_empty()
        || !matches!(parsed.server, "s.whatsapp.net" | "hosted")
        || parsed_lid.user.is_empty()
        || !matches!(parsed_lid.server, "lid" | "hosted.lid")
    {
        return Err(Error::InvalidJid);
    }
    let wrapper = proto::AdvSignedDeviceIdentityHmac::decode(bytes(identity)?)
        .map_err(|_| Error::InvalidProtobuf)?;
    let details = wrapper
        .details
        .filter(|b| !b.is_empty())
        .ok_or(Error::MissingIdentity)?;
    let mut hmac_input = Vec::new();
    if known_type(wrapper.account_type)? == 1 {
        hmac_input.extend([6, 5]);
    }
    hmac_input.extend(&details);
    let secret = Zeroizing::new(
        STANDARD
            .decode(&creds.adv_secret_key)
            .map_err(|_| Error::InvalidCredentials)?,
    );
    let expected = crypto::hmac_sha256(&hmac_input, &secret);
    let hmac = wrapper.hmac.ok_or(Error::InvalidHmac)?;
    if hmac.len() != 32 || !bool::from(expected.ct_eq(hmac.as_slice())) {
        return Err(Error::InvalidHmac);
    }
    let mut account = proto::AdvSignedDeviceIdentity::decode(details.as_slice())
        .map_err(|_| Error::InvalidProtobuf)?;
    let device_details = account.details.as_deref().ok_or(Error::MissingIdentity)?;
    let decoded =
        proto::AdvDeviceIdentity::decode(device_details).map_err(|_| Error::InvalidProtobuf)?;
    let key_index = decoded.key_index.ok_or(Error::MissingIdentity)?;
    let account_key = account
        .account_signature_key
        .as_deref()
        .ok_or(Error::MissingIdentity)?;
    if !matches!(account_key.len(), 32 | 33) {
        return Err(Error::InvalidAccountSignature);
    }
    known_type(decoded.account_type)?;
    let prefix = if known_type(decoded.device_type)? == 1 {
        [6, 5]
    } else {
        [6, 0]
    };
    let mut message = prefix.to_vec();
    message.extend(device_details);
    message.extend(creds.signed_identity_key.public.expose());
    if !crypto::verify_signature(
        account_key,
        &message,
        account
            .account_signature
            .as_deref()
            .ok_or(Error::MissingIdentity)?,
    ) {
        return Err(Error::InvalidAccountSignature);
    }
    let mut device_message = vec![6, 1];
    device_message.extend(device_details);
    device_message.extend(creds.signed_identity_key.public.expose());
    device_message.extend(account_key);
    let signing_key = crypto::PrivateKey::from_bytes(
        creds
            .signed_identity_key
            .private
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidCredentials)?,
    );
    account.device_signature = Some(
        signing_key
            .sign(&device_message)
            .map_err(|_| Error::InvalidCredentials)?
            .to_vec(),
    );
    let new_identity = json!({"identifier":{"name":lid,"deviceId":0},"identifierKey":Bytes::new(crypto::generate_signal_pub_key(account_key))});
    let mut identities = match &creds.signal_identities {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(values)) if values.len() <= 4096 => values.clone(),
        _ => return Err(Error::InvalidCredentials),
    };
    let mut exists = false;
    for identity in &identities {
        if identity.pointer("/identifier/name").and_then(Value::as_str) == Some(lid)
            && identity
                .pointer("/identifier/deviceId")
                .and_then(Value::as_u64)
                == Some(0)
        {
            let key: Bytes = serde_json::from_value(
                identity
                    .get("identifierKey")
                    .cloned()
                    .ok_or(Error::InvalidCredentials)?,
            )
            .map_err(|_| Error::InvalidCredentials)?;
            if key.expose() != crypto::generate_signal_pub_key(account_key) {
                return Err(Error::IdentityConflict);
            }
            exists = true;
        }
    }
    if !exists {
        if identities.len() == 4096 {
            return Err(Error::TooLarge);
        }
        identities.push(new_identity);
    }
    let mut me = json!({"id":pn,"lid":lid});
    if let Some(biz) = child(success, "biz")?
        && let Some(name) = attr(biz, "name")?
    {
        me["name"] = json!(name);
    }
    let platform = child(success, "platform")?
        .map(|node| attr(node, "name"))
        .transpose()?
        .flatten()
        .map(str::to_owned);
    let account_json = json!({"details":account.details.as_ref().map(|v|STANDARD.encode(v)),"accountSignatureKey":account.account_signature_key.as_ref().map(|v|STANDARD.encode(v)),"accountSignature":account.account_signature.as_ref().map(|v|STANDARD.encode(v)),"deviceSignature":account.device_signature.as_ref().map(|v|STANDARD.encode(v))});
    let encoded = encode_signed_device_identity(&account, false);
    let mut updated = creds.clone();
    updated.account = Some(account_json);
    updated.me = Some(me);
    updated.signal_identities = Some(json!(identities));
    updated.platform = platform;
    let reply = Node {
        tag: "iq".into(),
        attrs: vec![
            ("to".into(), "s.whatsapp.net".into()),
            ("type".into(), "result".into()),
            ("id".into(), msg_id.into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: "pair-device-sign".into(),
            attrs: vec![],
            content: Some(Content::Nodes(vec![Node {
                tag: "device-identity".into(),
                attrs: vec![("key-index".into(), key_index.to_string())],
                content: Some(Content::Bytes(encoded)),
            }])),
        }])),
    };
    Ok(PairingUpdate {
        expected: crypto::sha256(&creds.to_json().map_err(|_| Error::InvalidCredentials)?),
        credentials: updated,
        reply,
    })
}

/// QR reference rotation driven by the host's monotonic clock, without detached
/// timers or retention of private identity/noise keys. Persist initial creds first.
pub struct QrRotation {
    references: std::collections::VecDeque<Zeroizing<String>>,
    suffix: Zeroizing<String>,
    custom_timeout: Option<std::time::Duration>,
    next_at: Option<std::time::Instant>,
    first: bool,
    cancelled: bool,
}
impl std::fmt::Debug for QrRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QrRotation([redacted])")
    }
}
#[derive(Debug)]
pub enum QrPoll {
    Ready {
        qr: QrData,
        expires_at: std::time::Instant,
    },
    Waiting {
        deadline: std::time::Instant,
    },
    Exhausted,
}
impl QrRotation {
    pub fn from_stanza(
        stanza: &Node,
        creds: &Credentials,
        browser: &[String; 3],
        custom_timeout: Option<std::time::Duration>,
    ) -> Result<(Node, Self)> {
        creds.validate().map_err(|_| Error::InvalidCredentials)?;
        if stanza.tag != "iq" || attr(stanza, "type")? != Some("set") {
            return Err(Error::InvalidStanza);
        }
        let id = attr(stanza, "id")?
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or(Error::InvalidStanza)?;
        if custom_timeout.is_some_and(|d| d.is_zero() || d > std::time::Duration::from_secs(86_400))
        {
            return Err(Error::InvalidConfig);
        }
        let challenge = child(stanza, "pair-device")?.ok_or(Error::InvalidStanza)?;
        let Some(Content::Nodes(children)) = &challenge.content else {
            return Err(Error::InvalidStanza);
        };
        let mut references = std::collections::VecDeque::new();
        let mut total = 0usize;
        for reference in children.iter().filter(|child| child.tag == "ref") {
            let reference =
                std::str::from_utf8(bytes(reference)?).map_err(|_| Error::InvalidStanza)?;
            // Validate the format without exposing its temporary secret string.
            pairing_qr_data(reference, creds, browser)?;
            total = total.saturating_add(reference.len());
            if references.len() == 256 || total > 1024 * 1024 {
                return Err(Error::TooLarge);
            }
            references.push_back(Zeroizing::new(reference.to_owned()));
        }
        if references.is_empty() {
            return Err(Error::InvalidStanza);
        }
        let suffix = Zeroizing::new(format!(
            ",{},{},{},{}",
            STANDARD.encode(creds.noise_key.public.expose()),
            STANDARD.encode(creds.signed_identity_key.public.expose()),
            creds.adv_secret_key,
            companion_web_client_type(browser)
        ));
        let reply = Node {
            tag: "iq".into(),
            attrs: vec![
                ("to".into(), "s.whatsapp.net".into()),
                ("type".into(), "result".into()),
                ("id".into(), id.into()),
            ],
            content: None,
        };
        Ok((
            reply,
            Self {
                references,
                suffix,
                custom_timeout,
                next_at: None,
                first: true,
                cancelled: false,
            },
        ))
    }
    pub fn cancel(&mut self) {
        use zeroize::Zeroize;
        self.references.clear();
        self.suffix.zeroize();
        self.next_at = None;
        self.cancelled = true;
    }
    pub fn poll(&mut self, now: std::time::Instant) -> Result<QrPoll> {
        if self.cancelled {
            return Ok(QrPoll::Exhausted);
        }
        if let Some(deadline) = self.next_at
            && now < deadline
        {
            return Ok(QrPoll::Waiting { deadline });
        }
        if self.references.is_empty() {
            self.cancel();
            return Ok(QrPoll::Exhausted);
        }
        let duration = self
            .custom_timeout
            .unwrap_or(std::time::Duration::from_secs(if self.first {
                60
            } else {
                20
            }));
        let expires_at = now.checked_add(duration).ok_or(Error::InvalidConfig)?;
        let reference = self.references.pop_front().ok_or(Error::InvalidStanza)?;
        self.first = false;
        self.next_at = Some(expires_at);
        Ok(QrPoll::Ready {
            qr: QrData(Zeroizing::new(format!(
                "https://wa.me/settings/linked_devices#{}{}",
                reference.as_str(),
                self.suffix.as_str()
            ))),
            expires_at,
        })
    }
}
