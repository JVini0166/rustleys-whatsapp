//! JID helpers translated from Baileys WABinary/jid-utils.ts (MIT).
//! Numeric components currently accept unsigned protocol integers; legacy JS
//! coercion of malformed, fractional or infinite values is not implemented.

pub const S_WHATSAPP_NET: &str = "@s.whatsapp.net";
pub const OFFICIAL_BIZ_JID: &str = "16505361212@c.us";
pub const SERVER_JID: &str = "server@c.us";
pub const PSA_WID: &str = "0@c.us";
pub const STORIES_JID: &str = "status@broadcast";
pub const META_AI_JID: &str = "13135550002@c.us";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Domain {
    WhatsApp = 0,
    Lid = 1,
    Hosted = 128,
    HostedLid = 129,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jid<'a> {
    pub user: &'a str,
    pub server: &'a str,
    pub device: Option<u32>,
    pub domain_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    MissingSeparator,
    InvalidAgent,
    InvalidDevice,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub fn get_server_from_domain_type(initial: &str, domain: Option<u32>) -> &str {
    match domain {
        Some(1) => "lid",
        Some(128) => "hosted",
        Some(129) => "hosted.lid",
        _ => initial,
    }
}

pub fn jid_encode(user: &str, server: &str, device: Option<u32>, agent: Option<u32>) -> String {
    let mut out = String::with_capacity(user.len() + server.len() + 16);
    out.push_str(user);
    if let Some(a) = agent.filter(|a| *a != 0) {
        out.push('_');
        out.push_str(&a.to_string());
    }
    if let Some(d) = device.filter(|d| *d != 0) {
        out.push(':');
        out.push_str(&d.to_string());
    }
    out.push('@');
    out.push_str(server);
    out
}

pub fn jid_decode(jid: &str) -> Result<Jid<'_>, Error> {
    let (combined, server) = jid.split_once('@').ok_or(Error::MissingSeparator)?;
    let mut parts = combined.split(':');
    let mut user_agent = parts.next().unwrap_or_default().split('_');
    let user = user_agent.next().unwrap_or_default();
    let agent = user_agent.next();
    let device = parts
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| Error::InvalidDevice))
        .transpose()?;
    // A hosted/LID server overrides the agent component in the upstream helper.
    let domain_type = match server {
        "lid" => 1,
        "hosted" => 128,
        "hosted.lid" => 129,
        _ => agent
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| Error::InvalidAgent))
            .transpose()?
            .unwrap_or(0),
    };
    Ok(Jid {
        user,
        server,
        device,
        domain_type,
    })
}

pub fn are_jids_same_user(a: Option<&str>, b: Option<&str>) -> bool {
    a.and_then(|j| jid_decode(j).ok()).map(|j| j.user)
        == b.and_then(|j| jid_decode(j).ok()).map(|j| j.user)
}
pub fn jid_normalized_user(jid: Option<&str>) -> String {
    jid.and_then(|s| jid_decode(s).ok())
        .map(|j| {
            jid_encode(
                j.user,
                if j.server == "c.us" {
                    "s.whatsapp.net"
                } else {
                    j.server
                },
                None,
                None,
            )
        })
        .unwrap_or_default()
}
pub fn transfer_device(from: &str, to: &str) -> Result<String, Error> {
    let device = jid_decode(from).ok().and_then(|j| j.device);
    let to = jid_decode(to)?;
    Ok(jid_encode(to.user, to.server, device, None))
}
macro_rules! suffix_predicate {
    ($name:ident, $suffix:literal) => {
        pub fn $name(jid: Option<&str>) -> bool {
            jid.is_some_and(|s| s.ends_with($suffix))
        }
    };
}
suffix_predicate!(is_jid_meta_ai, "@bot");
suffix_predicate!(is_pn_user, "@s.whatsapp.net");
suffix_predicate!(is_lid_user, "@lid");
suffix_predicate!(is_jid_broadcast, "@broadcast");
suffix_predicate!(is_jid_group, "@g.us");
suffix_predicate!(is_jid_newsletter, "@newsletter");
suffix_predicate!(is_hosted_pn_user, "@hosted");
suffix_predicate!(is_hosted_lid_user, "@hosted.lid");
pub fn is_jid_status_broadcast(jid: &str) -> bool {
    jid == STORIES_JID
}
pub fn is_jid_bot(jid: Option<&str>) -> bool {
    let Some(user) = jid.and_then(|s| s.strip_suffix("@c.us")) else {
        return false;
    };
    user.len() == 11
        && user.bytes().all(|b| b.is_ascii_digit())
        && (user.starts_with("1313555") || user.starts_with("131655500"))
}
