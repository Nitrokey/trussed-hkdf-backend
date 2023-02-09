#![cfg_attr(not(feature = "std"), no_std)]

use heapless_bytes::Bytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use trussed::{
    backend::Backend,
    config::MAX_MEDIUM_DATA_LENGTH,
    key::{Kind, Secrecy},
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::{ClientKeystore, Keystore, ServiceResources},
    store::Store,
    types::{CoreContext, KeyId, Location, MediumData, Message, NoData, ShortData},
    Error, Platform,
};

#[cfg(feature = "virt")]
pub mod virt;

#[cfg(feature = "delog")]
delog::generate_macros!();

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[derive(Serialize, Deserialize)]
pub struct OkmId(KeyId);

pub struct HkdfExtension;

/// Can represent either data or a key
#[derive(Serialize, Deserialize)]
pub enum KeyOrData<const N: usize> {
    Key(KeyId),
    Data(Bytes<N>),
}

impl Extension for HkdfExtension {
    type Request = HkdfRequest;
    type Reply = HkdfReply;
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum HkdfRequest {
    Extract(HkdfExtractRequest),
    Expand(HkdfExpandRequest),
}
#[derive(Serialize, Deserialize)]
pub enum HkdfReply {
    Extract(HkdfExtractReply),
    Expand(HkdfExpandReply),
}

impl From<HkdfExpandRequest> for HkdfRequest {
    fn from(v: HkdfExpandRequest) -> Self {
        Self::Expand(v)
    }
}

impl From<HkdfExtractRequest> for HkdfRequest {
    fn from(v: HkdfExtractRequest) -> Self {
        Self::Extract(v)
    }
}

impl From<HkdfExpandReply> for HkdfReply {
    fn from(v: HkdfExpandReply) -> Self {
        Self::Expand(v)
    }
}

impl From<HkdfExtractReply> for HkdfReply {
    fn from(v: HkdfExtractReply) -> Self {
        Self::Extract(v)
    }
}

impl TryFrom<HkdfRequest> for HkdfExpandRequest {
    type Error = Error;
    fn try_from(v: HkdfRequest) -> Result<Self, Error> {
        match v {
            HkdfRequest::Expand(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<HkdfRequest> for HkdfExtractRequest {
    type Error = Error;
    fn try_from(v: HkdfRequest) -> Result<Self, Error> {
        match v {
            HkdfRequest::Extract(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HkdfReply> for HkdfExpandReply {
    type Error = Error;
    fn try_from(v: HkdfReply) -> Result<Self, Error> {
        match v {
            HkdfReply::Expand(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<HkdfReply> for HkdfExtractReply {
    type Error = Error;
    fn try_from(v: HkdfReply) -> Result<Self, Error> {
        match v {
            HkdfReply::Extract(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExtractReply {
    pub okm: OkmId,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExtractRequest {
    pub ikm: KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
    pub salt: Option<KeyOrData<MAX_MEDIUM_DATA_LENGTH>>,
    /// Location to store the OKM
    pub storage: Location,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExpandReply {
    pub key: KeyId,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExpandRequest {
    pub prk: OkmId,
    pub info: Message,
    pub len: usize,
    pub storage: Location,
}

pub trait HkdfClient: ExtensionClient<HkdfExtension> {
    fn hkdf_extract(
        &mut self,
        ikm: KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
        salt: Option<KeyOrData<MAX_MEDIUM_DATA_LENGTH>>,
        storage: Location,
    ) -> ExtensionResult<'_, HkdfExtension, HkdfExtractReply, Self> {
        self.extension(HkdfRequest::Extract(HkdfExtractRequest {
            ikm,
            salt,
            storage,
        }))
    }
    fn hkdf_expand(
        &mut self,
        prk: OkmId,
        info: Message,
        len: usize,
        storage: Location,
    ) -> ExtensionResult<'_, HkdfExtension, HkdfExpandReply, Self> {
        self.extension(HkdfRequest::Expand(HkdfExpandRequest {
            prk,
            info,
            len,
            storage,
        }))
    }
}

impl<C: ExtensionClient<HkdfExtension>> HkdfClient for C {}

pub struct HkdfBackend;

impl Backend for HkdfBackend {
    type Context = NoData;
}

impl ExtensionImpl<HkdfExtension> for HkdfBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut NoData,
        request: &HkdfRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<HkdfReply, Error> {
        let mut keystore = resources.keystore(core_ctx)?;
        Ok(match request {
            HkdfRequest::Extract(req) => extract(req, &mut keystore)?.into(),
            HkdfRequest::Expand(req) => expand(req, &mut keystore)?.into(),
        })
    }
}

fn get_mat<S: Store>(
    req: &KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
    keystore: &mut ClientKeystore<S>,
) -> Result<MediumData, Error> {
    Ok(match req {
        KeyOrData::Data(d) => d.clone(),
        KeyOrData::Key(key_id) => {
            let key_mat = keystore.load_key(Secrecy::Secret, None, key_id)?;
            if !matches!(key_mat.kind, Kind::Symmetric(..) | Kind::Shared(..)) {
                warn!("Attempt to HKDF on a private key");
                return Err(Error::MechanismInvalid);
            }
            Bytes::from_slice(&key_mat.material).map_err(|_| {
                warn!("Attempt to HKDF a too large key");
                Error::InternalError
            })?
        }
    })
}

fn extract<S: Store>(
    req: &HkdfExtractRequest,
    keystore: &mut ClientKeystore<S>,
) -> Result<HkdfExtractReply, Error> {
    let ikm = get_mat(&req.ikm, keystore)?;
    let salt = req
        .salt
        .as_ref()
        .map(|s| get_mat(s, keystore))
        .transpose()?;
    let salt_ref = salt.as_deref().map(|d| &**d);
    let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);
    assert_eq!(prk.len(), 256 / 8);
    let key_id = keystore.store_key(
        req.storage,
        Secrecy::Secret,
        Kind::Symmetric(prk.len()),
        &prk,
    )?;
    Ok(HkdfExtractReply { okm: OkmId(key_id) })
}
fn expand<S: Store>(
    req: &HkdfExpandRequest,
    keystore: &mut ClientKeystore<S>,
) -> Result<HkdfExpandReply, Error> {
    let prk = keystore.load_key(Secrecy::Secret, None, &req.prk.0)?;
    if !matches!(prk.kind, Kind::Symmetric(32)) {
        error!("Attempt to use wrong key for HKDF expand");
        return Err(Error::ObjectHandleInvalid);
    }

    let hkdf = Hkdf::<Sha256>::from_prk(&prk.material).map_err(|_| {
        warn!("Failed to create HKDF");
        Error::InternalError
    })?;
    let mut okm = ShortData::new();
    okm.resize_default(req.len).map_err(|_| {
        error!("Attempt to run HKDF with too large output");
        Error::WrongMessageLength
    })?;
    hkdf.expand(&req.info, &mut okm).map_err(|_| {
        warn!("Bad HKDF expand length");
        Error::WrongMessageLength
    })?;

    let key = keystore.store_key(
        req.storage,
        Secrecy::Secret,
        Kind::Symmetric(okm.len()),
        &okm,
    )?;

    Ok(HkdfExpandReply { key })
}
