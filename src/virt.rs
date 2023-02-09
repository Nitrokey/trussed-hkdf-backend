//! Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`HkdfBackend`](crate::HkdfBackend) backend.

use crate::HkdfBackend;

use serde::{Deserialize, Serialize};
use trussed::{
    api::{reply, request},
    backend,
    serde_extensions::{ExtensionDispatch, ExtensionImpl},
    service::ServiceResources,
    types::{Context, NoData},
    virt::{self, Filesystem, Ram, StoreProvider},
    Error, Platform,
};

use std::path::PathBuf;

pub type Client<S, D = Dispatcher> = virt::Client<S, D>;

pub struct Dispatcher;
pub enum BackendId {
    Hkdf,
}

#[derive(Serialize, Deserialize)]
#[repr(u8)]
pub enum ExtensionIds {
    Hkdf = 0,
}

impl TryFrom<u8> for ExtensionIds {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        if v == 0 {
            Ok(ExtensionIds::Hkdf)
        } else {
            Err(Error::InternalError)
        }
    }
}

impl ExtensionDispatch for Dispatcher {
    type BackendId = BackendId;
    type Context = NoData;
    type ExtensionId = ExtensionIds;

    fn extension_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        match backend {
            BackendId::Hkdf => match extension {
                ExtensionIds::Hkdf => HkdfBackend.extension_request_serialized(
                    &mut ctx.core,
                    &mut ctx.backends,
                    request,
                    resources,
                ),
            },
        }
    }
}

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<S>) -> R,
    S: StoreProvider,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            Dispatcher,
            &[
                backend::BackendId::Custom(BackendId::Hkdf),
                backend::BackendId::Core,
            ],
            f,
        )
    })
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Filesystem>) -> R,
    P: Into<PathBuf>,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
