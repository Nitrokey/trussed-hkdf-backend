// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::{
    HkdfExpandReply, HkdfExpandRequest, HkdfExtension, HkdfExtractReply, HkdfExtractRequest,
    HkdfRequest, KeyOrData, OkmId,
};
use trussed::{
    config::MAX_MEDIUM_DATA_LENGTH,
    serde_extensions::{ExtensionClient, ExtensionResult},
    types::{Location, Message},
};

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
