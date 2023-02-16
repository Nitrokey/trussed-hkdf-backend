// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

use heapless_bytes::Bytes;
use hex_literal::hex;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use trussed::{client::HmacSha256, syscall, types::Location};
use trussed_hkdf::{virt::with_ram_client, HkdfClient, KeyOrData::*};

const SALT: &[u8] = &hex!("0011223344556677889900AABBCCDDEE");
const IKM: &[u8] = &hex!("AABBCCDDEE0011223344556677889900");
const INFO: &[u8] = b"INFO";
const MSG: &[u8] = b"MSG";

#[test_log::test]
fn extensions() {
    let ref_hkdf = Hkdf::<Sha256>::new(Some(SALT), IKM);
    let mut okm = [0; 16];
    ref_hkdf.expand(INFO, &mut okm).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&okm).unwrap();
    mac.update(MSG);
    with_ram_client("hkdf_test", |mut client| {
        let prk = syscall!(client.hkdf_extract(
            Data(Bytes::from_slice(IKM).unwrap()),
            Some(Data(Bytes::from_slice(SALT).unwrap())),
            Location::External,
        ))
        .okm;
        let expanded = syscall!(client.hkdf_expand(
            prk,
            Bytes::from_slice(INFO).unwrap(),
            16,
            Location::Volatile
        ))
        .key;
        let signed = syscall!(client.sign_hmacsha256(expanded, MSG)).signature;
        mac.verify(&signed).unwrap();
    });
}
