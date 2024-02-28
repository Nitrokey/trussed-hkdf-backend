// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

//! Test that the core backend is still reachable.
//! Tests imported from the trussed repo

use trussed::{client::CertificateClient as _, syscall, try_syscall, types::Location::*};
use trussed_hkdf::virt;

#[test]
fn certificate_client() {
    virt::with_ram_client("rsa test", |mut client| {
        let fake_der = &[1u8, 2, 3];
        let id = syscall!(client.write_certificate(Volatile, fake_der)).id;

        let loaded_der = syscall!(client.read_certificate(id)).der;
        assert_eq!(loaded_der, fake_der);

        assert!(try_syscall!(client.read_certificate(id)).is_ok());
        assert!(try_syscall!(client.delete_certificate(id)).is_ok());
        assert!(try_syscall!(client.read_certificate(id)).is_err());
        assert!(try_syscall!(client.delete_certificate(id)).is_err());
    });
}
