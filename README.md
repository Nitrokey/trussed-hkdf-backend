<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# trussed-hkdf

`trussed-hkdf` is an extension and custom backend for [Trussed][] that provides an HKDF extension.

> [!IMPORTANT]  
> The `trussed-hkdf` crate providing the `HkdfExtension` has been moved into the [trussed-staging][] repository.
> New releases are tagged there.
> The `HkdfBackend` has been removed.
> Use the `StagingBackend` provided by `trussed-staging` instead.
> This repository is no longer maintained and archived.

[Trussed]: https://github.com/trussed-dev/trussed
[trussed-staging]: https://github.com/trussed-dev/trussed-staging

## License

This project is dual-licensed under the [Apache-2.0][] and [MIT][] licenses.
Configuration files and examples are licensed under the [CC0 1.0
license][CC0-1.0].  For more information, see the license header in each file.
You can find a copy of the license texts in the [`LICENSES`](./LICENSES)
directory.

[Apache-2.0]: https://opensource.org/licenses/Apache-2.0
[MIT]: https://opensource.org/licenses/MIT
[CC0-1.0]: https://creativecommons.org/publicdomain/zero/1.0/

This project complies with [version 3.0 of the REUSE specification][reuse].

[reuse]: https://reuse.software/practices/3.0/
