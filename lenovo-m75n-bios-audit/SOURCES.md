# Source manifest
Public Lenovo download page: https://support.lenovo.com/de/de/downloads/ds544268

| Artifact | SHA-256 |
|---|---|
| ImageM33(1).ROM (M33KT32A, 16 MiB) | 7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145 |
| ImageM33.ROM (M33KT33A, 16 MiB) | fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498 |
| m33j932usa.iso | b7fbed7fbec2299566e3c1b952360c200e2715cb39d1546e7a258542a094f97a |
| m33j933usa.iso | 7e6880cda4f04341c25eafd6d17704aa29c55acb9c90ca3daf61806fbee512a3 |
| m33jy32usa.exe | 1eb506878ba105e67cf6d711699e3af3e032bd3df0a54b17e080a4bb8ce4f4db |
| m33jy33usa.exe | 125774152cefe19e7ac0d81ddc31caee891845189b9b0d54c9e0802dfcb307c6 |

1.24 input is a private live AFU dump, 16 MiB, not a clean vendor image. Obtain from owner privately, verify its hash against private manifest. Do not share or commit it. 1.31 not available and not needed for scope. OEM packages obtained from user uploads; EXE payload not unpacked (Inno Setup 6.1.0). ISO El Torito FAT32 contains matching ROM; outer ISO contains an unrelated 8 MiB M11 image, not the M33 image.

Tools: UEFIExtract NE A75, ifrextract-rs, GNU objdump, Python 3, openssl, ACPICA iasl. Toolchain archives were supplied separately; not redistributed here. Obtain exact versions from owner; a new UEFIExtract version can change section extraction and instance ordering.
