Bundled OpenVPN for GVPN
========================

Client:  OpenVPN 2.7.9, from OpenVPN-2.7.9-I001-amd64.msi (community release, signed by OpenVPN Inc.)
Driver:  TAP-Windows6 9.27.0, from dist.win10.zip of https://github.com/OpenVPN/tap-windows6/releases
         (zip SHA-256 36E2609B7CEEFEDCB978CE5C48CAF9E0E5AF83423717C4E2E3C1D7EBCA8F62A5;
         tap0901.sys/.cat signed by Microsoft Windows Hardware Compatibility Publisher)
License: GPLv2, see license.txt. Sources: https://github.com/OpenVPN/openvpn,
         https://github.com/OpenVPN/tap-windows6

Why bundled: the community MSI runs JScript custom actions (GetInstallDir etc.). On systems
where the JScript engine is unavailable it fails with Windows Installer error 2739, and
Sentinel blocks outbound downloads while it runs. Sentinel setup therefore installs these
files offline instead of running the MSI.

Why TAP and not DCO: VPNGate servers only offer AES-128-CBC; the DCO driver only carries AEAD
ciphers (AES-GCM, ChaCha20). The 2.7.9 MSI no longer contains TAP-Windows6.

Contents
  bin\openvpn.exe, libcrypto-3-x64.dll, libssl-3-x64.dll, libpkcs11-helper-1.dll,
      vcruntime140.dll        - OpenVPN client runtime
  bin\tapctl.exe              - creates/removes the "GVPN TAP" adapter
  drivers\tap-windows6\       - OemVista.inf, tap0901.sys, tap0901.cat (amd64)

Updating: replace the files from newer releases. installer\build.ps1 refuses to package any
.exe/.dll/.sys/.cat here that lacks a valid Authenticode signature.
