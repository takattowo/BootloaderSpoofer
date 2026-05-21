# Bootloader Spoofer

Spoof locked bootloader on local attestations. Built against the modern [libxposed API 101](https://github.com/libxposed/api). Only select apps which check the presence of an unlocked bootloader, never hook Google apps or system framework unless you want to fail Play Integrity checks lol.

If the app sends the certificate to a secure server, you are fucked and this app is useless.

This app was made possible with @chiteroman and @5ec1cff's CertHack.

## Modes

Selectable in the UI; persisted to `mode.txt` in the module's data dir.

### `leaf_hack` (requires a working TEE)

Lets the real AndroidKeyStore generate the leaf, then in `engineGetCertificateChain` rewrites the leaf's RoT extension to claim verified-boot green / locked / state=0 and re-signs the leaf with the keybox intermediate's private key. The rest of the chain is replaced with the keybox CA chain.

This is the cleanest path: leaf serial number, validity period, subject, public key all come from the real cert. Only the RoT bytes change.

### `cert_generate` (works on broken TEE)

Generates a fresh `KeyPair` in `AndroidOpenSSL` / `Conscrypt` (skipping AndroidKeyStore), builds the leaf cert from scratch with a full RoT extension (purpose, algorithm, keySize, digest, ecCurve, noAuthRequired, origin, verifiedBoot fields, OS version, OS patch level, applicationID, vendor patch level, boot patch level), signs with the keybox intermediate. Caches chain by `KeystoreAlias` so `engineGetCertificateChain(alias)` returns the synthesized chain on later lookup.

Does **not** require AndroidKeyStore to produce a real chain; works when keymaster HAL / TEE is broken or absent.

Limitations vs leaf-hack:
- The generated keypair is **not** actually in the AndroidKeyStore. Apps that re-fetch via `KeyStore.getEntry(alias)` get `null`.
- `KeyInfo.isInsideSecureHardware()` is not hooked; returns the device's real value (false on broken TEE, so app may know).
- `applicationID` is best-effort; built from the current process's own package signatures.

## Keybox

Ships with the public Google Android Software Attestation Root test keybox (the same EC + RSA keys/certs every prior fork embeds). These are public, not TEE-backed, and will **not** beat any online check that validates against Google's hardware attestation root or revocation list. Local attestation only.

### Supply your own

XML format (TrickyStore-compatible subset):

```xml
<?xml version="1.0"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="any">
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----
... your EC private key ...
-----END EC PRIVATE KEY-----</PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>3</NumberOfCertificates>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----
... intermediate ...
-----END CERTIFICATE-----</Certificate>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----
... root ...
-----END CERTIFICATE-----</Certificate>
      </CertificateChain>
    </Key>
    <Key algorithm="rsa">
      <PrivateKey format="pem">... RSA private key ...</PrivateKey>
      <CertificateChain>
        ... RSA chain ...
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
```

## Build (local)

```
gradle :app:assembleRelease
```
