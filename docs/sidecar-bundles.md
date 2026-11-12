# Run 1-SEC with Rust scanning

Choose the `1sec-with-rust` archive for your operating system and processor from the [GitHub releases](https://github.com/simpleending/1-sec/releases/latest). Extract it into its own directory and start the engine from that directory.

```bash
./1sec up
```

On Windows, use `.\1sec.exe up` in PowerShell.

The bundle includes `1sec` and `1sec-engine` with their Windows extensions where applicable. The included configuration enables Rust. The main engine starts the adjacent scanner, supplies the private broker credential, and receives its match results. The scanner processes supplied telemetry. Native packet capture requires a separate build with packet-capture support.

For an upgrade, preserve your existing configuration and private data. Place the matching executables together and set `rust_engine.enabled: true` in your existing config.

## Verify the download

Download `sidecar-bundle-checksums.txt` and `sidecar-bundle-checksums.txt.sigstore.json` from the same release. Verify the manifest's signature with Cosign.

```bash
cosign verify-blob \
  --bundle sidecar-bundle-checksums.txt.sigstore.json \
  --certificate-identity https://github.com/simpleending/1-sec/.github/workflows/publish-sidecar-bundles.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sidecar-bundle-checksums.txt
```

That identity applies to the bundles added to v0.4.33. For bundles created during subsequent tagged releases, use the release workflow identity `https://github.com/simpleending/1-sec/.github/workflows/release.yml@refs/tags/<tag>` with the exact release tag.

Compute the SHA-256 hash of the downloaded archive and compare it to the corresponding line in the verified manifest. Use `sha256sum <archive>` on Linux, `shasum -a 256 <archive>` on macOS, or `Get-FileHash <archive> -Algorithm SHA256` in PowerShell.
