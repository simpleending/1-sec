"""Bundle the verified main archive and matching Rust asset for each target."""

import gzip
import hashlib
import io
import re
import stat
import sys
import tarfile
import zipfile
from pathlib import Path


SUPPORT_FILES = {"LICENSE", "README.md", "configs/default.yaml", "install.sh"}
RUST_ENABLED = rb"(?m)(^rust_engine:[ \t]*\r?\n[ \t]+enabled:[ \t]*)false(?=[ \t]*(?:\r?$|#))"
BUNDLE_GUIDE = b"""# Run 1-SEC with Rust scanning

Extract the archive into its own directory and open a terminal there.

- Linux or macOS: run `./1sec up`.
- Windows PowerShell: run `.\x5c1sec.exe up`.

The included configuration enables Rust scanning. The main engine launches
the adjacent Rust executable and connects it to the embedded broker.
The portable scanner processes supplied telemetry. Native packet capture
requires a separate build with packet-capture support.

If upgrading an existing installation, preserve its private data and config.
Keep the two matching executables together and set `rust_engine.enabled: true`
in your existing configuration.
"""


def signed_hashes(path):
    return {
        name: digest
        for line in path.read_text(encoding="ascii").splitlines()
        for digest, name in [line.split(maxsplit=1)]
    }


def verify_input(path, hashes):
    with path.open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != hashes.get(path.name):
            raise ValueError(f"Input does not match its signed manifest: {path.name}")


def read_archive(path, expected):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if sorted(entry.filename for entry in entries) != sorted(expected):
                raise ValueError(f"Unexpected archive contents: {path.name}")
            if any(stat.S_ISLNK(entry.external_attr >> 16) for entry in entries):
                raise ValueError(f"Symlink in archive: {path.name}")
            return {entry.filename: archive.read(entry) for entry in entries}

    with tarfile.open(path, "r:gz") as archive:
        entries = archive.getmembers()
        if sorted(entry.name for entry in entries) != sorted(expected):
            raise ValueError(f"Unexpected archive contents: {path.name}")
        if any(not entry.isfile() for entry in entries):
            raise ValueError(f"Non-file entry in archive: {path.name}")
        return {entry.name: archive.extractfile(entry).read() for entry in entries}


def write_archive(path, contents, executables):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in sorted(contents.items()):
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | (0o755 if name in executables else 0o644)) << 16
                archive.writestr(info, data)
        return

    with path.open("wb") as file, gzip.GzipFile(filename="", fileobj=file, mode="wb", mtime=0) as stream:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in sorted(contents.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name in executables else 0o644
                archive.addfile(info, io.BytesIO(data))


def package(tag, source, destination):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag, re.ASCII):
        raise ValueError(f"Invalid release tag: {tag!r}")
    version = tag.removeprefix("v")
    engine_hashes = signed_hashes(source / "checksums.txt")
    rust_hashes = signed_hashes(source / "rust-checksums.txt")
    destination.mkdir(exist_ok=False, parents=True)
    checksums = []
    for system in ("darwin", "linux", "windows"):
        suffix = ".exe" if system == "windows" else ""
        extension = "zip" if system == "windows" else "tar.gz"
        engine = f"1sec{suffix}"
        rust = f"1sec-engine{suffix}"
        for arch in ("amd64", "arm64"):
            agent = source / f"1sec_{version}_{system}_{arch}.{extension}"
            sidecar = source / f"1sec-engine-{system}-{arch}{suffix}"
            verify_input(agent, engine_hashes)
            verify_input(sidecar, rust_hashes)
            contents = read_archive(agent, SUPPORT_FILES | {engine})
            del contents["install.sh"]
            contents["BUNDLE.md"] = BUNDLE_GUIDE
            contents[rust] = sidecar.read_bytes()
            if not contents[engine] or not contents[rust]:
                raise ValueError(f"Missing executable content for {system}/{arch}")
            config, changes = re.subn(RUST_ENABLED, rb"\g<1>true", contents["configs/default.yaml"])
            if changes != 1:
                raise ValueError(f"Expected one disabled Rust setting in {agent.name}")
            contents["configs/default.yaml"] = config
            bundle = destination / f"1sec-with-rust_{version}_{system}_{arch}.{extension}"
            write_archive(bundle, contents, {engine, rust})
            if read_archive(bundle, contents.keys()) != contents:
                raise ValueError(f"Could not verify bundled files: {bundle.name}")
            with bundle.open("rb") as file:
                checksums.append(f"{hashlib.file_digest(file, 'sha256').hexdigest()}  {bundle.name}\n")

    (destination / "sidecar-bundle-checksums.txt").write_text("".join(checksums), encoding="ascii", newline="\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: package-sidecar-bundles.py <tag> <verified-inputs-dir> <output-dir>")
    package(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
