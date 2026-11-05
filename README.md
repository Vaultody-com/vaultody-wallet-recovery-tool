![VAULTODY](./src/resources/images/logo.svg?raw=true)

# VAULTODY Vault Recovery tool

#### Tool for recovering the master private key from vault recovery data

***

## Table of Contents

- [Download](#download)
  - [Verify your download](#verify-your-download)
- [Installing](#installing)
  - [First Method](#first-method)
- [Usage](#usage)
- [Building executable files](#building-executable-files)
    - [With docker](#with-docker)
    - [Without docker](#without-docker)
    - [Packages](#packages)
- [Releasing](#releasing)
- [License](#license)

## Download

Ready-to-use installers are published with every release. Pick the file for your operating system:

| Operating system | File | Download |
| --- | --- | --- |
| macOS (Intel and Apple Silicon) | `.dmg` | [Download for macOS](https://github.com/Vaultody-com/vaultody-wallet-recovery-tool/releases/latest/download/vaultody-wallet-recovery-tool.dmg) |
| Windows | `.exe` | [Download for Windows](https://github.com/Vaultody-com/vaultody-wallet-recovery-tool/releases/latest/download/vaultody-wallet-recovery-tool.exe) |
| Linux | `.AppImage` | [Download for Linux](https://github.com/Vaultody-com/vaultody-wallet-recovery-tool/releases/latest/download/vaultody-wallet-recovery-tool.AppImage) |

Every link above always serves the newest published version. Earlier versions and the release notes are on the
[Releases page](https://github.com/Vaultody-com/vaultody-wallet-recovery-tool/releases).

> **_NOTE:_** The installers are not code-signed. On macOS, open the application the first time via right-click on it and
> then "Open". On Windows, confirm the SmartScreen prompt. On Linux, make the `.AppImage` file executable with
> `chmod +x vaultody-wallet-recovery-tool.AppImage` before running it.

If you prefer to run the tool from its source code instead of using an installer, follow [Installing](#installing).

### Verify your download

This tool handles private keys, so check that the installer you downloaded is the one Vaultody built
from this repository before you run it. Every release, from v2.1.1 on, publishes three things next to
the installers:

- `SHA256SUMS`: the SHA-256 checksum of every installer;
- `SHA256SUMS.sigstore.json`: a signature over `SHA256SUMS`, made by this repository's release
  workflow (Sigstore keyless signing, verified with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/));
- a build provenance attestation for every installer, which records the repository, the workflow and
  the commit it was built from (verified with the [GitHub CLI](https://cli.github.com/)).

Download `SHA256SUMS` and `SHA256SUMS.sigstore.json` from the same release as the installer, put them in
the same folder, and run the three checks. Each must succeed; if one fails, do not run the installer.

**1. The installer matches the published checksum**

```bash
# macOS / Linux (replace the file name with the one you downloaded)
grep ' vaultody-wallet-recovery-tool.dmg$' SHA256SUMS | shasum -a 256 -c -
```

```powershell
# Windows (PowerShell): the two hashes must be identical
(Get-FileHash .\vaultody-wallet-recovery-tool.exe -Algorithm SHA256).Hash
Select-String 'vaultody-wallet-recovery-tool.exe' .\SHA256SUMS
```

**2. The checksums were signed by this repository's release workflow**

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Vaultody-com/vaultody-wallet-recovery-tool/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**3. The installer was built by GitHub Actions from this repository**

```bash
gh attestation verify vaultody-wallet-recovery-tool.dmg --repo Vaultody-com/vaultody-wallet-recovery-tool
```

## Installing

#### First Method

First you need to clone the repository.

Then you need to have `npm` package manager installed.

To install and start the application you need to run these two commands.

```bash
npm i -D
npm run start
```


## Usage

This Open Source Tool will help you back up and then recover your VAULTODY Vault in case of an emergency. It should be used together with the WaaS Backup and Recover feature in your VAULTODY Dashboard [here](https://app.vaultody.com/login).
To back up your Vault simply follow the steps below:

1. Open our Open Source Recovery Tool.
2. You would need to first generate a RSA key pair of public and private keys. For this purpose you require a password. It can be of your choosing, or you can generate a random and complex password by navigating to the “Generate Random Password” menu section.
3. Use the selected password in the "Generate RSA key pairs" menu section. The result will be one public key and one private key. Keep that password safe as it will be needed to recover your Vault.
4. Navigate to your VAULTODY Dashboard [here](https://app.vaultody.com/login). If you don’t have a Vault yet, you can create one. If you have already created your Vault, then open it and click the “Vault backup” button in its settings. Use the public key you’ve just generated in our Open Source Recovery Tool in the two fields for the RSA key.
5. The private key needs to be stored in a safe location, as it will be required for the recovery process of your Vault!
6. In the VAULTODY Dashboard complete the backup of your Vault. The PDF file downloaded will have more information on the Recovery process.

## Building executable files

### With docker

You need to have `docker` installed on your machine.

Building executable files can be done with this command (script):

```bash
./bin/build.sh
```

Choose the OS you want to have an executable for by giving the script a parameter with the name of the OS.

```bash
./bin/build.sh linux
./bin/build.sh windows
./bin/build.sh mac
```

> **_NOTE:_** Building executable files for macOS can be done only if the machine you are executing the script from is on macOS.

### Without docker

Using the following command will build the files for the OS you are executing it from

```bash
npm run build
```

If you want to build files for a specific OS you can use either of these scripts

```bash
npm run dist:linux
npm run dist:windows
npm run dist:mac
```

> **_NOTE:_** Building executable files without docker requires for the machine to be on the same OS or to have the necessary packages installed.

### Packages

Packages are located in `dist` folder

The file types that you get are as follows:
- For `linux` you will get `.AppImage` file
- For `windows` you will get `.exe` file
- For `macOS` you will get `.dmg` file

## Releasing

Releases are automated via GitHub Actions. Pushing a version tag triggers a build on all three platforms (Linux, Windows, macOS) and publishes a GitHub Release with the installers attached.

A release is cut only from reviewed code: the workflow refuses a tag that does not point at a commit on
`master`, and only the release managers may create `v*` tags. Running the workflow by hand
(`workflow_dispatch`) builds the installers as workflow artifacts and never creates a release.

### Steps

**1. Make sure you are on `master` and up to date**

```bash
git checkout master
git pull
```

**2. Bump the version in `package.json`**

Replace `1.0.0` with the version you want to release.

```bash
npm version 1.0.0 --no-git-tag-version
```

**3. Merge the version bump into `master`**

`master` takes changes only through a reviewed pull request: commit the version bump on a branch,
open a pull request and merge it.

```bash
git checkout -b release-1.0.0
git add package.json
git commit -m "chore: bump version to 1.0.0"
git push origin release-1.0.0
```

**4. Create and push the tag (release managers only)**

The tag must start with `v`, match the version in `package.json`, and point at the merged commit on
`master`; the workflow refuses any other.

```bash
git checkout master
git pull
git tag v1.0.0
git push origin v1.0.0
```

**5. GitHub Actions takes over**

Once the tag is pushed, the workflow automatically:
- Builds `.AppImage` on Linux
- Builds `.exe` on Windows
- Builds a universal `.dmg` on macOS (works on both Intel and Apple Silicon)
- Publishes `SHA256SUMS`, signs it (`SHA256SUMS.sigstore.json`) and records build provenance for every installer
- Creates a **draft** GitHub Release with the installers, `SHA256SUMS` and its signature attached, and release notes generated from commits since the previous tag
- Downloads the assets back from the release and verifies the checksums, the signature and the provenance; the run fails if any check fails

**6. Publish the release**

Go to the repository's **Releases** page on GitHub, review the draft release, optionally edit the description, and click **Publish release**.

> **_NOTE:_** The release is created as a draft — it will not be visible to users until you publish it manually.

## License

Released under the [MIT License](./LICENSE).
