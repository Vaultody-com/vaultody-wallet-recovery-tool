![VAULTODY](./src/resources/images/logo.svg?raw=true)

# VAULTODY Vault Recovery tool

#### Tool for recovering the master private key from vault recovery data

***

## Table of Contents

- [Download](#download)
- [Installing](#installing)
  - [First Method](#first-method)
- [Usage](#usage)
- [Recovering an embedded-wallet vault with the 24 recovery words](#recovering-an-embedded-wallet-vault-with-the-24-recovery-words)
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

## Recovering an embedded-wallet vault with the 24 recovery words

A vault created inside an application that embeds VAULTODY (the WaaS wallet widget) is backed up from the wallet
itself, not from the Dashboard, and without an RSA key. The wallet shows **24 recovery words** once, and VAULTODY
e-mails an encrypted **backup file** (`vaultody-backup-<vaultId>.json`, format `ecies-p256-v1`). Every share in that
file is sealed toward a key only the words derive, so the file is useless without the words and the words are
useless without the file. Keep them apart.

To recover offline:

1. Open the tool and go to **Recover with words**.
2. Choose the backup file from the e-mail.
3. Type the 24 words, in order. Case and spacing do not matter.
4. Press **Recover master keys**. For each key the vault holds, the tool shows the master extended private key
   (masked until you reveal it) and its public half, so a recovery can be checked without revealing anything.

How it works, for the record: the words give 32 bytes of entropy; `d = HKDF-SHA256(entropy, "", "vaultody:backup:v1") mod n`
on P-256, and `Q = d·G` must equal the `recipientPublicKey` in the file, otherwise the words are not this file's.
Each sealed part is opened with ECDH against its own ephemeral key, HKDF-SHA256 (`info = version ‖ Q ‖ E`) and
AES-256-GCM with the part's label as additional data, so a part moved to another key or index does not open. The
three shares of a key (indices 0 and 1 are VAULTODY's nodes, 2 the wallet) are the points of a degree-2 polynomial
at `x = index + 1`; Lagrange interpolation at zero gives the master private key, and the key's own chain code, sealed
under the key's id (`keyId|0|chain-code`), completes the extended key. A file written before the per-key chain code
carries one for the whole package (`master-chain-code|0|-`); the tool applies it to every key. The `mpc-identity`
entry in the file belongs to the wallet and moves no funds; the tool skips it.

The format's public test vectors are in `tests/backup-package.spec.js`, and `examples/recover-from-words.js` opens
the example package in `examples/data` with the words in `examples/data/recovery_words.txt`.

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

**3. Commit and push the version bump**

```bash
git add package.json
git commit -m "chore: bump version to 1.0.0"
git push origin master
```

**4. Create and push the tag**

The tag must start with `v` and match the version in `package.json`.

```bash
git tag v1.0.0
git push origin v1.0.0
```

**5. GitHub Actions takes over**

Once the tag is pushed, the workflow automatically:
- Builds `.AppImage` on Linux
- Builds `.exe` on Windows
- Builds a universal `.dmg` on macOS (works on both Intel and Apple Silicon)
- Creates a **draft** GitHub Release with all three installers attached and release notes generated from commits since the previous tag

**6. Publish the release**

Go to the repository's **Releases** page on GitHub, review the draft release, optionally edit the description, and click **Publish release**.

> **_NOTE:_** The release is created as a draft — it will not be visible to users until you publish it manually.

## License

Released under the [MIT License](./LICENSE).
