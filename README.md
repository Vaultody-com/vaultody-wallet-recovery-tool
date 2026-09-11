![VAULTODY](./src/resources/images/logo.svg?raw=true)

# VAULTODY Vault Recovery tool

#### Tool for recovering the master private key from vault recovery data

***

## Table of Contents

- [Download](#download)
- [Installing](#installing)
  - [First Method](#first-method)
- [Usage](#usage)
  - [Sealing your key parts for an import](#sealing-your-key-parts-for-an-import)
    - [One file, every key of the Vault](#one-file-every-key-of-the-vault)
    - [What this tool accepts](#what-this-tool-accepts)
    - [What "migration" means here, and what it does not](#what-migration-means-here-and-what-it-does-not)
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
To back up your Vault simply follow the steps bellow:

1. Open our Open Source Recovery Tool.
2. You would need to first generate a RSA key pair of public and private keys. For this purpose you require a password. It can be of your choosing, or you can generate a random and complex password by navigating to the “Generate Random Password” menu section.
3. Use the selected password in the "Generate RSA key pairs" menu section. The result will be one public key and one private key. Keep that password safe as it will be needed to recover your Vault.
4. Navigate to your VAULTODY Dashboard [here](https://app.vaultody.com/login). If you don’t have a Vault yet, you can create one. If you have already created your Vault, then open it and click the “Vault backup” button in its settings. Use the public key you’ve just generated in our Open Source Recovery Tool in the two fields for the RSA key.
5. The private key needs to be stored in a safe location, as it will be required for the recovery process of your Vault!
6. In the VAULTODY Dashboard complete the backup of your Vault. The PDF file downloaded will have more information on the Recovery process.

### Sealing your key parts for an import

If a player of your Vault's MPC key is permanently lost, VAULTODY can restore the key onto its nodes from the backup
package you already hold. Your backup holds one part per player, and the tool's **Seal key import** screen is what
prepares them: it opens each part and immediately re-locks it for the single node that owns that seat. The parts are
never put together, so the master private key is not formed on this machine at any point.

1. In your VAULTODY Dashboard, start the key import for the Vault. The owner approves it on the phone, and the
   Dashboard then shows a 6-digit verification code and offers a **key import ticket** to download. The ticket says
   which node owns which seat and carries no secrets.
2. Open **Seal key import** in this tool and choose the ticket, **every** Vault backup data file the ticket covers, and
   your RSA private key — plus its password when the key is SJCL encrypted.
3. Press **Seal the key parts**. The tool reports each key it sealed, with its seats, and offers **one** file to
   download.
4. Upload that file in the Dashboard together with the 6-digit code.
5. Back up the Vault again afterwards. The old packages still open the old keys, but their parts are out of date.

### One file, every key of the Vault

A Vault can hold two MPC keys — an `ecdsa` one for chains like Bitcoin and Ethereum, and an `eddsa` one for chains like
Solana — and they are separate keys, backed up into separate files. A key import covers **all** of them: the Dashboard
walks every key on the ticket and refuses an upload that is short one of them.

So the backup picker takes several files at once (hold ⌘ or Ctrl to select more than one), and one sealed file comes
back covering every key on the ticket. It is named `key_import_<vaultId>.json`, with no algorithm in the name. Give one
backup file per key: a file for a key the ticket does not import, or two files for the same key, is refused, and so is
a run missing the backup of a key the ticket does list — the message names the algorithm you still have to supply.

### What this tool accepts

Both kinds of import read the same format. Every backup data file must be:

- a **VAULTODY backup data file** — the `.json` your Dashboard produced when you backed the Vault up;
- a `shamir` sharing, because interpolating the imported points is what rebuilds the key inside the ceremony;
- carrying a part for **every seat the ticket names**, each part labelled with its own player index — the shared/ERS
  format, whose parts carry no index, cannot be used, because a part's seat cannot be read off its position;
- with every part, and the master chain code, RSA-sealed to the backup key pair you generated in this tool.

Anything else is refused rather than sealed, and the refusal names the format that was wanted: a short or
mis-addressed set of parts would not fail the ceremony, it would rebuild a different key.

The ticket is checked in full before anything is opened, and each refusal says which file to fix — a ticket with no
session id for the algorithm (the parts could not be locked to anything), a seat with no node public key, a kind this
tool does not seal for, or a ticket that asks for seats your backup has no part for.

### What "migration" means here, and what it does not

When the import is a **migration**, the ticket also carries the key you declared when you started the import: its chain
code and its compressed public key. Those are what the nodes will be handed, so those are what the tool seals against;
you are not asked to type them here a second time. If the declared public key is not the key your backup file holds,
the tool says so and seals nothing, because every node would rebuild the key from the parts and refuse at the end of
the ceremony anyway.

That is the **only** difference between the two kinds:

| | recovery | migration |
| --- | --- | --- |
| Is there a retired key on this deployment? | yes | no |
| Where the public key and chain code come from | each node's own stored row for the retired key | declared when the import was started, echoed on the ticket |
| Backup package format | VAULTODY backup data file | **the same** VAULTODY backup data file |

A migration therefore means *"import a VAULTODY-format backup package of a key this deployment does not hold"* — in
practice a key from another VAULTODY deployment, or one you backed up with this tool. **It is not a general importer**:
a key exported from another custody provider is a different format and is refused by name.

#### What a genuinely external key would additionally require

Accepting a third-party custodian's export is a larger piece of work than widening a validator, and none of it exists
today. It would need, at least:

- **A defined input format per source.** Every custodian exports something different — a BIP32 `xprv`, a PKCS#8 or
  SEC1 private key, a set of GG18/CMP/DKLS shares in that vendor's own encoding, a shard file protected by that
  vendor's own KMS. There is no single "external key file" to parse, so each source is its own reader, its own test
  vectors and its own security review.
- **A sharing step in the tool.** A VAULTODY package arrives already split into one Shamir part per player. An
  external key usually arrives whole, so the tool would have to *create* the sharing here: sample a polynomial over the
  right curve, evaluate it at each seat's abscissa and seal the points. That means the whole private key would exist
  in this process's memory — which today, deliberately, it never does — so it would need its own threat model, and the
  audit trail and wipe guarantees to match.
- **A curve and encoding map.** The parts, the group public key and the chain code all enter the envelope binding in
  mpc-node's own encodings (compressed SEC1 on secp256k1, the 32-byte encoded point on ed25519). An importer would
  have to convert from each source's encoding and prove it converted correctly, because a mis-encoded public key pins
  a binding production can never reproduce.
- **A chain code decision.** BIP32 derivation needs a master chain code. An external key may carry one, may carry a
  different derivation scheme, or may carry none at all — in which case somebody has to decide what the Vault's
  derivation tree is rooted at, and that decision changes every address the Vault will ever produce.
- **Proof of possession, before the ceremony.** A recovery is anchored by the node's own row for the retired key, and
  today's migration is anchored by the public key declared at initialization. Neither proves the client actually holds
  the private key they are importing. An external path wants a signature over a challenge under the imported key,
  checked before any node is asked to take part.
- **Dashboard support for declaring it.** The chain code and public key of a migration are declared when the import is
  initialized. Anything an external format needs on top of those — a derivation path, a source vendor, a
  proof-of-possession signature — has to be declarable there too, and carried onto the ticket.

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

MIT
