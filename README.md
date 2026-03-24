![VAULTODY](./src/resources/images/logo.svg?raw=true)

# VAULTODY Wallet Recovery tool

#### Tool for recovering private key from wallet recovery data

***

## Table of Contents

- [Installing](#installing)
  - [First Method](#first-method)
- [Usage](#usage)
- [Building executable files](#building-executable-files)
    - [With docker](#with-docker)
    - [Without docker](#without-docker)
    - [Packages](#packages)
- [Releasing](#releasing)
- [License](#license)

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

This Open Source Tool will help you back up and then recover your VAULTODY Wallet in case of an emergency. It should be used together with the WaaS Backup and Recover feature in your VAULTODY Dashboard [here](https://my.vaultody.com).
To backup your Wallet simply follow the steps bellow:

1. Open our Open Source Recovery Tool.
2. You would need to first generate a RSA key pair of public and private keys. For this purpose you require a password. It can be of your choosing, or you can generate a random and complex password by navigating to the “Generate Random Password” menu section.
3. Use the selected password in the "Generate RSA key pairs" menu section. The result will be one public key and one private key. Keep that password safe as it will be needed to recover your Wallet.
4. Navigate to your VAULTODY Dashboard [here](https://my.vaultody.com). If you don’t have a Wallet yet, you can create one. If you have already created your Wallet, then click on the “Back up Wallet” button. Use the public key you’ve just generated in our Open Source Recovery Tool in the two fields for the RSA key.
5. The private key needs to be stored in a safe location, as it will be required for the recovery process of your Wallet!
6. In the VAULTODY Dashboard complete the backup of your Wallet. The PDF file downloaded will have more information on the Recovery process.

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
