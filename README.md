# FidoVault

FidoVault is a tool to control access to secrets via symmetric encryption and decryption using [FIDO2](https://en.wikipedia.org/wiki/FIDO_Alliance#FIDO2) authenticators. A FidoVault vault file contains a secret encrypted via one or more FIDO2 authenticators, such that the secret is inaccessible without at least one of the authenticators, but any single authenticator can decrypt the secret. A password can optionally be required for decryption in addition to an authenticator.

> [!CAUTION]
> Most FIDO2 authenticators cannot be "backed up" or duplicated. If all the authenticators of a particular FidoVault are lost (or ["reset"](https://support.yubico.com/hc/en-us/articles/360016648899-Resetting-the-FIDO2-Application-on-Your-YubiKey-or-Security-Key)), then that FidoVault will become permanently inaccessible.
>
> Additionally, [when FIDO2 authenticators make a credential, they generate two random values, `credRandomWithUV` and `credRandomWithoutUV`, and associate them with the credential](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension). In the context of an assertion, the former is used when ["user verification"](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Presence_vs_User_Verification.html) (most commonly via the entry of a PIN) is performed and the latter when it is not. Consequently, secrets encrypted by an authenticator when user verification is not performed will not be able to be decrypted by the same authenticator when user verification is performed (and vice versa). For more detailed discussion of this issue and its implications, see [here](https://github.com/keepassxreboot/keepassxc/discussions/9506#discussioncomment-11864543).

## Hardware

Any standard [USB](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#usb) authenticator that supports the [HMAC Secret Extension](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#sctn-hmac-secret-extension) (which [reportedly most do](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)) should work with FidoVault. [NFC](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#nfc) and [Bluetooth](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#nfc) authenticators have not been tested, and PC/SC authenticators are not currently supported. Development and testing have primarily been done using a [Yubico Security Key](https://www.yubico.com/products/security-key/).

## Dependencies and Installation

FidoVault is written in Python 3, and has the following dependencies:

 * [`cryptography`](https://github.com/pyca/cryptography) (Debian package `python3-cryptography`) (for symmetric encryption and decryption of secrets)
 * [`[python-]fido2`](https://github.com/Yubico/python-fido2)>=2.0.0 (Debian package `python3-fido2`) (for accessing FIDO2 authenticators)
 
> [!NOTE]
> FidoVault has been updated to work with version 2.0 of `[python-]fido2`, and the current code will not work with earlier versions.

FidoVault should work on any platform on which Python 3 and the above dependencies can be installed, although running under Windows may require administrator privileges, since [Windows apparently requires](https://support.yubico.com/hc/en-us/articles/360016648939-Troubleshooting-Failed-connecting-to-the-YubiKey-Make-sure-the-application-has-the-required-permissions-in-YubiKey-Manager) [administrator privileges](https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.YubiKeyDevice.FindByTransport.html) [for certain FIDO APIs](https://github.com/keepassxreboot/keepassxc/issues/11400).

At least on Linux, if FidoVault's dependencies are installed and available (e.g., on Debian via `apt install python3-fido2`, which will pull in `python3-cryptography` as well), then the script can be run directly without installation as `path/to/fidovault.py`. It can also be installed from PyPI via pip / pipx, in which case it can be run simply as `fidovault`.

## Usage

Display usage instructions:

```
$ fidovault.py -h
usage: fidovault.py [-h] [-v VAULT] [-k KEY] [-i | -a]

Create and manage FidoVaults - control access to secrets via symmetric encryption and decryption using FIDO2 authenticators.

options:
  -h, --help         show this help message and exit
  -v, --vault VAULT  FidoVault location
  -k, --key KEY      use (only) this key section of the FidoVault
  -i, --init         initialize a FidoVault
  -a, --add          add a key section to a FidoVault

If neither '--init' nor '--add' are specified, the program will attempt to output the FidoVault's secret to STDOUT.
```

Initialize a FidoVault:

```
$ fidovault.py -i -v <vaultname>
Enter secret: 
Confirm secret: 
Please connect the device you wish to enroll (and disconnect any others).
Press <enter> when ready ... 
Checking device at /dev/hidraw2 ...
Device supports the hmac-secret extension.
Creating FIDO2 credential ... 
Enter PIN: 
Touch your authenticator now ...
FIDO2 credential created.
Enter name for this key section: Blue Key
Perform user verification when using this key section? (y/n - default is y) 
Combine password with FIDO2 hmac-secret when using this key section? (y/n - default is y) 
Getting hmac-secret ...
Touch your authenticator now ...
Enter password: 
Confirm password: 
Key section 'Blue Key' successfully added.
FidoVault '<vaultname>' updated.

```

Add an additional authenticator to an existing FidoVault (connect an already added authenticator before proceeding):

```
$ fidovault.py -a -v <vaultname>
Checking device at /dev/hidraw2 ...
Credential found on device.
Trying to decode token using 'Blue Key' key section ...
Getting hmac-secret ...
Enter PIN: 
Touch your authenticator now ...
Enter password: 
Token decryption succeeded.
Please connect the device you wish to enroll (and disconnect any others).
Press <enter> when ready ... 
Checking device at /dev/hidraw2 ...
Device supports the hmac-secret extension.
Creating FIDO2 credential ... 
Enter PIN: 
Touch your authenticator now ...
FIDO2 credential created.
Enter name for this key section: Red Key
Perform user verification when using this key section? (y/n - default is y) 
Combine password with FIDO2 hmac-secret when using this key section? (y/n - default is y) 
Getting hmac-secret ...
Touch your authenticator now ...
Enter password: 
Confirm password: 
Key section 'Red Key' successfully added.
FidoVault '<vaultname>' updated.

```

Output a FidoVault secret:

```
$ fidovault.py -v <vaultname>
Checking device at /dev/hidraw2 ...
Credential found on device.
Trying to decode token using 'Blue Key' key section ...
Getting hmac-secret ...
Enter PIN: 
Touch your authenticator now ...
Enter password: 
Token decryption succeeded.
<secret>
```

### Providing a FidoVault secret to another program

FidoVault is designed to be used in conjunction with other programs, by providing a secret to them. For programs that accept a secret on `STDIN`, simply pipe FidoVault's `STDOUT` to them (all FidoVault user interaction output is written to `STDERR` / `/dev/tty`, and so will be printed to the terminal and not redirected to the other program). E.g., to use a FidoVault secret for symmetric encryption [and decryption](https://unix.stackexchange.com/questions/560135/how-to-decrypt-file-that-was-symmetrically-encrypted-using-gpg) of a file with [GnuPG](https://gnupg.org/), run:

```
$ fidovault.py -v <vaultname> | gpg --passphrase-fd 0 --pinentry-mode loopback -c <filename>
```

and:

```
$ fidovault.py -v <vaultname> | gpg --passphrase-fd 0 --pinentry-mode loopback --output <filename> -d <filename.gpg>
```

To open a [KeePassXC](https://keepassxc.org/) database with a FidoVault secret as password, run:

```
$ fidovault.py -v <vaultname> | keepassxc --pw-stdin /path/to/database.kdbx
```

(Unfortunately, [this only works if KeePassXC is not currently running](https://github.com/keepassxreboot/keepassxc/issues/2089).)

For programs that expect a secret as an argument, FidoVault can pass a secret to them via [`xargs`](https://en.wikipedia.org/wiki/Xargs). E.g., to open a KeePassXC database with a FidoVault secret as password [via D-Bus](https://github.com/keepassxreboot/keepassxc/wiki/Using-DBus-with-KeePassXC) when KeePassXC is already running, run:

```
$ fidovault.py -v <vaultname> | xargs qdbus org.keepassxc.KeePassXC.MainWindow /keepassxc org.keepassxc.KeePassXC.MainWindow.openDatabase /path/to/database.kdbx
```

(On Debian Sid, replace `qdbus` with `qdbus6`.)

To pass the secret at a position other than the end of the command, use the `-I replace-str` argument of `xargs`. E.g., to open a KeePassXC database with a FidoVault secret as a password plus a keyfile that resides somewhere in the filesystem via D-Bus, run:

```
$ fidovault.py -v <vaultname> | xargs -I % qdbus org.keepassxc.KeePassXC.MainWindow /keepassxc org.keepassxc.KeePassXC.MainWindow.openDatabase /path/to/database.kdbx % /path/to/keyfile
```

> [!CAUTION]
> Including a secret in a command's arguments is generally considered insecure, since the secret will be visible to anyone with access to the system process list. The above `qdbus` command is [additionally insecure since it will place the secret on the D-Bus message bus, which also may be accessible to others](https://github.com/keepassxreboot/keepassxc/issues/8826).

## Background

The original motivation of FidoVault was the desire to implement a standalone tool to [open KeePassXC databases with FIDO2 authenticators](https://github.com/keepassxreboot/keepassxc/discussions/9506), but the code quickly evolved into a more general purpose tool. FidoVault's basic architecture was inspired by the discussion [here](https://github.com/keepassxreboot/keepassxc/discussions/9506), as well as the design of [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) plus its [systemd-cryptenroll extension](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html). Indeed, I seriously contemplated using LUKS + systemd-cryptenroll (possibly with loop devices) as a general purpose FIDO2-protected secret store, but since LUKS is designed around block devices and the [device mapper](https://en.wikipedia.org/wiki/Device_mapper), it cannot be easily used by non-root users.

## Alternatives ##

Other projects similar to FidoVault:

 * [tokenring](https://github.com/glyph/tokenring): "TokenRing is a back-end for the Python keyring module, which uses a hard token to encrypt your collection of passwords as a large Fernet token, composed of individual password entries, each of which is separately encrypted as a smaller Fernet token of its own."
 * [age-plugin-fido](https://github.com/riastradh/age-plugin-fido): "draft fido plugin for age(1)" ("early draft, likely buggy, protocol not finalized", "usability issues with multiple fido keys", "not actually tested with age(1) yet")
 * [age-plugin-yubikey](https://github.com/olastor/age-plugin-fido2-hmac/): "Encrypt files with fido2 keys that support the "hmac-secret" extension."
 * [FileKey](https://filekey.app/): "Files need protection. FileKey secures them. Works with Yubikeys. Drop files in. They lock. Drop them again. They unlock. Your data stays on your device, and only you hold the key. Open source and powered by AES-256 encryption—the same standard trusted by the US government for top-secret information." ([Reddit announcement thread](https://old.reddit.com/r/yubikey/comments/1iiptny/introducing_filekey_encrypt_decrypt_files_using/))
 * [khefin](https://github.com/mjec/khefin): "A system for using a FIDO2 authenticator with hmac-secret extension support to generate passphrase-protected secrets." ([abandoned a couple of years ago](https://github.com/mjec/khefin/issues/42))

## Donations

FidoVault is absolutely free software, and there is no expectation of any sort of compensation or support for the project. That being said, if anyone wishes to donate (to Thomas More, the tool's primary author), this can be done via [the Ko-fi platform](https://ko-fi.com/thomasmore).

## License

FidoVault is free / open source software, released under the terms of the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) or later.
