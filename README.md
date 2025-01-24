# FidoVault

FidoVault is a tool to control access to secrets via symmetric encryption and decryption using hardware [FIDO2](https://en.wikipedia.org/wiki/FIDO_Alliance#FIDO2) keys. A FidoVault vault file contains a secret encrypted via one or more FIDO2 keys, such that the secret is inaccessible without at least one of the keys, but any single key can decrypt the secret. A password can optionally be required for decryption in addition to a key.

> [!CAUTION]
> Most FIDO2 keys cannot be "backed up" or duplicated. If all the keys of a particular FidoVault are lost or ["reset"](https://support.yubico.com/hc/en-us/articles/360016648899-Resetting-the-FIDO2-Application-on-Your-YubiKey-or-Security-Key)), then that FidoVault will become permanently inaccessible.
>
> Additionally, [when FIDO2 keys make a credential, they generate two random values, `credRandomWithUV` and `credRandomWithoutUV`, and associate them with the credential](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension). In the context of an assertion, the former is used when ["user verification" (`userVerification` or `uv`)](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Presence_vs_User_Verification.html) is done and the latter when it is not. Consequently, secrets encrypted by a key when user verification is not done will not be able to be decrypted by the same key when user verification is done (and vice versa). For more detailed discussion of this issue and its implications, see [here](https://github.com/keepassxreboot/keepassxc/discussions/9506#discussioncomment-11864543).

## Hardware

Any hardware FIDO2 key that supports the [HMAC Secret Extension](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#sctn-hmac-secret-extension) (which [reportedly most do](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)) should work with FidoVault. Development and testing have primarily been done using a [Yubico Security Key](https://www.yubico.com/products/security-key/).

## Dependencies

FidoVault is written in Python 3, and has the following dependencies:

 * [Cryptography](https://github.com/pyca/cryptography) (for symmetric encryption and decryption of secrets)
 * [python-fido2 version 1.2.0](https://github.com/Yubico/python-fido2/releases/tag/1.2.0) (for accessing FIDO2 keys)
 
> [!NOTE]
> Be sure to use version 1.2.0 of python-fido2; FidoVault will not work correctly with earlier versions.

## Usage

Initialize a FidoVault:

```
$ fidovault.py -i -v <vaultname>
Enter secret: 
Confirm secret: 
Prompt for passwords to combine with FIDO2 hmac-secrets? (y/n - default is y) y
Please connect the FIDO2 key you wish to add (and disconnect any others).
Press <enter> when ready ... 
Checking key at /dev/hidraw1 ...
Key supports the hmac-secret extension.
Making FIDO2 credential ... 
Touch your authenticator device now ...
Success.
Getting hmac-secret ... 
Touch your authenticator device now ...
Success.
Enter password (leave blank for none): 
Confirm password: 
Enter name for this key: Blue Key
FIDO2 key successfully added.
FidoVault '<vaultname>' updated.
```

Add an additional key to an existing FidoVault (connect an already configured FIDO2 key before proceeding):

```
$ fidovault.py -a -v <vaultname>
Checking key at /dev/hidraw1 ...
Key supports the hmac-secret extension.
Touch your authenticator device now ...
Enter password (leave blank for none): 
Attempting to decrypt token of 'Blue Key' ...
Token decryption succeeded.
Please connect the FIDO2 key you wish to add (and disconnect any others).
Press <enter> when ready ... 
Checking key at /dev/hidraw1 ...
Key supports the hmac-secret extension.
Making FIDO2 credential ... 
Touch your authenticator device now ...
Success.
Getting hmac-secret ... 
Touch your authenticator device now ...
Success.
Enter password (leave blank for none): 
Confirm password: 
Enter name for this key: Red Key
FIDO2 key successfully added.
FidoVault '<vaultname> updated.
```

Print a FidoVault secret:

```
$ fidovault.py -v <vaultname>
Checking key at /dev/hidraw1 ...
Key supports the hmac-secret extension.
Touch your authenticator device now ...
Enter password (leave blank for none): 
Attempting to decrypt token of 'Blue Key' ...
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

The original motivation of FidoVault was the desire to implement a standalone tool to [open KeePassXC databases with FIDO2 keys](https://github.com/keepassxreboot/keepassxc/discussions/9506), but the code quickly evolved into a more general purpose tool. FidoVault's basic architecture was inspired by the discussion [here](https://github.com/keepassxreboot/keepassxc/discussions/9506), as well as the design of [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) plus its [systemd-cryptenroll extension](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html). Indeed, I seriously contemplated using LUKS + systemd-cryptenroll (possibly with loop devices) as a general purpose FIDO2-protected secret store, but since LUKS is designed around block devices and the [device mapper](https://en.wikipedia.org/wiki/Device_mapper), it cannot be easily used by non-root users.

## Alternatives ##

Other projects similar to FidoVault:

 * [tokenring](https://github.com/glyph/tokenring): "TokenRing is a back-end for the Python keyring module, which uses a hard token to encrypt your collection of passwords as a large Fernet token, composed of individual password entries, each of which is separately encrypted as a smaller Fernet token of its own."
 * [age-plugin-fido](https://github.com/riastradh/age-plugin-fido): "draft fido plugin for age(1)" ("early draft, likely buggy, protocol not finalized", "usability issues with multiple fido keys", "not actually tested with age(1) yet")
 * [age-plugin-yubikey](https://github.com/olastor/age-plugin-fido2-hmac/): "Encrypt files with fido2 keys that support the "hmac-secret" extension."
 * [khefin](https://github.com/mjec/khefin): "A system for using a FIDO2 authenticator with hmac-secret extension support to generate passphrase-protected secrets." ([abandoned a couple of years ago](https://github.com/mjec/khefin/issues/42))

## Donations

FidoVault is absolutely free software, and there is no expectation of any sort of compensation or support for the project. That being said, if anyone wishes to donate (to Thomas More, the tool's primary author), this can be done via [the Ko-fi platform](https://ko-fi.com/thomasmore).

## License

FidoVault is free / open source software, released under the terms of the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) or later.
