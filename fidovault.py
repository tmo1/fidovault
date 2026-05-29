#! /usr/bin/env python3

# FidoVault: A tool to control access to secrets via symmetric encryption and decryption using FIDO2 authenticators.
# Copyright (c) 2025-2026 Thomas More.
# Project home: https://github.com/tmo1/fidovault
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Some of the code in this file has been copied from the python-fido2 examples, located here:
# https://github.com/Yubico/python-fido2/tree/main/examples
# The following applies to any such code:
#
# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Control access to secrets via symmetric encryption and decryption using FIDO2 authenticators.

usage: fidovault.py [-h] [-v VAULT] [-k KEY] [-p PARAMETERS] [-g N] [-m] [-i | -a]
Run 'fidovault.py -h' for help
"""

import argparse
import base64
import configparser
import os
import sys
from getpass import getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction, ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.hid import CtapHidDevice
from fido2.utils import sha256
from fido2.webauthn import UserVerificationRequirement

__version__ = "0.2.0"
ORIGIN = 'example.com'


class CliInteraction(UserInteraction):
    def __init__(self):
        self._pin = None

    def prompt_up(self):
        print_tty("Touch your authenticator now ...")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print_tty("User Verification required")
        return True


def print_tty(message):
    print(message, file=sys.stderr)


def input_boolean(prompt, default):
    """Prompt user for a boolean value and return it"""
    default_str = "y" if default else "n"
    while True:
        inp = input(prompt + f" (y/n - default is {default_str}) ").lower() or default_str
        if inp in ["n", "no", "false", "off", "0"]:
            return False
        if inp in ["y", "yes", "true", "on", "1"]:
            return True
        print_tty("Please enter 'y' or 'n'")


def get_password(confirm):
    """Get a password from the user"""
    while True:
        password = getpass("Enter password: ")
        if not confirm or password == getpass("Confirm password: "):
            return password.encode()
        print_tty("Passwords do not match - please try again")


def find_fido2_device():
    """Return the first device that supports the hmac-secret extension, or None if none are found"""
    client_data_collector = DefaultClientDataCollector(f"https://{ORIGIN}")
    for dev in CtapHidDevice.list_devices():
        print_tty(f"Checking device at {dev.descriptor.path} ...")
        client = Fido2Client(dev, client_data_collector=client_data_collector, user_interaction=CliInteraction(),
                             extensions=[HmacSecretExtension(allow_hmac_secret=True)])
        if "hmac-secret" in client.info.extensions:
            print_tty("Device supports the hmac-secret extension")
            return client
        print_tty("Device does not support the hmac-secret extension")
    print_tty("No device (with hmac-secret support) found")
    return None


def add_key_section(vault, token, kdf_parameters):
    """Add a key section to a FidoVault; return True if successful, False if not"""
    input(
        "Please connect the device you wish to add (and disconnect any others).\nPress <enter> when ready ... ")
    client = find_fido2_device()
    if client is None: return False
    print_tty("Creating FIDO2 credential ... ")
    user_id = os.urandom(8)
    try:
        result = client.make_credential({"challenge": os.urandom(12), "rp": {"id": ORIGIN, "name": "fidovault"},
                                         "user": {"id": user_id, "name": "fidovault_user"},
                                         "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                                         "extensions": {"hmacCreateSecret": True}, }, )
    except ClientError as ce:
        print_tty(ce.cause)
        return False
    if not result.client_extension_results.get("hmacCreateSecret"):
        print_tty("Error: hmacCreateSecret not found")
        return False
    print_tty("FIDO2 credential created")
    credential = result.response.attestation_object.auth_data.credential_data
    hmac_secret_salt = os.urandom(32)
    kdf_salt = os.urandom(16)
    key_name = None
    while key_name is None:
        n = 1
        while True:
            default_key_name = f"Key {n}"
            if default_key_name not in vault.sections(): break
            n += 1
        key_name = input(f"Enter name for this key section: (default is '{default_key_name}')") or default_key_name
        if key_name in vault.sections():
            print_tty(
                f"'{vault}' already contains a key section named '{key_name}' - please choose a different name")
            key_name = None
    user_verification = input_boolean(
        "Perform user verification when using this key section?", True)
    password = input_boolean(
        "Combine password with FIDO2 hmac-secret when using this key section?", True)
    vault[key_name] = {"credential": base64.standard_b64encode(credential.credential_id).decode(),
                       "user-verification": user_verification,
                       "password": password,
                       "hmac-secret-salt": base64.standard_b64encode(hmac_secret_salt).decode(),
                       "phc": f"$argon2id$v=19${kdf_parameters}${base64.standard_b64encode(kdf_salt).decode()}$$"
                       }
    secret = get_hmac_secret(vault[key_name], client)
    if vault[key_name].getboolean("password"):
        secret += get_password(True)
    fernet_key = derive_key(secret, kdf_salt, kdf_parameters)
    if fernet_key is None: return False
    f = Fernet(fernet_key)
    vault[key_name]["token"] = base64.standard_b64encode(f.encrypt(token)).decode()
    print_tty(f"Key section '{key_name}' successfully added")
    return True


def get_hmac_secret(key_section, client):
    """Return hmac-secret from device 'client' using data from 'key_section', or None if unsuccessful"""
    print_tty("Getting hmac-secret ...")
    user_verification = UserVerificationRequirement.REQUIRED if key_section.getboolean(
        "user-verification") else UserVerificationRequirement.DISCOURAGED
    salt = base64.standard_b64decode(key_section["hmac-secret-salt"])
    allow_list = [{"type": "public-key", "id": base64.standard_b64decode(key_section["credential"])}]
    try:
        result = client.get_assertion(
            {"rpId": ORIGIN, "challenge": os.urandom(12), "allowCredentials": allow_list,
             "userVerification": user_verification, "extensions": {
                "hmacGetSecret": {"salt1": salt}}}).get_response(0)
    except ClientError as ce:
        print_tty(ce.cause)
        return None
    return result.client_extension_results["hmacGetSecret"]["output1"].encode()


def derive_key(secret, salt, kdf_parameters):
    """Return a Fernet key derived from 'secret' and 'salt', or None if unsuccessful"""
    kdf_algorithm = 'argon2id'
    kdf_parameters = kdf_parameters.split(',')
    kdf_parameters_dict = {}
    try:
        for kdf_parameter in kdf_parameters:
            k, v = kdf_parameter.split("=")
            kdf_parameters_dict[k] = int(v)
        kdf = Argon2id(salt=salt if salt is not None else os.urandom(16), length=32,
                       iterations=kdf_parameters_dict['t'],
                       lanes=kdf_parameters_dict['p'], memory_cost=kdf_parameters_dict['m'])
    except (ValueError, KeyError):
        print_tty(f"Error: Invalid KDF ({kdf_algorithm}) parameter specification: {kdf_parameters}")
        return None
    try:
        key = kdf.derive(secret)
    except MemoryError:
        print_tty(f"Error: Could not allocate memory for key derivation ({kdf_algorithm})")
        return None
    return base64.urlsafe_b64encode(key)


def write_vault(vault, filename):
    """Write vault to filename"""
    with open(filename, "w") as fp:
        vault.write(fp)


def read_vault(filename):
    """Read vault from filename and return it, or None if unsuccessful"""
    if not os.path.isfile(filename):
        print_tty(f"Error: '{filename}' does not exist")
        return None
    fidovault = configparser.ConfigParser()
    fidovault.read(filename)
    return fidovault


def decrypt_token(vault, key):
    """Return a decrypted FidoVault token, or None if unsuccessful"""
    if key:
        if key in vault.sections():
            allow_list = [{"type": "public-key", "id": base64.standard_b64decode(vault[key]["credential"])}]
        else:
            print_tty(f"Error: Key section '{key}' not found in vault")
            return None
    else:
        allow_list = [{"type": "public-key", "id": base64.standard_b64decode(vault[key_section]["credential"])} for
                      key_section
                      in vault.sections()]
    # ccd = CollectedClientData.create(type="webauthn.get", challenge=websafe_encode(os.urandom(12)), origin=f"https://{ORIGIN}}")
    for dev in CtapHidDevice.list_devices():
        print_tty(f"Checking device at {dev.descriptor.path} ...")
        # pre-flight check: https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-terminology
        client = Ctap2(dev)
        try:
            result = client.get_assertion(ORIGIN, sha256(os.urandom(12)), allow_list, options={"up": False})
        except CtapError as ce:
            if ce.code == 46:
                print_tty("No valid credentials found on device")
                continue
            else:
                print_tty(ce)
                return None
        print_tty("Valid credential found on device")
        credential = result.credential["id"]
        break
    else:
        print_tty("No device with valid credential found - cannot decrypt token")
        return None
    client_data_collector = DefaultClientDataCollector(f"https://{ORIGIN}")
    client = Fido2Client(dev, client_data_collector=client_data_collector, user_interaction=CliInteraction(),
                         extensions=[HmacSecretExtension(allow_hmac_secret=True)])
    for key_name in vault.sections():
        if base64.standard_b64decode(vault[key_name]["credential"]) == credential:
            print_tty(f"Trying to decode token using '{key_name}' key section ...")
            secret = get_hmac_secret(vault[key_name], client)
            if secret is None: return None
            if vault[key_name].getboolean("password"):
                secret += get_password(False)
            phc = vault[key_name]["phc"].split("$")
            fernet_key = derive_key(secret, base64.standard_b64decode(phc[4]), phc[3])
            if fernet_key is None: return None
            f = Fernet(fernet_key)
            try:
                decrypted_token = f.decrypt(base64.standard_b64decode(vault[key_name]["token"]))
            except cryptography.fernet.InvalidToken:
                print_tty("Token decryption failed")
                return None
            print_tty("Token decryption succeeded")
            return decrypted_token
    print_tty("Credential does not match any key section in vault - cannot decrypt token")
    return None


def init_vault(secret, kdf_parameters):
    """Initialize a FidoVault"""
    if secret is None:
        while True:
            secret = getpass("Enter secret: ")
            if getpass("Confirm secret: ") == secret: break
            print_tty("Entries do not match - please try again")
    vault = configparser.ConfigParser()
    return vault if add_key_section(vault, secret.encode(), kdf_parameters) else None


def main():
    # Parse command line arguments

    parser = argparse.ArgumentParser(
        description="Create and manage FidoVaults - control access to secrets via symmetric encryption and decryption using FIDO2 authenticators",
        epilog="If neither '--init' nor '--add' are specified, the program will attempt to output the FidoVault's secret to STDOUT")
    parser.add_argument("-v", "--vault", help="FidoVault filename", default="fidovault.ini")
    parser.add_argument("-k", "--key", help="use (only) this key section of the FidoVault")
    default_kdf_parameters = 't=1,p=4,m=2097152'
    parser.add_argument("-p", "--parameters", help=f"Argon2id parameters (default: '{default_kdf_parameters}'), only used when initializing a FidoVault or adding a key section to one", default=default_kdf_parameters)
    parser.add_argument("-g", "--generate",
                        help="generate FidoVault secret utilizing at least N cryptographically random bits (only used if initializing a FidoVault, otherwise ignored)",
                        type=int, metavar="N")
    parser.add_argument("-m", "--mlockall",
                        help="lock all process memory into RAM (Linux only, and the memlock limit must be high enough to accommodate the memory used by Argon2id)",
                        action="store_true", default=False)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("-i", "--init", action="store_true", help="initialize a FidoVault")
    action.add_argument("-a", "--add", action="store_true", help="add a key section to a FidoVault")
    args = parser.parse_args()

    # Memory security

    if sys.platform == "linux":
        from ctypes import CDLL
        libc = CDLL(None)
        # https://filippo.io/linux-syscall-table/
        PR_CTL, MLOCKALL = 157, 151
        # Try to set process to non-dumpable
        # https://docs.kernel.org/admin-guide/LSM/Yama.html
        # https://lwn.net/Articles/491440/
        # https://stackoverflow.com/questions/37032203/make-syscall-in-python
        # https://github.com/python/cpython/issues/86902
        # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/prctl.h
        PR_SET_DUMPABLE = 4
        result = libc.syscall(PR_CTL, PR_SET_DUMPABLE, 0)
        if result != 0:
            print_tty(f"Failed to set non-dumpable - aborting")
            return 1
        if args.mlockall:

            # Try to lock all future process memory
            # https://eklitzke.org/mlock-and-mlockall
            # https://keepassxc.org/blog/2019-02-21-memory-security/
            # https://groups.google.com/g/golang-nuts/c/Rt3HeMMS_AQ
            # mman.h
            #
            # Argon2 is designed to use a considerable amount of memory, so locking memory will cause memory allocation
            # failure when hashing unless the memlock limit is sufficiently high:
            # https://man7.org/linux/man-pages/man5/limits.conf.5.html
            # https://github.com/pyca/cryptography/issues/14778

            MCL_FUTURE = 2
            result = libc.syscall(MLOCKALL, MCL_FUTURE)
            if result != 0:
                print_tty(f"Failed to lock memory - aborting")
                return 1

    # Perform requested FidoVault action

    if args.init:
        if os.path.isfile(args.vault):
            print_tty(f"FidoVault initialization requested but file '{args.vault}' already exists - aborting")
            return 1
        secret = base64.standard_b64encode(
            os.urandom(args.generate // 8 + (1 if args.generate % 8 else 0))) if args.generate else None
        vault = init_vault(secret, args.parameters)
        if vault is not None:
            write_vault(vault, args.vault)
            print_tty(f"FidoVault '{args.vault}' initialized")
        else:
            print_tty("FidoVault initialization failed")
            return 1
    else:
        vault = read_vault(args.vault)
        if vault is None: return 1
        if args.add:
            if not add_key_section(vault, decrypt_token(vault, None), args.parameters): return 1
            write_vault(vault, args.vault)
            print_tty(f"Updated FidoVault '{args.vault}'")
        else:
            token = decrypt_token(vault, args.key)
            if token is None: return 1
            print(token.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
