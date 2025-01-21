#! /usr/bin/python3

"""
FidoVault: A tool to control access to secrets via symmetric encryption and decryption using hardware FIDO2 keys.
Copyright (c) 2025 Thomas More.
Project home: https://github.com/tmo1/fidovault

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import base64
import configparser
import os
import sys
from getpass import getpass

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fido2.client import Fido2Client, UserInteraction, ClientError
from fido2.ctap import CtapError
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.hid import CtapHidDevice


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print_tty("Touch your authenticator device now ...")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print_tty("User Verification required.")
        return True


def print_tty(message):
    print(message, file=sys.stderr)


def find_fido2_device():
    for dev in CtapHidDevice.list_devices():
        print_tty(f"Checking key at {dev.descriptor.path} ...")
        client = Fido2Client(dev, "https://example.com", user_interaction=CliInteraction(),
                             extensions=[HmacSecretExtension(allow_hmac_secret=True)])
        if "hmac-secret" in client.info.extensions:
            print_tty("Key supports the hmac-secret extension.")
            return client
        print_tty("Key does not support the hmac-secret extension.")


def secret_to_key(secret, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_000_000)
    return base64.urlsafe_b64encode(kdf.derive(secret))


def decrypt_token():
    client = find_fido2_device()
    if client is None:
        print_tty("No FIDO2 key (with hmac-secret support) found.")
        print_tty("Cannot decrypt token.")
        exit(1)
    allow_list = [{"type": "public-key", "id": bytes.fromhex(fido2_key["credential"])} for fido2_key in
                  fido2_keys.values()]
    salts = {"salt" + str(i + 1): bytes.fromhex(fido2_key["hmac-secret-salt"]) for i, fido2_key in
             enumerate(fido2_keys.values())}
    result = client.get_assertion({"rpId": "example.com", "challenge": os.urandom(12), "allowCredentials": allow_list,
                                   "extensions": {"hmacGetSecret": salts}}).get_response(0)
    output1 = result.extension_results["hmacGetSecret"]["output1"].encode()
    secret = add_password(output1, False)
    for key_name, fido2_key in fido2_keys.items():
        print_tty(f"Attempting to decrypt token of '{key_name}' ...")
        try:
            kdf_salt = bytes.fromhex(fido2_key["kdf-salt"])
            f = Fernet(secret_to_key(secret, kdf_salt))
            decrypted_token = f.decrypt(bytes.fromhex(fido2_key["token"]))
        except cryptography.fernet.InvalidToken:
            print_tty("Token decryption failed.")
            pass
        else:
            print_tty("Token decryption succeeded.")
            return decrypted_token
    print_tty("Cannot decrypt token.")
    exit(1)


def add_password(secret, confirm):
    if config["options"].getboolean("password-prompt"):
        password1 = getpass("Enter password (leave blank for none): ")
        if confirm:
            password2 = getpass("Confirm password: ")
            if password1 != password2:
                print_tty("Passwords do not match - aborting.")
                exit(1)
        return secret + password1.encode()
    return secret


def init():
    if os.path.isfile(args.vault):
        print_tty(f"FidoVault initialization requested but file '{args.vault}' already exists - aborting.")
        exit(1)
    secret1 = getpass("Enter secret: ")
    secret2 = getpass("Confirm secret: ")
    if secret1 != secret2:
        print_tty("Entries do not match - aborting.")
        exit(1)
    password_prompt = input("Prompt for passwords to combine with FIDO2 hmac-secrets? (y/n - default is y) ")
    config["options"] = {"password-prompt": "No" if password_prompt in ["No", "no", "N", "n"] else "Yes"}
    add_fido2(secret1.encode())


def add_fido2(token):
    input("Please connect the FIDO2 key you wish to add (and disconnect any others).\nPress <enter> when ready ... ")
    client = find_fido2_device()
    if client is None:
        print_tty("No FIDO2 key (with hmac-secret support) found.")
        exit(1)
    print_tty("Making FIDO2 credential ... ")
    user_id = os.urandom(8)
    try:
        result = client.make_credential({"challenge": os.urandom(12), "rp": {"id": "example.com", "name": "fidovault"},
                                         "user": {"id": user_id, "name": "fidovault_user"},
                                         "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                                         "extensions": {"hmacCreateSecret": True}, }, )
    except ClientError as ce:
        print_tty(ce.cause)
        exit(1)
    if not result.extension_results.get("hmacCreateSecret"):
        print_tty("Error: hmacCreateSecret not found!")
        return
    print_tty("Success.")
    credential = result.attestation_object.auth_data.credential_data
    hmac_secret_salt = os.urandom(32)
    print_tty("Getting hmac-secret ... ")
    result = client.get_assertion({"rpId": "example.com", "challenge": os.urandom(12),
                                   "allowCredentials": [{"type": "public-key", "id": credential.credential_id}],
                                   "extensions": {"hmacGetSecret": {"salt1": hmac_secret_salt}}}).get_response(0)
    print_tty("Success.")
    output1 = result.extension_results["hmacGetSecret"]["output1"].encode()
    secret = add_password(output1, True)
    kdf_salt = os.urandom(16)
    fernet_key = secret_to_key(secret, kdf_salt)
    f = Fernet(fernet_key)
    key_name = input("Enter name for this key: ") or "Key " + str(len(config.sections()) + 1)
    if key_name in config.sections():
        print_tty(f"Key name '{key_name}' already exists - aborting.")
        exit(1)
    config[key_name] = {"credential": credential.credential_id.hex(),
                        "hmac-secret-salt": hmac_secret_salt.hex(),
                        "kdf-salt": kdf_salt.hex(),
                        "token": f.encrypt(token).hex()}
    print_tty("FIDO2 key successfully added.")
    with open(args.vault, "w") as vault:
        config.write(vault)
    print_tty(f"FidoVault '{args.vault}' updated.")


parser = argparse.ArgumentParser(
    description="Create and manage FidoVaults - control access to secrets via symmetric encryption and decryption using hardware FIDO2 keys.",
    epilog="If neither '--init' nor '--add' are specified, the program will attempt to print the FidoVault's secret to STDOUT.")
parser.add_argument("-v", "--vault", help="FidoVault location", default="fidovault.ini")
parser.add_argument("-k", "--key", help="use only this key section of the FidoVault")
action = parser.add_mutually_exclusive_group()
action.add_argument("-i", "--init", action="store_true", help="initialize a FidoVault")
action.add_argument("-a", "--add", action="store_true", help="add a FIDO2 key to a FidoVault")
args = parser.parse_args()

config = configparser.ConfigParser()
if args.init:
    init()
else:
    if not os.path.isfile(args.vault):
        print_tty(f"File '{args.vault}' does not exist - aborting.")
        exit(1)
    config.read(args.vault)
    fido2_keys = {k: v for k, v in config.items() if "token" in v}
    if args.key:
        fido2_keys = {k: v for k, v in config.items() if k == args.key}
        if not fido2_keys:
            print_tty(f"{args.key}' not found in '{args.vault}' - aborting.")
            exit(1)
    if args.add:
        add_fido2(decrypt_token())
    else:
        print(decrypt_token().decode())
