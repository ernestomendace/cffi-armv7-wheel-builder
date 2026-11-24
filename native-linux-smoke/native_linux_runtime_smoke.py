#!/usr/bin/env python3
"""Native Linux x86-64 import, crypto and offline NTLM/SMB protocol smoke."""
import importlib
import importlib.metadata
import json
import os
import pathlib
import platform
import struct
import sys
import sysconfig


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def main():
    require(sys.version_info[:2] == (3, 9), "PYTHON_VERSION_MISMATCH")
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "NATIVE_LINUX_ARCHITECTURE_MISMATCH")
    require(struct.calcsize("P") == 8, "POINTER_WIDTH_MISMATCH")
    soabi = sysconfig.get_config_var("SOABI")
    require(isinstance(soabi, str) and soabi.startswith("cpython-39-x86_64"), "SOABI_MISMATCH")
    site = pathlib.Path(os.environ["MCP_NATIVE_SITE"]).resolve(strict=True)
    distributions = {
        "cffi":("cffi", "cffi", "2.0.0"),
        "cryptography":("cryptography", "cryptography", "50.0.2"),
        "pycparser":("pycparser", "pycparser", "2.23"),
        "pyspnego":("spnego", "pyspnego", "0.12.4"),
        "smbprotocol":("smbprotocol", "smbprotocol", "1.12.0"),
        "typing-extensions":("typing_extensions", "typing-extensions", "4.15.0"),
    }
    imported = {}
    for module_name, (import_name, distribution, version) in distributions.items():
        module = importlib.import_module(import_name)
        actual = importlib.metadata.version(distribution)
        require(actual == version, "PACKAGE_VERSION_MISMATCH_" + distribution)
        path = pathlib.Path(module.__file__).resolve()
        require(os.path.commonpath((str(site), str(path))) == str(site),
                "PACKAGE_OUTSIDE_PRIVATE_TARGET_" + distribution)
        imported[distribution] = actual
    backend = importlib.import_module("_cffi_backend")
    require(os.path.commonpath((str(site), str(pathlib.Path(backend.__file__).resolve()))) == str(site),
            "CFFI_BACKEND_OUTSIDE_PRIVATE_TARGET")

    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import hashes
    from spnego._ntlm_raw.crypto import RC4Handle

    key = bytes.fromhex("0102030405")
    expected_rc4 = bytes.fromhex("b2396305f03dc027ccc3524a0a1118a8")
    zeros = bytes(16)
    require(Cipher(ARC4(key), mode=None).encryptor().update(zeros) == expected_rc4,
            "CRYPTOGRAPHY_ARC4_VECTOR_FAIL")
    require(RC4Handle(key).update(zeros) == expected_rc4, "PYSPNEGO_RC4_VECTOR_FAIL")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"synthetic OAuth RS256 native Linux smoke"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    private_key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

    # Exercise SESSION_SETUP using actual smbprotocol/pyspnego, with an in-memory
    # NTLM peer and a throwaway local password file; no socket or SMB server.
    import spnego
    from smbprotocol.exceptions import MoreProcessingRequired
    from smbprotocol.session import SMB2SessionSetupResponse, Session

    class Value:
        def __init__(self, value): self.value = value
        def get_value(self): return self.value

    class Request:
        def __init__(self, message_id): self.message = {"message_id": Value(message_id)}

    class FixturePeer:
        server_name = "fixture.invalid"
        gss_negotiate_token = None
        client_security_mode = 1
        dialect = 0x0210
        supports_encryption = True
        require_signing = False
        def __init__(self):
            self.preauth_integrity_session_hash_value = {}
            self.preauth_integrity_hash_value = []
            self.session_table = {}
            self.context = spnego.server(protocol="ntlm")
            self.request_id = 0
            self.token = None
            self.tokens_seen = 0
        def send(self, request, **_kwargs):
            self.request_id += 1
            self.token = request["buffer"].get_value()
            self.tokens_seen += 1
            self.preauth_integrity_session_hash_value[self.request_id] = []
            return Request(self.request_id)
        def receive(self, _request):
            token = self.context.step(self.token)
            body = SMB2SessionSetupResponse()
            body["buffer"] = token or b""
            body["session_flags"] = 0
            response = {"session_id":Value(1), "data":Value(body.pack()),
                        "status":Value(0 if self.context.complete else 0xC0000016)}
            if not self.context.complete:
                raise MoreProcessingRequired(response)
            return response
        def verify_signature(self, *_args, **_kwargs): return None

    credential_file = pathlib.Path(os.environ["MCP_NATIVE_FIXTURE_CREDS"])
    require(credential_file.is_file(), "NTLM_FIXTURE_MISSING")
    previous = os.environ.get("NTLM_USER_FILE")
    os.environ["NTLM_USER_FILE"] = str(credential_file)
    try:
        peer = FixturePeer()
        session = Session(peer, "fixture-user", "fixture-password",
                          require_encryption=False, auth_protocol="ntlm")
        session.connect()
        require(session._connected and session.session_id == 1 and len(session.session_key) == 16
                and peer.tokens_seen == 2 and peer.context.complete,
                "NTLM_SYNTHETIC_HANDSHAKE_FAILED")
    finally:
        if previous is None:
            os.environ.pop("NTLM_USER_FILE", None)
        else:
            os.environ["NTLM_USER_FILE"] = previous
    print(json.dumps({"status":"PASS", "python":sys.version.split()[0],
        "platform":platform.platform(), "machine":platform.machine(), "soabi":soabi,
        "imports":imported, "cffi_backend":"PASS", "arc4_known_answer":"PASS",
        "oauth_rs256_sign_verify":"PASS", "ntlm_session_setup_fixture":"PASS",
        "network":"disabled by container network namespace", "credentials":"synthetic only"},
        sort_keys=True))


if __name__ == "__main__":
    main()
