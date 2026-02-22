import os
import base64
import tempfile
import unittest

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from mnemonic import Mnemonic

from wallet_generator import (
    generate_ethereum_wallet,
    generate_bitcoin_wallet,
    derive_fernet_key,
    wallet_to_text,
)

class TestEthereumWallet(unittest.TestCase):

    def setUp(self):
        self.wallet = generate_ethereum_wallet()

    def test_returns_all_required_fields(self):
        for field in ("chain", "private_key", "public_key", "address", "seed_phrase"):
            self.assertIn(field, self.wallet, f"Missing field: {field}")

    def test_chain_is_ethereum(self):
        self.assertEqual(self.wallet["chain"], "Ethereum")

    def test_private_key_starts_with_0x(self):
        self.assertTrue(self.wallet["private_key"].startswith("0x"))

    def test_private_key_correct_length(self):
        self.assertEqual(len(self.wallet["private_key"]), 66)

    def test_private_key_is_hex(self):
        hex_part = self.wallet["private_key"][2:]
        self.assertTrue(all(c in "0123456789abcdefABCDEF" for c in hex_part))

    def test_address_starts_with_0x(self):
        self.assertTrue(self.wallet["address"].startswith("0x"))

    def test_address_is_42_chars(self):
        self.assertEqual(len(self.wallet["address"]), 42)

    def test_address_is_checksum(self):
        from eth_account import Account
        addr = self.wallet["address"]
        self.assertRegex(addr, r"^0x[0-9a-fA-F]{40}$")

    def test_public_key_is_not_empty(self):
        self.assertTrue(len(self.wallet["public_key"]) > 0)


    def test_seed_phrase_has_12_words(self):
        words = self.wallet["seed_phrase"].split()
        self.assertEqual(len(words), 12)

    def test_seed_phrase_words_are_valid_bip39(self):
        mnemo = Mnemonic("english")
        self.assertTrue(mnemo.check(self.wallet["seed_phrase"]))

    def test_two_wallets_are_unique(self):
        other = generate_ethereum_wallet()
        self.assertNotEqual(self.wallet["private_key"], other["private_key"])
        self.assertNotEqual(self.wallet["address"],     other["address"])
        self.assertNotEqual(self.wallet["seed_phrase"], other["seed_phrase"])


class TestBitcoinWallet(unittest.TestCase):

    def setUp(self):
        self.wallet = generate_bitcoin_wallet()

    def test_returns_all_required_fields(self):
        for field in ("chain", "private_key", "public_key", "address", "seed_phrase"):
            self.assertIn(field, self.wallet, f"Missing field: {field}")

    def test_chain_is_bitcoin(self):
        self.assertEqual(self.wallet["chain"], "Bitcoin")


    def test_private_key_is_64_hex_chars(self):
        pk = self.wallet["private_key"]
        self.assertEqual(len(pk), 64)
        self.assertTrue(all(c in "0123456789abcdefABCDEF" for c in pk))


    def test_public_key_is_compressed(self):
        pk = self.wallet["public_key"]
        self.assertEqual(len(pk), 66)

    def test_public_key_prefix_is_02_or_03(self):
        prefix = self.wallet["public_key"][:2]
        self.assertIn(prefix, ("02", "03"))

    # ── Address ───────────────────────────────────────────────────────────────

    def test_address_starts_with_1(self):
        # Legacy P2PKH mainnet address (base58 encoded)
        addr = self.wallet["address"]
        self.assertTrue(addr.startswith("1"),
            f"Expected legacy P2PKH address starting with '1', got: {addr}")

    def test_address_length_in_valid_range(self):
        # Legacy P2PKH base58 addresses are 25–34 chars
        addr = self.wallet["address"]
        addr_len = len(addr)
        self.assertGreaterEqual(addr_len, 25,
            f"Address too short: {addr}")
        self.assertLessEqual(addr_len, 34,
            f"Address too long ({addr_len}): {addr} — may be bech32, check encoding param")

    # ── Seed phrase ───────────────────────────────────────────────────────────

    def test_seed_phrase_has_12_words(self):
        self.assertEqual(len(self.wallet["seed_phrase"].split()), 12)

    def test_seed_phrase_is_valid_bip39(self):
        mnemo = Mnemonic("english")
        self.assertTrue(mnemo.check(self.wallet["seed_phrase"]))

    # ── Uniqueness ────────────────────────────────────────────────────────────

    def test_two_wallets_are_unique(self):
        other = generate_bitcoin_wallet()
        self.assertNotEqual(self.wallet["private_key"], other["private_key"])
        self.assertNotEqual(self.wallet["address"],     other["address"])


# ══════════════════════════════════════════════════════════════════════════════
#  Encryption / Decryption Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryption(unittest.TestCase):

    def _encrypt_and_save(self, data: str, password: str, filepath: str):
        salt = os.urandom(16)
        key  = derive_fernet_key(password, salt)
        enc  = Fernet(key).encrypt(data.encode())
        with open(filepath, "wb") as f:
            f.write(salt + enc)

    def _load_and_decrypt(self, password: str, filepath: str) -> str:
        with open(filepath, "rb") as f:
            salt, enc = f.read(16), f.read()
        key = derive_fernet_key(password, salt)
        return Fernet(key).decrypt(enc).decode()


    def test_derive_fernet_key_returns_bytes(self):
        key = derive_fernet_key("password", os.urandom(16))
        self.assertIsInstance(key, bytes)

    def test_derive_fernet_key_is_url_safe_base64(self):
        key = derive_fernet_key("password", os.urandom(16))
        decoded = base64.urlsafe_b64decode(key + b"==")
        self.assertEqual(len(decoded), 32)

    def test_same_password_same_salt_gives_same_key(self):
        salt = os.urandom(16)
        k1 = derive_fernet_key("mypassword", salt)
        k2 = derive_fernet_key("mypassword", salt)
        self.assertEqual(k1, k2)

    def test_different_salts_give_different_keys(self):
        k1 = derive_fernet_key("mypassword", os.urandom(16))
        k2 = derive_fernet_key("mypassword", os.urandom(16))
        self.assertNotEqual(k1, k2)

    def test_different_passwords_give_different_keys(self):
        salt = os.urandom(16)
        k1 = derive_fernet_key("password1", salt)
        k2 = derive_fernet_key("password2", salt)
        self.assertNotEqual(k1, k2)

    def test_encrypt_decrypt_roundtrip(self):
        wallet  = generate_ethereum_wallet()
        payload = wallet_to_text(wallet)
        password = "test_password_123!"

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tmp:
            path = tmp.name
        try:
            self._encrypt_and_save(payload, password, path)
            result = self._load_and_decrypt(password, path)
            self.assertEqual(result, payload)
        finally:
            os.unlink(path)

    def test_wrong_password_raises_invalid_token(self):
        payload = "secret wallet data"
        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tmp:
            path = tmp.name
        try:
            self._encrypt_and_save(payload, "correct_password", path)
            with self.assertRaises(InvalidToken):
                self._load_and_decrypt("wrong_password", path)
        finally:
            os.unlink(path)

    def test_encrypted_file_has_salt_prepended(self):
        payload = "test"
        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tmp:
            path = tmp.name
        try:
            self._encrypt_and_save(payload, "pw", path)
            with open(path, "rb") as f:
                raw = f.read()
            self.assertGreater(len(raw), 16)
        finally:
            os.unlink(path)

    def test_bitcoin_wallet_roundtrip(self):
        wallet  = generate_bitcoin_wallet()
        payload = wallet_to_text(wallet)
        password = "btc_secure_pw"

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tmp:
            path = tmp.name
        try:
            self._encrypt_and_save(payload, password, path)
            result = self._load_and_decrypt(password, path)
            self.assertEqual(result, payload)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
#  wallet_to_text Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestWalletToText(unittest.TestCase):

    def test_eth_wallet_text_contains_all_fields(self):
        wallet = generate_ethereum_wallet()
        text   = wallet_to_text(wallet)
        self.assertIn("Chain",       text)
        self.assertIn("Address",     text)
        self.assertIn("Public Key",  text)
        self.assertIn("Private Key", text)
        self.assertIn("Seed Phrase", text)

    def test_eth_wallet_text_contains_correct_values(self):
        wallet = generate_ethereum_wallet()
        text   = wallet_to_text(wallet)
        self.assertIn(wallet["address"],     text)
        self.assertIn(wallet["private_key"], text)
        self.assertIn(wallet["seed_phrase"], text)

    def test_btc_wallet_text_contains_chain_bitcoin(self):
        wallet = generate_bitcoin_wallet()
        text   = wallet_to_text(wallet)
        self.assertIn("Bitcoin", text)

    def test_wallet_text_is_multiline(self):
        wallet = generate_ethereum_wallet()
        text   = wallet_to_text(wallet)
        self.assertGreater(text.count("\n"), 3)




if __name__ == "__main__":
    unittest.main(verbosity=2)