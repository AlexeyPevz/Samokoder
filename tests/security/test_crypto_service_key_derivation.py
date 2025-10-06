"""Тест: деривация ключа Fernet из строкового секрета работает корректно."""
from samokoder.core.security.crypto import CryptoService


def test_crypto_service_derives_fernet_key_from_string_secret():
    secret = "my-very-strong-app-secret-key-which-is-not-base64"
    crypto = CryptoService(secret)

    plaintext = "hello-world"
    ciphertext = crypto.encrypt(plaintext)
    assert isinstance(ciphertext, str)

    decoded = crypto.decrypt(ciphertext)
    assert decoded == plaintext
