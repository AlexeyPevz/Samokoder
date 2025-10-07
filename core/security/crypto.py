from cryptography.fernet import Fernet, InvalidToken
from samokoder.core.log import get_logger
import base64
import hashlib
from typing import Union

log = get_logger(__name__)

def _derive_fernet_key(secret: Union[str, bytes]) -> bytes:
    """
    Derive a valid Fernet key from an arbitrary secret string or bytes.

    Fernet requires a 32-byte urlsafe base64-encoded key. We derive it by
    taking SHA-256 of the provided secret and base64-url-encoding the digest.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode()
    else:
        secret_bytes = secret

    digest = hashlib.sha256(secret_bytes).digest()
    return base64.urlsafe_b64encode(digest)


class CryptoService:
    """
    A centralized service for handling encryption and decryption using Fernet.
    """

    def __init__(self, secret_key: Union[str, bytes]):
        """
        Initializes the CryptoService with a secret key.

        :param secret_key: The secret key for encryption and decryption.
                           Must be a 32-byte URL-safe base64-encoded key.
        """
        if not secret_key:
            raise ValueError("A secret key must be provided for CryptoService.")

        # Accept either a pre-generated Fernet key or a raw secret string/bytes
        # and derive a Fernet-compatible key from it.
        try:
            derived_key = _derive_fernet_key(secret_key)
            self.fernet = Fernet(derived_key)
        except (ValueError, TypeError) as e:
            # As a fallback, try to use the provided value as a Fernet key directly
            # to maintain backward compatibility if a proper Fernet key is supplied.
            log.debug(f"Failed to derive key, trying direct Fernet key: {e}")
            try:
                self.fernet = Fernet(secret_key if isinstance(secret_key, bytes) else secret_key.encode())
            except Exception as e:
                log.error(f"Failed to initialize Fernet with provided key: {e}")
                raise ValueError(f"Invalid secret key format: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts a plaintext string.

        :param plaintext: The string to encrypt.
        :return: The encrypted string (ciphertext).
        """
        return self.fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts a ciphertext string.

        :param ciphertext: The string to decrypt.
        :return: The decrypted string (plaintext), or an empty string if decryption fails.
        """
        if not ciphertext:
            return ""
        try:
            return self.fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            log.warning("Failed to decrypt token; it may be invalid or corrupted.")
            return ""
        except Exception as e:
            log.error(f"An unexpected error occurred during decryption: {e}")
            return ""
