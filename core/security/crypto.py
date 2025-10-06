from cryptography.fernet import Fernet, InvalidToken
from samokoder.core.log import get_logger

log = get_logger(__name__)

class CryptoService:
    """
    A centralized service for handling encryption and decryption using Fernet.
    """

    def __init__(self, secret_key: bytes):
        """
        Initializes the CryptoService with a secret key.

        :param secret_key: The secret key for encryption and decryption.
                           Must be a 32-byte URL-safe base64-encoded key.
        """
        if not secret_key:
            raise ValueError("A secret key must be provided for CryptoService.")
        self.fernet = Fernet(secret_key)

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
