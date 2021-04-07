"""Cryptographic operations.

Usage example:

    # Compute the hash over the content of a file
    file_hash = HashingEngine.compute_content_sha256("/etc/passwd")

    # Get a random hash
    random_hash = HashingEngine.generate_random_hash()
"""
import binascii
import os

from modules.configuration.parameters import Packages
from Crypto.Hash import SHA256  # nosec

RECOMMENDED_MIN_HASH_LENGTH = Packages.Utils.Crypto.RECOMMENDED_MIN_HASH_LENGTH


class HashingEngine:
    """Class containing hashing operations."""

    @staticmethod
    def compute_content_sha256(path: str) -> str:
        """Computes the SHA256 hash over a file content.

        Args:
            path (str): Path of the file

        Returns:
            str: Hexadecimal representation of the hash
        """
        with open(path, "rb") as file:
            content = file.read()

        file_hash = SHA256.new(data=content).hexdigest()

        return file_hash

    @staticmethod
    def generate_random_hash(length: int = RECOMMENDED_MIN_HASH_LENGTH) -> str:
        """Generates a random hash.

        Args:
            length (int): Desired length of the hash, in bytes. Defaults to
                RECOMMENDED_MIN_HASH_LENGTH, which contains the recommended
                minimum length of a hash considered secure in the platform
                context

        Returns:
            str: Random hash in the hexadecimal representation
        """
        return binascii.hexlify(os.urandom(length)).decode("utf-8")
