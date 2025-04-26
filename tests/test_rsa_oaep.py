import unittest
import os
import tempfile

from rsa_oaep.rsa import generate_keypair, save_key_to_file, load_key_from_file
from rsa_oaep.oaep import oaep_encrypt, oaep_decrypt


class TestRSAOAEP(unittest.TestCase):
    """Test cases for RSA-OAEP encryption and decryption"""
    
    def setUp(self):
        """Set up test environment"""
        # Use a smaller key size for faster tests
        self.key_bits = 1024
        # Generate a key pair for testing
        self.public_key, self.private_key, self.p, self.q = generate_keypair(self.key_bits)
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
    
    def tearDown(self):
        """Clean up test environment"""
        self.temp_dir.cleanup()
    
    def test_key_generation(self):
        """Test key generation"""
        n_pub, e = self.public_key
        n_priv, d = self.private_key
        
        # Public and private modulus should be the same
        self.assertEqual(n_pub, n_priv)
        # Public exponent should be 65537
        self.assertEqual(e, 65537)
        # n should equal p*q
        self.assertEqual(n_pub, self.p * self.q)
        # ed ≡ 1 (mod φ(n))
        phi_n = (self.p - 1) * (self.q - 1)
        self.assertEqual((e * d) % phi_n, 1)
    
    def test_key_serialization(self):
        """Test key serialization and deserialization"""
        # Save keys to files
        pub_key_file = os.path.join(self.temp_dir.name, "pub_key.txt")
        priv_key_file = os.path.join(self.temp_dir.name, "priv_key.txt")
        
        save_key_to_file(self.public_key, pub_key_file)
        save_key_to_file((self.private_key[0], self.private_key[1], self.p, self.q), priv_key_file)
        
        # Load keys from files
        loaded_pub_key = load_key_from_file(pub_key_file)
        loaded_priv_key = load_key_from_file(priv_key_file)
        
        # Check if loaded keys match original keys
        self.assertEqual(loaded_pub_key, self.public_key)
        self.assertEqual(loaded_priv_key[0], self.private_key[0])
        self.assertEqual(loaded_priv_key[1], self.private_key[1])
    
    def test_oaep_encryption_decryption(self):
        """Test OAEP encryption and decryption"""
        # Test with different message lengths
        test_messages = [
            b"Hello, world!",
            b"",  # Empty message
            b"A" * 64,  # Longer message
            os.urandom(100)  # Random binary data
        ]
        
        for message in test_messages:
            # Encrypt message
            ciphertext = oaep_encrypt(message, self.public_key)
            
            # Decrypt message
            decrypted = oaep_decrypt(ciphertext, self.private_key)
            
            # Check if decrypted message matches original
            self.assertEqual(decrypted, message)
    
    def test_oaep_with_label(self):
        """Test OAEP encryption and decryption with label"""
        message = b"Secret message with label"
        label = b"This is a label"
        
        # Encrypt message with label
        ciphertext = oaep_encrypt(message, self.public_key, label)
        
        # Decrypt message with correct label
        decrypted = oaep_decrypt(ciphertext, self.private_key, label)
        self.assertEqual(decrypted, message)
        
        # Decrypt message with incorrect label should fail
        wrong_label = b"Wrong label"
        with self.assertRaises(ValueError):
            oaep_decrypt(ciphertext, self.private_key, wrong_label)


if __name__ == "__main__":
    unittest.main()