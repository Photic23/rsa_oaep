from .rsa import (
    is_prime, 
    generate_prime, 
    extended_gcd, 
    mod_inverse, 
    generate_keypair, 
    save_key_to_file, 
    load_key_from_file
)
# Import file operations directly - these will be defined in this file
# since we're experiencing import issues

__all__ = [
    'is_prime', 
    'generate_prime', 
    'extended_gcd', 
    'mod_inverse', 
    'generate_keypair', 
    'save_key_to_file', 
    'load_key_from_file',
    'encrypt_file',
    'decrypt_file'
]

# Define the file operations functions directly in the __init__.py
# This is a workaround for the import issues

import os
import struct
from oaep import oaep_encrypt, oaep_decrypt

def encrypt_file(input_file, output_file, key_file):
    """Encrypt a file using RSA-OAEP"""
    public_key = load_key_from_file(key_file)
    n, e = public_key
    
    # Calculate maximum message size in bytes
    block_size = (n.bit_length() // 8) - 2 * 32 - 2  # 32 is the SHA-256 digest size in bytes
    
    # Get the original file extension
    original_extension = os.path.splitext(input_file)[1].lower()
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # First write the original extension (up to 10 bytes, padded with spaces)
        # Format: [length of extension (1 byte)][extension (up to 10 bytes)]
        ext_bytes = original_extension.encode('utf-8')
        ext_length = min(len(ext_bytes), 10)
        f_out.write(bytes([ext_length]))
        f_out.write(ext_bytes[:ext_length])
        # Pad if necessary
        if ext_length < 10:
            f_out.write(b' ' * (10 - ext_length))
        
        # Now encrypt and write the actual file data
        while True:
            block = f_in.read(block_size)
            if not block:
                break
            
            encrypted_block = oaep_encrypt(block, public_key)
            
            # Write the length of the encrypted block followed by the block itself
            f_out.write(struct.pack('>I', len(encrypted_block)))
            f_out.write(encrypted_block)

def decrypt_file(input_file, output_file, key_file):
    """Decrypt a file using RSA-OAEP"""
    try:
        private_key = load_key_from_file(key_file)
        
        with open(input_file, 'rb') as f_in:
            # Read the extension information
            ext_length = f_in.read(1)[0]
            ext_bytes = f_in.read(10)
            original_extension = ext_bytes[:ext_length].decode('utf-8')
            
            # Check if we need to apply the original extension to the output file
            base_output = os.path.splitext(output_file)[0]
            if original_extension and not output_file.lower().endswith(original_extension.lower()):
                output_file = base_output + original_extension
                print(f"Restoring original extension: {original_extension}")
                print(f"Output file renamed to: {output_file}")
            
            with open(output_file, 'wb') as f_out:
                while True:
                    # Read the length of the encrypted block
                    length_bytes = f_in.read(4)
                    if not length_bytes or len(length_bytes) < 4:
                        break
                    
                    block_length = struct.unpack('>I', length_bytes)[0]
                    encrypted_block = f_in.read(block_length)
                    
                    if len(encrypted_block) != block_length:
                        raise ValueError("Incomplete encrypted block read")
                    
                    decrypted_block = oaep_decrypt(encrypted_block, private_key)
                    f_out.write(decrypted_block)
        
        return output_file  # Return the possibly modified output filename
                
    except Exception as e:
        # Delete the output file if decryption fails
        try:
            if os.path.exists(output_file):
                os.remove(output_file)
        except:
            pass
        raise e