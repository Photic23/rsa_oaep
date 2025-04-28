import os
import sha256

def mgf1(seed, length):
    """Mask Generation Function based on SHA-256"""
    hlen = 32  # SHA-256 digest size is always 32 bytes
    if length > (2**32) * hlen:
        raise ValueError("Mask too long")
    
    T = b""
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4, byteorder='big')
        hasher = sha256.new()
        hasher.update(seed + C)
        T += hasher.digest()
        counter += 1
    
    return T[:length]

def oaep_encrypt(message, key, label=b""):
    """RSA-OAEP Encryption using SHA-256"""
    n, e = key
    k = (n.bit_length() + 7) // 8  # Length of the RSA modulus in bytes
    
    # SHA-256 digest size is always 32 bytes
    hlen = 32
    mlen = len(message)
    
    # Check if message is too long
    if mlen > k - 2 * hlen - 2:
        raise ValueError("Message too long")
    
    # Calculate label hash using SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Create padded message (DB = lHash || PS || 0x01 || M)
    PS = b'\x00' * (k - mlen - 2 * hlen - 2)
    DB = lhash + PS + b'\x01' + message ##
    
    # Generate random seed
    seed = os.urandom(hlen)
    
    # Calculate mask for DB using seed
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Calculate masked DB
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    
    # Calculate mask for seed using masked DB
    seedMask = mgf1(maskedDB, hlen)
    
    # Calculate masked seed
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
    
    # Construct encoded message (EM = 0x00 || maskedSeed || maskedDB)
    EM = b'\x00' + maskedSeed + maskedDB
    
    # Convert to integer and apply RSA encryption
    m_int = int.from_bytes(EM, byteorder='big')
    c_int = pow(m_int, e, n)
    
    # Convert ciphertext to bytes
    ciphertext = c_int.to_bytes(k, byteorder='big')
    
    return ciphertext

def oaep_decrypt(ciphertext, key, label=b""):
    """RSA-OAEP Decryption using SHA-256"""
    n, d = key
    k = (n.bit_length() + 7) // 8  # Length of the RSA modulus in bytes
    
    # SHA-256 digest size is always 32 bytes
    hlen = 32
    
    # Check ciphertext length
    if len(ciphertext) != k:
        raise ValueError("Decryption error: Invalid ciphertext length")
    
    # Convert ciphertext to integer and apply RSA decryption
    c_int = int.from_bytes(ciphertext, byteorder='big')
    m_int = pow(c_int, d, n)
    
    # Convert back to bytes with proper padding
    EM = m_int.to_bytes(k, byteorder='big')
    
    # Separate components
    first_byte = EM[0]
    maskedSeed = EM[1:1+hlen]
    maskedDB = EM[1+hlen:]
    
    # Verify first byte
    if first_byte != 0:
        raise ValueError("Decryption error: Invalid padding")
    
    # Calculate seed mask
    seedMask = mgf1(maskedDB, hlen)
    
    # Recover seed
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    
    # Calculate DB mask
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Recover DB
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    
    # Calculate label hash using SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Verify label hash
    if not DB.startswith(lhash):
        raise ValueError("Decryption error: Invalid label hash")
    
    # Find message boundary
    i = hlen
    while i < len(DB):
        if DB[i] == 0:
            i += 1
        elif DB[i] == 1:
            i += 1
            break
        else:
            raise ValueError("Decryption error: Invalid padding")
    
    # Extract message
    message = DB[i:]
    
    return message