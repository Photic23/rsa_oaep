import os
import sha256

def mgf1(seed, length):
    """Fungsi Mask Generation Function berbasis SHA-256
    Source: https://en.wikipedia.org/wiki/Mask_generation_function"""
    hlen = 32  # Digest size untuk SHA-256 
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
    """Fungsi enkripsi RSA-OAEP menggunakan SHA-256
    Source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding#Encoding"""
    n, e = key
    k = (n.bit_length() + 7) // 8  # Panjang modulus RSA dalam bytes

    hlen = 32 # Digest size untuk SHA-256 
    mlen = len(message)
    
    # Periksa panjang pesan
    if mlen > k - 2 * hlen - 2:
        raise ValueError("Message too long")
    
    # Hash label menggunakan SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Buat pesan yang dipadding (DB = lHash || PS || 0x01 || M)
    PS = b'\x00' * (k - mlen - 2 * hlen - 2)
    DB = lhash + PS + b'\x01' + message ##
    
    # Generate seed random
    seed = os.urandom(hlen)
    
    # Menggunakan mgf1 untuk generate mask db
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Mask DB dengan dbMask (maskedDB = DB XOR dbMask)
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    
    # Menggunakan mgf1 untuk generate mask seed
    seedMask = mgf1(maskedDB, hlen)
    
    # Mask seed dengan dbMask (maskedSeed = seed XOR seedMask)
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
    
    # Membuat encoded message (EM = 0x00 || maskedSeed || maskedDB)
    EM = b'\x00' + maskedSeed + maskedDB
    
    # Ubah ke int dan lakukan enkripsi RSA
    m_int = int.from_bytes(EM, byteorder='big')
    c_int = pow(m_int, e, n)
    
    # Ubah ciphertext ke bytes
    ciphertext = c_int.to_bytes(k, byteorder='big')
    
    return ciphertext

def oaep_decrypt(ciphertext, key, label=b""):
    """RSA-OAEP Decryption using SHA-256
    Source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding#Decoding"""
    n, d = key
    k = (n.bit_length() + 7) // 8  # Panjang modulus RSA dalam bytes
    
    hlen = 32 # Digest size untuk SHA-256 
    
    # Periksa panjang ciphertext
    if len(ciphertext) != k:
        raise ValueError("Decryption error: Invalid ciphertext length")
    
    # Ubah ke int dan lakukan dekripsi RSA
    c_int = int.from_bytes(ciphertext, byteorder='big')
    m_int = pow(c_int, d, n)
    
    # Ubah kembali ke bytes
    EM = m_int.to_bytes(k, byteorder='big')
    
    # Memisahkan komponen
    first_byte = EM[0]
    maskedSeed = EM[1:1+hlen]
    maskedDB = EM[1+hlen:]
    
    # Periksa byte pertama
    if first_byte != 0:
        raise ValueError("Decryption error: Invalid padding")
        
    # Menggunakan mgf1 untuk generate mask seed
    seedMask = mgf1(maskedDB, hlen)
    
    # Recover seed (seed = maskedSeed XOR seedMask)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    
    # Menggunakan mgf1 untuk generate mask db
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Recover DB (DB = maskedDB XOR dbMask)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    
    # Hash label menggunakan SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Periksa label hash
    if not DB.startswith(lhash):
        raise ValueError("Decryption error: Invalid label hash")
    
    # Cari batasan pesan
    i = hlen
    while i < len(DB):
        if DB[i] == 0:
            i += 1
        elif DB[i] == 1:
            i += 1
            break
        else:
            raise ValueError("Decryption error: Invalid padding")
    
    # Ekstrak pesan setelah byte 0x01
    message = DB[i:]
    
    return message