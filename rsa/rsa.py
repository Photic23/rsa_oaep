import random

# RSA Key Generation
def is_prime(n, k=40):
    """Miller-Rabin primality test"""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    while True:
        # Generate a random odd number with specified bit length
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Set the highest and lowest bit
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(e, phi):
    """Find modular multiplicative inverse"""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return (x % phi + phi) % phi

def generate_keypair(bits=2048):
    """Generate RSA key pair"""
    # Generate two prime numbers p and q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    n = p * q  # Modulus
    phi = (p - 1) * (q - 1)  # Euler's totient function
    
    # Choose public exponent e
    e = 65537  # Common value for e
    
    # Calculate private exponent d
    d = mod_inverse(e, phi)
    
    # Public key: (n, e), Private key: (n, d)
    return (n, e), (n, d)

# Key Serialization
def save_key_to_file(key, filename):
    """Save RSA key to file in hexadecimal format"""
    # Regular key (n, e or d)
    n, x = key
    key_str = f"{n:x}\n{x:x}"
    
    with open(filename, 'w') as f:
        f.write(key_str)

def load_key_from_file(filename):
    """Load RSA key from file"""
    with open(filename, 'r') as f:
        lines = f.read().strip().split('\n')
    
    if len(lines) == 2:
        # Regular key (n, e or d)
        n = int(lines[0], 16)
        x = int(lines[1], 16)
        return (n, x)
    else:
        raise ValueError("Invalid key file format")