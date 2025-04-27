# Source: https://medium.com/@domspaulo/python-implementation-of-sha-256-from-scratch-924f660c5d57

def right_rotate(n, b):
    """Rotasi kanan bilangan 32-bit n sebanyak b bit."""
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

def pad_message(message):
    """Melakukan padding pada pesan.

    1. Tambahkan satu bit '1'
    2. Tambahkan K bit '0', di mana K adalah jumlah terkecil >= 0 sedemikian sehingga
       panjang pesan dalam bit + 1 + K + 64 adalah kelipatan 512
    3. Tambahkan panjang pesan asli sebagai bilangan 64-bit big-endian
    """
    # Konversi menjadi bytes jika input berupa string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Panjang pesan dalam bit
    message_length = len(message) * 8
    
    # Tambahkan bit '1' (diikuti 7 bit '0' untuk melengkapi satu byte)
    message = bytearray(message) + b'\x80'
    
    # Tambahkan bit '0' hingga panjang pesan (dalam bit) mod 512 = 448
    # Ini untuk memastikan total panjang menjadi kelipatan 64 byte (512 bit) setelah tambah 8 byte berikutnya
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Tambahkan panjang pesan asli sebagai bilangan 64-bit big-endian
    message += message_length.to_bytes(8, byteorder='big')
    
    return message

def sha256(message):
    """Implementasi fungsi hash SHA-256."""
    
    # Inisialisasi nilai hash (32-bit pertama dari bagian pecahan akar kuadrat 8 bilangan prima pertama)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    
    # Inisialisasi konstanta ronde (32-bit pertama dari bagian pecahan akar kubik 64 bilangan prima pertama)
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Padding pesan agar panjangnya kelipatan 512 bit
    padded_message = pad_message(message)
    
    # Proses pesan dalam chunk 512-bit (64 byte)
    for chunk_start in range(0, len(padded_message), 64):
        chunk = padded_message[chunk_start:chunk_start + 64]
        
        # Buat schedule array pesan w[0..63] dari word 32-bit
        w = [0] * 64
        
        # Copy 16 kata pertama dari chunk ke schedule array
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big')
        
        # Extend 16 word pertama menjadi 48 word berikutnya w[16..63]
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        # Inisialisasi variabel dengan nilai hash saat ini
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # Loop utama fungsi compression
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Tambahkan hasil chunk yang dikompres ke nilai hash saat ini
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Hasil akhir hash (big-endian)
    digest = b''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += val.to_bytes(4, byteorder='big')
    
    return digest

# Kelas SHA256
class SHA256:
    # Konstruktor: Inisialisasi objek dengan pesan awal
    def __init__(self, message=b''):
        # Konversi menjadi bytes jika input berupa string
        if isinstance(message, str):
            message = message.encode('utf-8')
        self.message = bytearray(message) if message else bytearray()
    
    # Menambahkan data tambahan ke pesan yang sudah ada
    def update(self, message):
        # Konversi menjadi bytes jika input berupa string
        if isinstance(message, str):
            message = message.encode('utf-8')
        self.message += message
        return self
    
    # Menghasilkan hasil hash dalam bentuk bytes
    def digest(self):
        return sha256(self.message)
    
    # Menghasilkan hasil hash dalam bentuk hex
    def hexdigest(self):
        return self.digest().hex()

# Fungsi untuk membuat instance
def new(message=b''):
    return SHA256(message)