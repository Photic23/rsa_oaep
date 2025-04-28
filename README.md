# Tugas Pemrograman RSA-OAEP

## Anggota Kelompok 8
* Naufal Mahdy Hanif - 2206082335
* Mika Ahmad Al Husseini - 2206826476
* Henry Soedibjo - 2206827762

# Cara Pakai App-nya

## Menjalankan app
* Clone github repository atau open source code langsung
* Pastikan berada di level directory yang sama dengan main.py
* Jalankan main.py menggunakan 'python main.py'

## Generate Keypair
* Dari menu utama app, masuk ke tab 'Key Generation'
* Pilih directory yang ingin dijadikan tempat dari keypair
* Masukkan prefix dari keypair, setelah prefix program akan memberikan keterangan mana yang private dan public key
* Tekan generate dan keypair akan tersimpan di directory yang diinginkan
* Keypair disimpan dalam bentuk hexadecimal, baris pertama 'n' baris kedua e

## Encrypt File
* Pastikan sudah memiliki public key dari keypair yang akan digunakan
* Dari menu utama app, masuk ke tab 'Encrypt'
* Pilih file yang ingin diencrypt pada 'Input File'
* Pilih public key yang akan digunakan pada 'Public Key File' 
* Pilih directory yang akan digunakan untuk menyimpan hasil enkripsi pada 'Output File', jangan lupa untuk memberikan nama file hasil enkripsi juga
* Tekan tombol 'Encrypt' dan file akan terenkripsi pada direktori yang dituju dengan format .enc

## Decrypt File
* Pastikan sudah memiliki private key dari keypair yang telah digunakan untuk encrypt file yang ingin didecrypt
* Dari menu utama app, masuk ke tab 'Decrypt'
* Pilih file yang ingin didecrypt pada 'Input File'
* Pilih private key yang akan digunakan pada 'Private Key File' 
* Pilih directory yang akan digunakan untuk menyimpan hasil dekripsi pada 'Output File', jangan lupa untuk memberikan nama file hasil dekripsi juga
* Tekan tombol 'Decrypt' dan file akan terdekripsi pada direktori yang dituju


## Logic Program

# Generate Keypair
* Bakal nyari prime number 2048 bits sampai ketemu di 'generate_prime'
* Generate p dan q, each 1024 bits, terus dapetin modulus n 2048 bits dari p dan q
* Dapetin phi dari p dan q lalu e-nya 65537 (2^16 + 1)
* Dapetin d dari mod inverse e terhadap phi
* Dapetin public key (n, e) dan private key (n, d)
* Save key yang didapetin dengan basis satu variabel per line

# Encrypt
* Retrieve n sama e dari public key file
* Ukuran blok didapatkan dari (n.bit_length() // 8) - 2 * 32 - 2, yang berarti untuk 2048 bits atau 256 bytes, maka size blok adalah 190 bytes
* Format dari file ditulis dulu di 10 bytes awal, kalau kurang akan dipadding

* Untuk tiap block data:
* Dilanjut dengan pembuatan data block yang diawali label hash (default kosong), padding, separator \x01, dan block pesan
* Dilanjut generate mask db menggunakan mfg1 dengna seed random
* Dilanjut xor data block dengan mask db
* Dilanjut pembuatan mask seed menggunakan data block yang sudah dimask
* Dilanjut lagi dengan xor seed dengan mask seed
* Kemudian didapatkan encoded message dari seed dan data block yang sudah dimasked
* Lalu diubah encoded message menjadi integer dan dilakukan enkripsi rsa
* Kemudian dikembalikan lagi menjadi bytes dan di-append ke encrypted file

# Decrypt