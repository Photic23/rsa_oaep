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
