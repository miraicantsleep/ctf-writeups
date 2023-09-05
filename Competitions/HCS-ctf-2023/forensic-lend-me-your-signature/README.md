# Lend me your signature
## Description
Aku sedang dikirim gambar waifu oleh temanku, tapi sepertinya gambar tersebut tidak bisa dilihat. Tolong bantulah aku!

**author: abdierryy**

[chall.png](http://34.101.202.34/files/9585fb35fdded47777ddf4bc34c7f477/chall.png?token=eyJ1c2VyX2lkIjo2LCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjo2fQ.ZPc7AQ.cj4fZIcvfI4Ij7i0NVhUyoikAvk)

## Hints
1. Setiap file memiliki hex signature entah itu header atau footer.
   Namun satu hal yang pasti aku memotong bagian bawah gambar tersebut, jangan sampai dia mendapatkannya h3h3
2. chunckkkkkk? sepertinya ada software untuk mengembalikan chuck widthXheight pada gambar. Mungkin kamu harus mengecheck metadata mu itu benar benar krusial

## Approach
Pertama saya melakukan `file chall.png` untuk memastikan bahwa dokumen tersebut benar `png` atau tidak.
```
chall.png: data
```
File format tersebut bukan lah `png` lalu saya baca kembali nama dari soal yang diberikan yaitu `Lend me your signature`. Saya mencari di google tentang file signature `png` dan ternyata header dari file `chall.png` berbeda dengan header file biasanya.

### Header file chall.png
![image](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/0a7a36fe-46c2-4119-8ff7-f4c0d7e0c2ec)

### Header file png biasanya
![image](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/9ff6dbcd-2603-44b3-8129-46235cc15469)

Terlihat bahwa ada perbedaan pada baris pertama nya. Yang seharusnya
```
89 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52
```
menjadi
```
48 41 43 4B  45 44 48 43   53 00 00 0D  49 48 44 52
```

Maka saya ubah header dari file `chall.png` dan file png tersebut dapat dibuka.
![chall](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/759bc5a3-6dda-4bfc-9e14-4c0f1f9784b1)

Tetapi file tersebut masih tidak memunculkan flag yang diminta.

Setelah googling, saya mendapatkan tool dari [repository ini](https://github.com/ryanking13/png-unhide/tree/master) yang dapat mengecek apakah besar ukuran file `png` sesuai dengan header `IHDR`.

Setelah menjalankan file python tersebut dengan command `python checker.py chall.png` saya mendapatkan return command sebagai berikut.
```
[*] Height in the IHDR: 0x17c
[*] Real Height: 0x192
[!!] Wrong size in the IHDR
Automatically fix the IHDR? (Y/N)y
[*] Fixed file saved to chall_fixed.png
```

Saya buka file `chall_fixed.png`, putar foto tersebut dan flag telah ditemukan dan dapat terbaca dengan jelas.
![image](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/f9a0751c-e49a-49a8-a227-80a142b0ba76)

## Flag
```
HCS{N1c3_Th4ts_VerY_Ea5y_R1ghT????}
```
