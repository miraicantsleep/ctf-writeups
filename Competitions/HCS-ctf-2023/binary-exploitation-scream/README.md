# Scream
## Description
Bisa ga sih ga usah teriak teriak, ribut tau !!!!!
sebagai mahasiswa aku cuma pingin tidurku tidak diganggu 😞

**author: HyggeHalcyon**

`nc 34.101.202.34 10005`

## Approach
Disini kita diberikan sebuah program C yang bernama `scream.c` dan sebuah executable yang dinamakan `chall`

Saya mencoba untuk menganalisa isi dari program `scream.c` tersebut dan menemukan bahwa fungsi input `gets` telah diberikan. Fungsi input `gets` sangat rentan terhadap buffer overflow.

Maka dari itu saya mencoba untuk spam huruf `A` sebanyak-banyaknya 

![image](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/41100374-8101-47b2-bb42-ff47f7b05049)

Dan sesuai ekspektasi, program tersebut mengalami buffer overflow dan memberikan flag.

## Flag
```
HCS{Buff3r_0v3rfl0wwwwww}
```

## Alternative Approach
Dari soal sudah diberikan clue yang sangat jelas bahwa kita hanya harus 'berteriak' dan program akan memberikan flag nya.
