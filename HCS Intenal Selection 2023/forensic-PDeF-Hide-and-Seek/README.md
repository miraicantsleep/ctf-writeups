# PDeF Hide and Seek
## Description
Temanku suka banget bermain petak umpat, tapi aku yakin kamu bisa menemukannya

**author: abdierryy**

[Hide_and_seek.pdf](http://34.101.202.34/files/7e0ad05bc1dcde161068cb58dd658073/Hide_and_seek.pdf?token=eyJ1c2VyX2lkIjo2LCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjo1fQ.ZPc4cw.V4hwbyj9glMLWOjtOnUQ-VcPISg)

## Approach
Selalu jalankan command `file Hide_and_seek.pdf` untuk mengecek kebenaran file format tersebut.
```
Hide_and_seek.pdf: PDF document, version 1.7, 1 pages
```
File format sudah benar. Jika kita buka lebih lanjut, tidak terlihat adanya teks di dalam pdf tersebut, lalu saya melakukan `Ctrl+A` untuk mengecek apakah ada teks yang tersembunyi di pdf tersebut dan benar saja. ada teks transparan yang tersembunyi oleh gambar.
![image](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/d300a737-1c27-42ab-9f3f-e313ac609a39)

```
Hide and seek's origins trace back to ancient times, as people mimicked hunting in play. Medieval Europe saw early
versions. Indigenous cultures and Native American tribes embraced similar activities. By the 16th-18th centuries, regional
variations thrived. Modernization led to standardized rules and its English name. The 19th-20th centuries brought
widespread popularity as a childhood game, inspiring adaptations like "sardines" and "kick the can." Hide and seek's cultural
influence extended to literature and media. Despite technological advances, it remains relevant, nurturing social skills and
creativity. This enduring, universal game continues to connect generations through the joy of pursuit and discovery, but the
flag is HCS{G00d_St4rt_W1th_PDF_0x13458}
```

## Flag
```
HCS{G00d_St4rt_W1th_PDF_0x13458}
```
