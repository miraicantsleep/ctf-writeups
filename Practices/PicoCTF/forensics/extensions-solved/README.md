# extensions

## Description
This is a really weird text file [TXT](https://jupiter.challenges.picoctf.org/static/e7e5d188621ee705ceeb0452525412ef/flag.txt)? Can you find the flag?

## Hints
1. How do operating systems know what kind of file it is? (It's not just the ending!
2. Make sure to submit the flag as picoCTF{XXXXX}

## Approach
First i downloaded the file with `https://jupiter.challenges.picoctf.org/static/e7e5d188621ee705ceeb0452525412ef/flag.txt`

For forensics problems, i always have to make sure that the extensions of the file is the actual format of the file. In this case, the file extensions DOES NOT MATCH the actual format of the file.

I run `file flag.txt` and it returns
```
flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
```
This is a PNG file hidden as a txt file.

So to solve it, i just changed the file extension type and hence, the flag.

## Flag
```
picoCTF{now_you_know_about_extensions}
```

<img width="849" alt="flag" src="https://github.com/miraicantsleep/ctf-writeups/assets/29684003/76aa3bc9-5974-4e27-8046-de9a1b414e81">

