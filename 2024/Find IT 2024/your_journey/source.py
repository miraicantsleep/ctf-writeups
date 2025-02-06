#!/usr/bin/python3
from hidden import *

while True:
    ans = input(
        "\nExplore and discover the profound essence of this journey, as you seek out the genuine truth that lies within\n$ "
    ).strip()

    if any(char in ans for char in block):
        print(
            f"\n{ascii1}\nYour journey is blocked by something; perhaps this is not the time for the truth to appear.\n-FIND IT 2024\n"
        )
    else:
        try:
            eval(ans + "()")
            print("Is this the true ending???\n")
        except sussy:
            print(f"\n{ascii2}\nOh no! Maybe you forgor something.\nAmogus!!\n")
        except anothersussy:
            print(
                f"\n{ascii2}\nOh no! Maybe take a step back to see the whole journey again.\nAmogus!!\n"
            )
        except:
            print(f"\n{ascii2}\nOh no! Maybe this is not the correct path.\nAmogus!!\n")
