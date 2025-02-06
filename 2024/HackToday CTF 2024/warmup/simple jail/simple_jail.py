#!/usr/bin/env python3

FLAG = 'REDACTED'

input = input()

if '_' in input or any([c for c in input if c in __import__('string').whitespace]) or not all(c in __import__('string').printable for c in input):
    exit()

print(eval(input, {'__builtins__': {}}, {'__builtins__': {}}))
