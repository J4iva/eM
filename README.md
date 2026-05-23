# eM
Educational RSA-like encrypted messaging demo in C++ using block-based encryption.

## Overview
This project implements a simplified RSA workflow that:
- Packs plaintext into fixed-size byte blocks
- Generates public/private keys from two primes
- Encrypts each block with modular exponentiation
- Decrypts blocks back into the original message (including padding)

## Project Structure
- `eM.cpp` — single-file implementation and demo `main()`

## Build
```bash
g++ -std=c++11 -o em eM.cpp
```

## Run
```bash
./em
```

## Configuration
You can tweak the demo by editing `main()` in `eM.cpp`:
- `p` and `q` should be primes; `n = p * q` must be larger than the max block value  
  (for `BLOCK_SIZE = 2`, this means `n > 65535`).
- `BLOCK_SIZE` controls how many bytes are packed per block.
- `MAX_CAPACIDAD` caps the number of encrypted blocks.
- `mensaje` sets the sample plaintext message.

## Limitations & Security Notes
This is a learning-focused “RSA-lite” demo:
- Uses very small primes and `long long`, so key sizes are not secure.
- Padding is simple space filling; decrypted output may include trailing spaces.
- No modern padding scheme (e.g., OAEP) or message integrity checks.
