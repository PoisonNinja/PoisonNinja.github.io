---
layout: post
title: AES-128 in Google Sheets
---

# What is AES?
AES, or the Advanced Encryption Standard, is a encryption standard established by the National Institute of Standards (NIST).

Rijndael is the specific algorithm used in AES. It is a symmetric block cipher, meaning that it operates on blocks of data and can encrypt and decrypt data using only one key (as opposed to asymmetrical encryption, which needs a public and a private key).

## Brief History
AES was created in 1997 through a competition hosted by the National Institute of Standards and Technology (NIST), which wanted to replace the Data Encryption Standard (DES).

DES was already proven to be insecure, and NIST needed a new algorithm that was "an unclassified, publicly disclosed encryption algorithm capable of protecting sensitive government information well into the next century". Several groups submitted algorithms to the competition. Submitted ciphers were evaluated by the NSA for speed, security, and feasibility on low powered devices (smart cards, etc.).

Eventually, an algorithm submitted by Belgians Joan Daemen and Vincent Rijmen, called Rijndael. Eventually, it would become U.S. FIPS PUB 197.

In 2003, the US government announced that AES could be used to protect confidential information, and was used by the NSA to store important documents.

Today, AES is one of the most popular block ciphers in existence due to it's high performance and security it provides.

# AES implementation
AES uses four basic operations, grouped in rounds. The number of rounds depends on the AES bit size. The higher bit size, the more rounds.

Since I implemented AES-128 in Google Sheets, that is what we will be looking at specifically.

For AES-128, there are 10 rounds, plus an initial round that only has the AddRoundKey step.

Below is a diagram of a round for both encryption and decryption.

![AES diagram](http://i.stack.imgur.com/SnHH2.png)

AES-128 requires a key of 128-bits (16 bytes) and a plaintext of 128-bits (16 bytes)

## Byte organization
The bytes in the plaintext and key are arranged in a 4x4 matrix, top to bottom, left to right. For example, 00112233445566778899AABBCCDDEEFF becomes
```
00 44 88 CC
11 55 99 DD
22 66 AA EE
33 77 BB FF
```

## Prerequisite Stuff

### sbox and inverse sbox
A sbox is a table that takes an input value, looks it up, and outputs another value. The the inverse sbox takes the output from the sbox, and restores it to the original input value.

The sbox hides relationships between the key and the output data.

![sbox](https://captanu.files.wordpress.com/2015/04/aes_sbox.jpg)

The sbox isn't actually random. It was constructed using a formula designed to avoid pairing certain values to other values, so that analysis would be much harder.

### XOR
A basic operation that operates on the binary level. It is only true if and only if one of the bits is 1.

![XOR Truth Table](http://www.electronicshub.org/wp-content/uploads/2015/07/TRUTH-TABLE-1.jpg)

### Galois / Finite Field
In simple terms, a Galois Finite Field is a matrix that has a maximum limit before values wrap around. Finite fields are defined by the equation p^k, where p is a prime and k is a positive integer. p is the characteristic of the finite field, because adding p copies of any number is equal to 0. Finite fields can also be identified in the notation GF(x), where x is equal to p^k.

There are only two operations: addition and multiplication.

Addition is defined as "adding two of these polynomials together, and reducing the result modulo the characteristic." In AES, the Galois field is defined as GF(256), or 2^8. Therefore, the characteristic is 2.

When the characteristic is 2, addition is simply just XORing the the values together.

Multiplication in a finite field is much more complicated. First, multiply the numbers normally, such as in algebra. Then, divide that (because it won't fit into an 8 bit field) by a fixed number, known as an irreducible polynomial. I have to admit that this is a little beyond my math level, but here it is:
```
x8 + x4 + x3 + x + 1 = 0x11b
```

We divde the product of those two numbers by this polynomial, and the remainder is our product.

In Java:
```
public byte FFMul(unsigned byte a, unsigned byte b) {
   unsigned byte aa = a, bb = b, r = 0, t;
   while (aa != 0) {
      if ((aa & 1) != 0)
         r = r ^ bb;
      t = bb & 0x80;
      bb = bb << 1;
      if (t != 0)
         bb = bb ^ 0x1b;
      aa = aa >> 1;
   }
   return r;
}
```

### rcon
The rcon, or round constant, is a constant number for each round. It is simply defined as 2^n, where n is the round number. This is important for generating the key schedule, which is explained next.

### Key Schedule
Each round of AES uses a different key. Each key is derived from the previous key, and so the key schedule changes based on the input key.

For AES-128, we need to expand a 128-bit key to 10 different 128-bit keys

## Operations

### SubBytes
SubBytes is one of the most simple operations. Here, we simply replace each byte with the corresponding value in the sbox.

For decryption, we replace each byte with the corresponding byte in the inverse sbox.

For example:
```
00 71 07 16
11 73 11 0B
07 61 76 72
70 04 79 00
```

becomes
```
63 A3 C5 47
82 8F 82 2B
C5 EF 38 40
51 F2 B6 63
```

### ShiftRows
ShiftRows is another easy operations. The rows in the matrix each shift by a predetermined amount. This is also known as a rotation. Bytes that "fall off" one end are inserted at the other end.

In AES, the first row is left unchanged. The second row is shifted by one byte to the left. The third row is shifted by two bytes to the left, and the fourth row is shifted by three bytes.

This step is an example of a transposition cipher, which merely moves around bytes instead of modifying them.

During decryption, the direction of the shift would be reversed.

### MixColumns
MixColumns is a very important, yet hard step to calculate. This is where knowledge of the Galois Field and general matrix multiplication is necessary.

The Rijndael Galois Field is defined as:

![Rijndael Galois Field](https://wikimedia.org/api/rest_v1/media/math/render/svg/643fda02841bc799fa769c18670206ab7dde8524)

The MixColumns step operates on one column at a time (as the name suggests). b is the output column, and a is the corresponding columns in the input matrix.

To calculate a value in this step, use the standard matrix multiplication rules and multiply Rijndael's Galois Field with the input "column", except that multiplication still follows the rules of multiplication in a finite field.

![Rijndael MixColumns](https://wikimedia.org/api/rest_v1/media/math/render/svg/692b64470b3c92b2b88a245f1de14f481668d20a)

Or, to put it another way:

![](https://wikimedia.org/api/rest_v1/media/math/render/svg/d87b0911a654fa7fa7fcc8f0d49f32b763a27c26)<br />
![](https://wikimedia.org/api/rest_v1/media/math/render/svg/73390ae5901029c3502f3b4d65357140f5f0b921)<br />
![](https://wikimedia.org/api/rest_v1/media/math/render/svg/43766345980b7bb305ebe271ad1e4088b1033609)<br />
![](https://wikimedia.org/api/rest_v1/media/math/render/svg/01f3e27f3fb392d30ff92f99c41b06f33721b5f9)

b<sub>0</sub> is the result of the MixColumns operation, and a<sub>0</sub> is the corresponding cell of the input.

### AddRoundKey
This step combines the round key
