# Merkle-Hellman-knapsack-cryptosystem
implementation of Merkle–Hellman algorithm in python

## Installation

its script dont need installation

## Usage

```python
merkle_system = MerkleHellman(weights=[2, 3, 6, 12, 24, 49, 100, 206, 517])

merkle_system.encrypt(address="./text.txt"),

print(merkle_system.decrypt(address="./text_encrypted"))
```
