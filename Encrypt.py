"""
"" 19th OCT 2025 ::: Irfan Habeeb Gazi
"" 28th OCT 2025 ::: Vivek Halder
"" 29th OCT 2025 ::: Surjayan Kar
""
"" Usage: sage Encrypt.py <pub_key> <message>
""
"" This program encrypts a given message (stored as a point) using Elliptic Curve Cryptography.
"" The private key and public key must be pregeenerated by the user and stored in the
"" corresponding files. Please refer to KeyGeneration.py and KeyGenerationUtil.py for more
"" details. The encrypted message is stored in the file 'ecc_ciphertext.txt'.
""
"" The arguments to be provided to the program are as follows:
"" 1. <pub_key> : The path to file containing the public key for the cryptosystem. This file also
"" stores the elliptic curve parameters to be used.
"" 2. <message> : The message (point) to be encrypted. The point should be a valid point on the
"" elliptic curve defined in the public key file.
""
"" <Sample Input / Output>
""
"" INPUT 1:
"" ecc_public_key.txt:-
"" {
"" public_key": "(7 : 13*a + 1 : 1)",
"" generator": "(8 : 16*a + 7 : 1)",
"" coefficients": "(2, 3, 5, 7, 11)",
"" field_order": "289",
"" field_degree": "2"
"" }
""
"" message.txt:-
"" (12 : 2 : 1)
""
"" OUTPUT 1:
"" ecc_ciphertext.txt:-
"" {
"" C1": "(14 : 11*a + 12 : 1)",
"" C2": "(14*a + 13 : 16*a + 12 : 1)"
"" }
"""

import sys
import json
from sage.all import *


USAGE = "sage Encrypt.py <pub_key> <message>"
if (len(sys.argv) != 3):
    print("Invalid Arguments!")
    print(f"\nUsage: {USAGE}")
    exit(1)


def load_json(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def parse_field(base_field, field_degree):
    if field_degree == 1:
        return GF(base_field)
    else:
        return GF((base_field, field_degree), names=('a',))


def parse_coeffs(coeffs_str, K):
    return [K(c.strip()) for c in coeffs_str]


def parse_point(point_str, E):
    point_str = point_str.strip()
    point_str = point_str[1:-1]
    coords = [s.strip() for s in point_str.split(':')]

    if len(coords) != 3:
        raise ValueError("Invalid point format: " + point_str)

    try:
        x = E.base_field()(coords[0])
        y = E.base_field()(coords[1])
        z = E.base_field()(coords[2])
    except Exception as ex:
        raise ValueError(
            f"Invalid coordinate in point: {point_str}. Error: {ex}")

    try:
        point = E(x, y, z)
    except Exception as ex:
        raise ValueError(
            f"Failed to construct point on curve: {point_str}. Error: {ex}"
        )

    return point


def main():
    pub = load_json(sys.argv[1])

    base_field = int(pub['base_field'].strip())
    field_degree = int(pub['field_degree'].strip())
    coeffs_str = pub['coefficients']
    coeffs_str = coeffs_str[1:-1].split(',')
    generator_str = pub['generator']
    public_key_str = pub['public_key']

    K = parse_field(base_field, field_degree)
    coeffs = parse_coeffs(coeffs_str, K)
    E = EllipticCurve(K, coeffs)
    G = parse_point(generator_str, E)
    public_key = parse_point(public_key_str, E)

    with open(sys.argv[2], 'r') as msg_file:
        msg_str = msg_file.read().strip()
    M = parse_point(msg_str, E)

    # Generate receiver's ephemeral key
    q = G.order()
    k = randint(1, q - 1)

    ciphertext = {
        "C1": str(k * G),
        "C2": str(M + k * public_key)
    }

    with open('ecc_ciphertext.txt', 'w') as cipher_file:
        json.dump(ciphertext, cipher_file, indent=2)

    print("Encryption complete. Ciphertext saved to 'ecc_ciphertext.txt'.")


if __name__ == "__main__":
    main()
