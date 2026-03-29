"""
"" 21st FEB 2026 ::: Irfan Habeeb Gazi
"" 12th FEB 2026 ::: Vivek Halder
"" 29th OCT 2025 ::: Surjayan Kar
""
"" Usage: sage Encrypt.py <pub_key> <message>
""
"" This program encrypts a given message (stored as a point) using Elliptic Curve Cryptography.
"" The private key and public key must be pregeenerated by the user and stored in the
"" corresponding files. Please refer to KeyGeneration.py for more
"" details. The encrypted message is stored in the file 'ecc_ciphertext.txt'.
""
"" It offers two different modes of operation:
"" 1: Encryption of multiple ASCII characters into a point on the elliptic curve. 
""    In this mode, the user provides the path to the file containing the public key, and the path to the
""    .txt file containing the characters to be encrypted
""    sage Encrypt.py 1 ecc_public_key.txt message.txt
""
"" 2. Encryption of multiple points stored in a file.
""    In this mode, the user provides the path to the file containing the public key, and a
""    the path to the .txt file containing the points to  be encrypted. The points should be valid
""    points on the elliptic curve defined in the public key file.
""    sage Encrypt.py 2 ecc_public_key.txt message.txt
""
"" <Sample Input / Output>
""
"" INPUT 1:
"" Mode = 2
"" ecc_public_key.txt:-
"" {
"" "public_key": "(7 : 13*a + 1 : 1)",
"" "generator": "(8 : 16*a + 7 : 1)",
"" "coefficients": "(2, 3, 5, 7, 11)",
"" "base_field": "17",
"" "field_degree": "2"
"" }
""
"" message.txt:-
"" (12 : 2 : 1)
"" (12 : 3 : 1)
""
"" OUTPUT 1:
"" Mode = 1
"" ecc_ciphertext.txt:-
"" {
"" "C1": "(2 : 16*a + 13 : 1)",
"" "ciphertexts": [
""    {
""      "C2": "(4*a + 3 : 3*a + 5 : 1)"
""    },
""    {
""      "C2": "(13*a + 7 : 11*a + 7 : 1)"
""    }
""  ]
"" }
""
"" Time Taken - 0.61s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 2:
"" ecc_public_key.txt:-
"" {
""   "public_key": "(95896570400982669048054269309280068466 : 101613368519350077389271444278575641331 : 1)",
""   "generator": "(146509865186709558332568654250747812154 : 296706650525226469128366357359881794645 : 1)",
""   "coefficients": "(135679116661939155249036766490267172875, 278115415174837476836815625805522646686, 139871793268352908519147087491400262288, 135428774238550599914948378814411507415, 126880101249320461602323281701382698900)",
""   "base_field": "297654049293069287429956324068660269161",
""   "field_degree": "1"
"" }
""
"" message.txt:-
"" the big brown fox jumped over the lazy dog
""
"" OUTPUT 2:
"" ecc_ciphertext.txt:-
"" {
""  "C1": "(246061286564754751223481938184875213521 : 110533907861387102692001622673252613287 : 1)",
""  "ciphertexts": [
""    {
""      "C2": "(212589896626005822151635803020135877828 : 28823606331589452243615912585454517360 : 1)"
""    },
""    {
""      "C2": "(15870025185520236649974831640236855158 : 237795918822894126070205945576744798046 : 1)"
""    },
""    {
""      "C2": "(227830625249530556693312438373163312902 : 104643644650003530211917092432558116090 : 1)"
""    }
""  ]
"" }
""
"" Time Taken - 0.72s (Linux x86_64 - ASUS TUF 2022)
"""

import sys
import json
import secrets
from sage.all import *

USAGE1 = "sage Encrypt.py 1 <pub_key> <message>"
USAGE2 = "sage Encrypt.py 2 <pub_key> <message>"
if (len(sys.argv) != 4):
    print("Invalid Arguments!")
    print(f"\nASCII Encryption: {USAGE1}")
    print("OR")
    print(f"Point Encryption: {USAGE2}")
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

    if not (point_str.startswith('(') and point_str.endswith(')')):
        raise ValueError(
            "Point must be in parentheses, e.g. '(x : y : z)': " + repr(point_str))

    point_str = point_str[1:-1]

    coords = [s.strip() for s in point_str.split(':')]

    if len(coords) != 3:
        raise ValueError(
            "Invalid point format (expected 3 coords) : " + repr(point_str))

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

def generate_ephemeral_key(G):
    # Generate receiver's ephemeral key
    q = G.order()

    if q is None:
        raise ValueError("Generator order unknown. Check public key file.")

    # convert q to integer if it's not
    q_int = int(q)
    if q_int <= 1:
        raise ValueError("Invalid order of the generator point G.")

    # Generate random k in [1, q-1], making sure it is a Cryptographically Secure Pseudo-Random Number
    k = secrets.randbelow(q_int - 1) + 1  # 1 <= k < q

    return k

def encrypt_point(M, G, public_key):
    k = generate_ephemeral_key(G)

    ciphertext = {
        "C1": str(k * G),
        "C2": str(M + k * public_key)
    }

    return ciphertext


def map_chars_to_point(chunk, E):
    X_candid = sum([ord(c) << (8 * i) for i, c in enumerate(chunk)])
    X_candid = X_candid << 8  # Padding X by 8 bits

    # Check if X is a valid x-coordinate on the curve
    for _ in range(256):
        # Check if value of X is greater than field size
        if X_candid >= E.base_field().order():
            raise ValueError(
                f"Cannot map characters to point: Exceeded field size. X = {X_candid}, Field Size = {int(E.base_field().order())}"
            )

        try:
            P = E.lift_x(E.base_field()(X_candid))
            return P
        except Exception:
            X_candid += 1

    return None


def compute_chunk_size(E):
    p = E.base_field().order()

    if p.nbits() < 16:
        raise ValueError(
            f"Field size too small for character encoding. Field Size = {p}. Minimum required field size is 16 bits (65535)."
        )
    return (p.nbits() - 8) // 8

def encrypt_blocks(M_blocks, G, public_key):
    k = generate_ephemeral_key(G)

    C1 = k * G
    ciphertexts = []
    for M in M_blocks:
        C2 = M + k * public_key
        ciphertexts.append({"C2": str(C2)})
    return {"C1": str(C1), "ciphertexts": ciphertexts}

def main():
    mode = int(sys.argv[1])
    pub = load_json(sys.argv[2])

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

    with open(sys.argv[3], 'r') as msg_file:
        msg_str = msg_file.read().strip()

    if mode == 1:
        if (field_degree > 1):
            raise ValueError(
                f"Message mapping not supported for extended fields. Field Degree = {field_degree}"
            )

        msg_str.strip()

        # Break message into dynamically sized chunks
        chunk_size = compute_chunk_size(E)
        chunks = [msg_str[i:i + chunk_size]
                  for i in range(0, len(msg_str), chunk_size)]
        print(f"Given Field Size: {int(E.base_field().order())}, Chunk Size: {chunk_size} characters.\n")
        print(f"Splitting message into {len(chunks)} chunks:\n")

        M_blocks = []
        for chunk in chunks:
            M = map_chars_to_point(chunk, E)
            print(f"Mapped chunk '{chunk}' to point {M}")
            M_blocks.append(M)

        ciphertext = encrypt_blocks(M_blocks, G, public_key)

    elif mode == 2:
        points_strs = [line.strip()
                       for line in msg_str.splitlines() if line.strip()]

        if not points_strs:
            raise ValueError(
                "Mode 2: No valid points found in the message file.")

        M_blocks = []
        for point_str in points_strs:
            M = parse_point(point_str, E)
            M_blocks.append(M)

        ciphertext = encrypt_blocks(M_blocks, G, public_key) 
    else:
        raise ValueError("Invalid mode! Please choose a valid mode (1 or 2).")

    with open('ecc_ciphertext.txt', 'w') as cipher_file:
        json.dump(ciphertext, cipher_file, indent=2)

    print("Encryption complete. Ciphertext saved to 'ecc_ciphertext.txt'.")


if __name__ == "__main__":
    main()
