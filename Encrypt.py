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
"" It offers two different modes of operation:
"" 0: Encrption a single point stored in a file.
""    In this mode, the user provides the path to the file containing the public key, and a
""    the path to the .txt file containing the point to  be encrypted. The point should be a
""    valid point on the elliptic curve defined in the public key file.
""    sage Encrypt.py 0 ecc_public_key.txt message.txt
""
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
"" Mode = 0
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
""
"" OUTPUT 1:
"" Mode = 1
"" ecc_ciphertext.txt:-
"" {
"" "C1": "(14 : 11*a + 12 : 1)",
"" "C2": "(14*a + 13 : 16*a + 12 : 1)"
"" }
""
"" INPUT 2:
"" ecc_public_key.txt:-
"" {
"" "public_key": "(33826589915974876451303538711434911780771211905044168883402609147833006747732 : 27566994943980390140539650248379388081128599148510027697475930812689256311866 : 1)",
"" "generator": "(9 : 14781619447589544791020593568409986887264606134616475288964881837755586237401 : 1)",
"" "coefficients": "(0, 486662, 0, 1, 0)",
"" "base_field": "57896044618658097711785492504343953926634992332820282019728792003956564819949","" "field_degree": "1"
"" }
""
"" message.txt:-
"" blue
""
"" OUTPUT 2:
"" ecc_ciphertext.txt:-
"" {
"" "C1": "(31894743248758571947732118035776289069590431853604163486169561500672450626470 : 17022476366370823369904501506306283319725097315687443836148662080126252360294 : 1)",
"" "C2": "(32710928097340310354198571803413987008186855435925972928960974582482408697236 : 27263700611213709848986074990488688584781464945924217181237791975065342270456 : 1)"
"" }
"""

import sys
import json
import secrets
from sage.all import *


USAGE1 = "sage Encrypt.py 0 <pub_key> <message>"
USAGE2 = "sage Encrypt.py 1 <pub_key> <message>"
USAGE3 = "sage Encrypt.py 2 <pub_key> <message>"
if (len(sys.argv) != 4):
    print("Invalid Arguments!")
    print(f"\nUsage: {USAGE1}")
    print("OR")
    print(f"Usage: {USAGE2}")
    print("OR")
    print(f"Usage: {USAGE3}")
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


def encrypt_point(M, G, public_key):
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
    return (p.nbits() - 8) // 8

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

    if mode == 0:
        M = parse_point(msg_str, E)
        ciphertext = encrypt_point(M, G, public_key)

    elif mode == 1:
        if (field_degree > 1):
            raise ValueError(
                f"Message mapping not supported for extended fields. Field Degree = {field_degree}"
            )

        msg_str.strip()

        # Break message into dynamically sized chunks
        chunk_size = compute_chunk_size(E)
        chunks = [msg_str[i:i + chunk_size]
                  for i in range(0, len(msg_str), chunk_size)]

        ciphertext_list = []

        for chunk in chunks:
            M = map_chars_to_point(chunk, E)
            print(f"Mapped chunk '{chunk}' to point {M}")
            ciphertext_list.append(encrypt_point(M, G, public_key))

        ciphertext = {
            "ciphertexts": ciphertext_list
        }

    elif mode == 2:
        points_strs = [line.strip()
                       for line in msg_str.splitlines() if line.strip()]

        if not points_strs:
            raise ValueError(
                "Mode 2: No valid points found in the message file.")

        ciphertext_list = []

        for point_str in points_strs:
            M = parse_point(point_str, E)
            ct = encrypt_point(M, G, public_key)
            ciphertext_list.append(ct)

        ciphertext = {
            "ciphertexts": ciphertext_list
        }

    with open('ecc_ciphertext.txt', 'w') as cipher_file:
        json.dump(ciphertext, cipher_file, indent=2)

    print("Encryption complete. Ciphertext saved to 'ecc_ciphertext.txt'.")


if __name__ == "__main__":
    main()
