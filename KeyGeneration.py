#!/usr/bin/python3

"""
"" 21st AUG 2025 ::: Irfan Habeeb Gazi
"" 24th AUG 2025 ::: Vivek Halder
"" 9th SEP 2025 ::: Surjayan Kar
""
"" Usage: sage KeyGeneration.py <Mode> [<Parameters>]
""
"" This program generates the public / private key pair for an Elliptic Curve over GF(p^n) or GF(p).
"" It offers different modes of operations for key generation, including:
"" 1. Create a new curve with specified base field and specified curve parameters.
"" 2. Create a new curve with specified base field and random curve parameters.
"" 3. Use a predefined curve with corresponding parameters (e.g., Ed25519).
"" 4. Generate a new curve with specified number of bits for the prime field.
""
"" The argument <Mode> specifies the operation mode:
"" 0: Create a new curve with specified base field and curve parameters.
""    In this mode, the user must provide the base field, degree and curve coefficients a1, a2, a3, a4, a6.
""    sage KeyGeneration.py <Mode=0> <Base_Field> <Degree> <Coeff_a1> <Coeff_a2> <Coeff_a3> <Coeff_a4> <Coeff_a6>
""
"" 1: Create a new curve with random parameters.
""    In this mode, all coefficients are set to Random Element taken from the Base Field or Xtended Field
""    (Depending upon the degree). So, the values of Coefficients are absent in the command line.
""    sage KeyGeneration.py <Mode=1> <Base_Field> <Degree>
""
"" 2: Use a predefined curve with corresponding parameters.
""    In this mode, the user must provide the curve name for a predefined Elliptic Curve.
""    Currently supported curves are: Ed25519, secp256k1, P-256.
""    sage KeyGeneration.py <Mode=2> <Curve_Name>
""
"" 3: Generate a new curve with specified number of bits for the prime field.
""    In this mode, the user must provide the number of bits for the prime field.
""    The remaining curve parameters will be generated randomly.
""    sage KeyGeneration.py <Mode=3> <Bits>
""
"" The public / private key pair are additionally saved to two seperate files,
"" ecc_public_key.txt and ecc_private_key.txt in the current working directory in JSON format.
"" This serves as the persistent store for the generated keys, which can be used in future
"" for encryption / decryption. Please refer to Encryption.py / Decryption.py for more details.
""
"" <Sample Input/Output Sets>
""
"" INPUT 1:-
"" Mode = 0
"" Base_Field = 17
"" Degree = 1
"" Coeff_a1 = 2
"" Coeff_a2 = 3
"" Coeff_a3 = 5
"" Coeff_a4 = 7
"" Coeff_a6 = 11
"" OUTPUT 1:-
"" Field: Finite Field of size 17
"" Curve: Elliptic Curve defined by y^2 + 2*x*y + 5*y = x^3 + 3*x^2 + 7*x + 11 over Finite Field of size 17
"" Group order |E(K)| = 17 = 17 * 1
"" Using subgroup of prime order q = 17 (≈ 5 bits)
"" Generator G = (12 : 2 : 1)
"" Private Key (scalar mod q): 14
"" Public Key (point): (9 : 15 : 1)
"" Time Taken = 0.75s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 2:-
"" Mode = 1
"" Base_Field = 23
"" Degree = 1
"" OUTPUT 2:-
"" Field: Finite Field of size 23
"" Curve: Elliptic Curve defined by y^2 + 6*x*y + 10*y = x^3 + 8*x^2 + 13*x + 2 over Finite Field of size 23
"" Group order |E(K)| = 32 = 2 * 16
"" Using subgroup of prime order q = 2 (≈ 2 bits)
"" Generator G = (22 : 21 : 1)
"" Private Key (scalar mod q): 1
"" Public Key (point): (22 : 21 : 1)
"" Time Taken = 0.75s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 3:-
"" Mode = 2
"" Curve_Name = secp256k1
"" OUTPUT 3:- 
"" Field: Finite Field of size 115792089237316195423570985008687907853269984665640564039457584007908834671663
"" Curve: Elliptic Curve defined by y^2 = x^3 + 7 over Finite Field of size 115792089237316195423570985008687907853269984665640564039457584007908834671663
"" Group order |E(K)| = 115792089237316195423570985008687907852837564279074904382605163141518161494337 = 115792089237316195423570985008687907852837564279074904382605163141518161494337 * 1
"" Using subgroup of prime order q = 115792089237316195423570985008687907852837564279074904382605163141518161494337 (≈ 256 bits)
"" Generator G = (55066263022277343669578718895168534326250603453777594175500187360389116729240 : 32670510020758816978083085130507043184471273380659243275938904335757337482424 : 1)
"" Private Key (scalar mod q): 29021016459232706789186322220791135419842867329588552320355761916659955141289
"" Public Key (point): (74199934061742352277479740564507324138411616448181072549634363409191656855326 : 36364381465393420939967928665194862299455368884398756420657581822897070807092 : 1)
"" Time Taken = 0.95s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 4:-
"" Mode = 3
"" Bits = 5
"" OUTPUT 4:-
"" Field: Finite Field of size 23
"" Curve: Elliptic Curve defined by y^2 + 5*x*y + 7*y = x^3 + 12*x^2 + 20*x + 18 over Finite Field of size 23
"" Group order |E(K)| = 29 = 29 * 1
"" Using subgroup of prime order q = 29 (≈ 5 bits)
"" Generator G = (15 : 6 : 1)
"" Private Key (scalar mod q): 3
"" Public Key (point): (11 : 8 : 1)
"" Time Taken = 0.76s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 5:-
"" Mode = 0
"" Base_Field = 170141183460469231731687303715884105727
"" Degree = 1
"" Coeff_a1 = 123456789987654321
"" Coeff_a2 = 987654321123456789
"" Coeff_a3 = 111111111111111111
"" Coeff_a4 = 222222222222222222
"" Coeff_a6 = 333333333333333333
"" OUTPUT 5:-
"" Field: Finite Field of size 170141183460469231731687303715884105727
"" Curve: Elliptic Curve defined by y^2 + 123456789987654321*x*y + 111111111111111111*y = x^3 + 987654321123456789*x^2 + 222222222222222222*x + 333333333333333333 over Finite Field of size 170141183460469231731687303715884105727
"" Group order |E(K)| = 170141183460469231752155638447580548628 = 7300843374051852701 * 23304319068831573028
"" Using subgroup of prime order q = 7300843374051852701 (≈ 63 bits)
"" Generator G = (56637119735112556676803805625465195495 : 138347011707034180834772335167024668467 : 1)
"" Private Key (scalar mod q): 2234101151657213417
"" Public Key (point): (92776700886180934713646129660892550603 : 15730881493556840037980909091901598635 : 1)" Time Taken = 0.12 Sec (Linux x86_64)"
"" Time Taken = 0.78s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 6:-
"" Mode = 1
"" Base_Field = 340282366920938463463374607431768211507
"" Degree = 1
"" OUTPUT 6:-
"" Field: Finite Field of size 340282366920938463463374607431768211507
"" Curve: Elliptic Curve defined by y^2 + 243196349567586688323734545302763678060*x*y + 58374006788639806421013289492672466219*y = x^3 + 138501807666724098955824924930654497436*x^2 + 215674511201270667020058335343072195984*x + 159881290889881161147711197156555596807 over Finite Field of size 340282366920938463463374607431768211507
"" Group order |E(K)| = 340282366920938463439361665434655262608 = 946894928202823 * 359366553548643214349296
"" Using subgroup of prime order q = 946894928202823 (≈ 50 bits)
"" Generator G = (185044437768815005974499897910819333463 : 32898134685307147819107535620013780325 : 1)
"" Private Key (scalar mod q): 27067074713073
"" Public Key (point): (191945957228654284066840980435483025091 : 5571787734137215789978890296338585959 : 1)
"" Time Taken = 0.80s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 7:-
"" Mode = 2
"" Curve_Name = Ed25519
"" OUTPUT 7:-
"" Field: Finite Field of size 57896044618658097711785492504343953926634992332820282019728792003956564819949
"" Curve: Elliptic Curve defined by y^2 = x^3 + 486662*x^2 + x over Finite Field of size 57896044618658097711785492504343953926634992332820282019728792003956564819949
"" Group order |E(K)| = 57896044618658097711785492504343953926856930875039260848015607506283634007912 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 * 8
"" Using subgroup of prime order q = 7237005577332262213973186563042994240857116359379907606001950938285454250989 (≈ 253 bits)
"" Generator G = (9 : 14781619447589544791020593568409986887264606134616475288964881837755586237401 : 1)
"" Private Key (scalar mod q): 6280492694137048552125600780687406650025121449631737549316946596676252384382
"" Public Key (point): (51885453843249473905695560995509728478073761805791663156234216576257664730160 : 34879757084333187750047713052074580028317511821684536887863856916853124460977 : 1)
"" Time Talken = 0.78s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 8:-
"" Mode = 3
"" Bits = 256
"" OUTPUT 8:-
"" Field: Finite Field of size 80231902115021755678039147812442535246327574221053469221669196592970904776607
"" Curve: Elliptic Curve defined by y^2 + 10162344738799003467612015563455964643777110697422901003729755032366293167684*x*y + 77130752187081080723453632835804996654719575065085247790892902639283510437344*y = x^3 + 25033615423618065815306752943662785470883758012297121914332083906515846485195*x^2 + 15646868640810435075778840679535166373356744192540792807725281759589814979852*x + 42226170828265745384600909103508331371400826004715159800743928990772960255686 over Finite Field of size 80231902115021755678039147812442535246327574221053469221669196592970904776607
"" Group order |E(K)| = 80231902115021755678039147812442535246542285583752107257260316037183034305714 = 55765412007292902557820366619407351937 * 1438739520198096421329213947139949286322
"" Using subgroup of prime order q = 55765412007292902557820366619407351937 (≈ 126 bits)
"" Generator G = (1218558127851732328018907506971368872346321217533345772758449036236694305870 : 2776357186138637912531536531320990515035023235924619976620587373545042322970 : 1)
"" Private Key (scalar mod q): 26895762238325103660873616040114029819
"" Public Key (point): (42816172632848740663231636207608199981226698986945745962571470527884671199876 : 74110368433330564047438851503058966373109924480475243279566010966193443693010 : 1)
"" Time Taken = 5.1s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 9:-
"" Mode = 0
"" Base_Field = 23
"" Degree = 2
"" Coeff_a1 = 15*a
"" Coeff_a2 = 7*a
"" Coeff_a3 = 15*a + 3
"" Coeff_a4 = 1
"" Coeff_a6 = 2
"" OUTPUT 9:-
"" Field: Finite Field in a of size 23^2
"" Curve: Elliptic Curve defined by y^2 + 15*a*x*y + (15*a+3)*y = x^3 + 7*a*x^2 + x + 2 over Finite Field in a of size 23^2
"" Group order |E(K)| = 514 = 257 * 2
"" Using subgroup of prime order q = 257 (≈ 9 bits)
"" Generator G = (14*a + 21 : 4*a + 8 : 1)
"" Private Key (scalar mod q): 147
"" Public Key (point): (9*a + 22 : 4*a : 1) 
"" Time Taken = 0.67s (Linux x86_64 - ASUS TUF 2022)
""
"" INPUT 10:-
"" Mode = 3
"" Bits = 512
"" OUTPUT 10:-
"" Field: Finite Field of size 8869665144807667184160533361914500345240693369047847399042807114698592960130492527442491012529180201587084504449309098496944897278148396876996868641829109
"" Curve: Elliptic Curve defined by y^2 + 59049729017315553666478943487321048973449343929009894129181234973239075327804298597865255632719293229952833928971469824081944513244711503694211186512607*x*y + 5562259715811637310425959796134519112113558049833463508340255905181834616704686298273865345735648021960000652275003124818835279436903110875024084934491443*y = x^3 + 145310528550826388012127277981750923752644716688535413861694364003142666688194702908138957710187193841098718448669707982534116475046431200043245136200565*x^2 + 5903230388036477427567816557799279508837701754755859579753815373433658932280666240670278539681865507107288743540381216664180997792727081516020720736704889*x + 2445957735916535690033211653302029625244570737485643759152595112566936762919326347104808616770104351681197423153070201004911180239135490331618630731752047 over Finite Field of size 8869665144807667184160533361914500345240693369047847399042807114698592960130492527442491012529180201587084504449309098496944897278148396876996868641829109
"" Group order |E(K)| = 8869665144807667184160533361914500345240693369047847399042807114698592960130578254859598830473417695960845124283097788424440614325880729291759850074316351 = 412654672724166410729588239192386037579520461 * 21494158993169764025901263063810697420995880288470995261898408979091556537985547149504813568707516038247570491
"" Using subgroup of prime order q = 412654672724166410729588239192386037579520461 (≈ 149 bits)
"" Generator G = (8504955427650704656893154489345919221165489081476858819957146018870944132016650263728292689931683612123732157688474612593109312408415324390326130832733613 : 975975180005062260554483409360421884654441987343088877760277166307675153268000938214722676458958244550154696727481933923395937528978548261569772697911684 : 1)
"" Private Key (scalar mod q): 225857426619647566868404969301180012539039870
"" Public Key (point): (3254433442252266738458837461474254536571774342340299458014031998943158351722667944574410964551908981173493518933019189284268434350808133371155706326738186 : 4194895666432287196989341793736396588870884847465713054911235898656278004675279992261349811247754157181878107659908392342450191212124817603934298595292443 : 1)
"" Time Taken = 47 mins 48.34s (Linux x86_64 - ASUS TUF 2022)
"""

from sage.all import *
import json
import sys

# Make Field and Elliptic Curve available globally
K = None
E = None

USAGE1 = "sage KeyGeneration.py <Mode=0> <Base_Field> <Degree> <Coeff_a1> <Coeff_a2> <Coeff_a3> <Coeff_a4> <Coeff_a6>"
USAGE2 = "sage KeyGeneration.py <Mode=1> <Base_Field> <Degree>"
USAGE3 = "sage KeyGeneration.py <Mode=2> <Curve_Name>"
USAGE4 = "sage KeyGeneration.py <Mode=3> <Bits>"


def die(message, code=1):
    print(f"Error: {message}", file=sys.stderr)
    exit(code)


if (len(sys.argv) < 3):
    print("Not Enough Arguments!")
    print(f"\n{USAGE1}")
    print("           OR")
    print(f"\n{USAGE2}")
    print("           OR")
    print(f"\n{USAGE3}")
    print("           OR")
    print(f"\n{USAGE4}")
    exit(1)

Mode = int(sys.argv[1])


def is_singular(E) -> bool:
    """
    Check if the elliptic curve is singular.
    Returns True if singular, False otherwise.
    """
    return E.discriminant() == 0


def build_field(base_p: int, degree: int):
    """
    Build the finite field GF(p^n).
    """
    if base_p <= 2:
        die("Base field prime p must be greater than 2 for these Weierstrass forms.")
    if not is_prime(base_p):
        die(f"Base field p={base_p} is not prime.")
    if degree <= 0:
        die("Degree must be >= 1.")
    if degree == 1:
        return GF(base_p)

    try:
        return GF((base_p, degree), names=('a',))
    except Exception as e:
        die(f"Failed to construct GF({base_p}^{degree}): {e}")


def parse_coeffs(K, coeffs_str):
    """
    Parse curve coefficients from strings to field elements.
    """
    try:
        return [K(c) for c in coeffs_str]
    except Exception as e:
        die(f"Failed to parse coefficients over the field: {e}")


def pick_prime_order_generator(E, curve_order=None, min_bits=160, max_tries=64):
    """
    Pick a generator of the largest prime-order subgroup.
    Returns (G, q, h, N) where N=|E|, N=q*h, and G has order q.
    """
    N = curve_order if curve_order is not None else E.order()
    fac = factor(N)
    q = max([p for p, e in fac for _ in [0] if p.is_prime()])
    if q.nbits() < min_bits:
        print(f"Warning: largest prime factor is only {
              q.nbits()} bits; not cryptographically strong.", file=sys.stderr)
    h = N // q
    for _ in range(max_tries):
        P = E.random_point()
        G = h * P
        if not G.is_zero():
            if (q * G).is_zero():
                return G, q, h, N
    die("Failed to derive a prime-order generator after multiple attempts.")


def setup_curve_with_params(base_field, degree, coeffs_str):
    """
    Setup an elliptic curve with specified parameters.
    """
    K = build_field(base_field, degree)
    coeffs = parse_coeffs(K, coeffs_str)
    E = EllipticCurve(K, coeffs)

    if is_singular(E):
        die("The provided curve parameters result in a singular curve. Please provide valid parameters.")

    return K, E


def setup_curve_random(base_field, degree, retries=64):
    """
    Setup an elliptic curve with random parameters.
    """
    K = build_field(base_field, degree)
    for _ in range(retries):
        coeffs = [K.random_element() for _ in range(5)]
        try:
            E = EllipticCurve(K, coeffs)
            if not is_singular(E):
                return K, E
        except Exception:
            pass
    die(f"Failed to generate a random non-singular curve over GF({
        base_field}^{degree}) after {retries} attempts.")


def setup_predefined_curve(name):
    """
    Setup a predefined elliptic curve by name.
    Supported curves: secp256k1, P-256 (prime256v1/secp256r1), curve25519, ed25519.

    Here:
        Gx is the X-coordinate of the generator point
        Gy is the Y-coordinate of the generator point
        G is the generator point
    """
    name = name.strip()

    # secp256k1
    if name.lower() == "secp256k1":
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        K = build_field(p, 1)

        # y^2 = x^3 + 7  => [a1,a2,a3,a4,a6] = [0,0,0,0,7]
        E = EllipticCurve(K, [0, 0, 0, 0, 7])

        Gx = K(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
        Gy = K(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        G = E(Gx, Gy)

        n = Integer(
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        h = 1
        return K, E, G, n, h

    # NIST P-256 (aka prime256v1 / secp256r1)
    if name in ["P-256", "prime256v1", "secp256r1", "p-256", "P256"]:
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        K = GF(p)
        a = K(-3)
        b = K(0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)
        E = EllipticCurve(K, [0, 0, 0, a, b])
        Gx = K(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296)
        Gy = K(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
        G = E(Gx, Gy)
        n = Integer(
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)
        h = 1
        return K, E, G, n, h

    # Ed25519 (Twisted Edwards form)
    if name.lower() == "ed25519":
        p = 2**255 - 19
        K = GF(p)
        A = K(486662)

        E = EllipticCurve(K, [0, A, 0, 1, 0])
        x = K(9)
        rhs = x**3 + A*x**2 + x
        if not rhs.is_square():
            die("Curve25519 base point x=9 does not yield a quadratic residue y^2.")
        y = rhs.sqrt()
        G = E(x, y)

        # same prime subgroup order
        n = Integer(2**252 + 27742317777372353535851937790883648493)
        h = 8
        return K, E, G, n, h

    die(f"Unsupported curve name: {
        name}. Try: secp256k1, P-256, curve25519, ed25519.")


def setup_curve_with_bits(bits, retries=64):
    """
    Setup an elliptic curve with a prime field of specified bit length.
    """
    lower_bound = Integer(1) << (bits - 1)
    upper_bound = (Integer(1) << bits) - 1

    p = random_prime(upper_bound, lbound=lower_bound)
    K = build_field(p, 1)

    for _ in range(retries):
        coeff = [K.random_element() for _ in range(5)]

        try:
            E = EllipticCurve(K, coeff)
            if not is_singular(E):
                return K, E
        except Exception:
            pass

    die(f"Failed to find a non-singular curve over GF({
        p}) after {retries} attempts.")


def generate_keypair(mode, args):
    """
    Generate elliptic curve parameters and keypair based on mode and arguments.
    Returns a dictionary with all relevant parameters.
    """
    K = None
    E = None
    G = None
    q = None
    h = None
    N = None

    if mode == 0:
        if len(args) != 7:
            die(f"Problem with Arguments!\n{USAGE1}")
        base_field = int(args[0])
        degree = int(args[1])
        coeffs_str = args[2:7]
        K, E = setup_curve_with_params(base_field, degree, coeffs_str)
        G, q, h, N = pick_prime_order_generator(E)
    elif mode == 1:
        if len(args) != 2:
            die(f"Problem with Arguments!\n{USAGE2}")
        base_field = int(args[0])
        degree = int(args[1])
        K, E = setup_curve_random(base_field, degree)
        G, q, h, N = pick_prime_order_generator(E)
    elif mode == 2:
        if len(args) != 1:
            die(f"Problem with Arguments!\n{USAGE3}")
        curve_name = args[0]
        K, E, G, q, h = setup_predefined_curve(curve_name)
        base_field = K.order()
        degree = 1
        N = q * h
    elif mode == 3:
        if len(args) != 1:
            die(f"Problem with Arguments!\n{USAGE4}")
        bits = int(args[0])
        K, E = setup_curve_with_bits(bits)
        base_field = K.order()
        degree = 1
        G, q, h, N = pick_prime_order_generator(E)
    else:
        die("Invalid Mode! Please choose a valid mode (0, 1, 2, or 3)." + f"\n{USAGE1}" + "           OR" + f"\n{
            USAGE2}" + "           OR" + f"\n{USAGE3}" + "           OR" + f"\n{USAGE4}")

    if G is None:
        die("Failed to derive a prime-order generator.")

    sk = Integer(randint(1, q - 1))
    pk = sk * G

    return {
        "field": K,
        "curve": E,
        "group_order": N,
        "prime_order": q,
        "cofactor": h,
        "generator": G,
        "private_key": sk,
        "public_key": pk,
        "base_field": base_field,
        "field_degree": degree,
    }


def write_key_files_json(params, pub_filename="ecc_public_key.txt", priv_filename="ecc_private_key.txt"):
    # Write public key data as JSON
    coefficients = params['curve'].a_invariants()

    pub_data = {
        "public_key": str(params['public_key']),
        "generator": str(params['generator']),
        "coefficients": str(coefficients),
        "base_field": str(params['base_field']),
        "field_degree": str(params['field_degree']),
    }
    with open(pub_filename, 'w') as pub_file:
        json.dump(pub_data, pub_file, indent=2)
    # Write private key data as JSON
    priv_data = {
        "private_key": str(params['private_key'])
    }
    with open(priv_filename, 'w') as priv_file:
        json.dump(priv_data, priv_file, indent=2)


def main():
    if len(sys.argv) < 3:
        print("Not Enough Arguments!")
        print(f"\n{USAGE1}")
        print("           OR")
        print(f"\n{USAGE2}")
        print("           OR")
        print(f"\n{USAGE3}")
        print("           OR")
        print(f"\n{USAGE4}")
        exit(1)

    mode = int(sys.argv[1])
    args = sys.argv[2:]

    params = generate_keypair(mode, args)

    write_key_files_json(params)

    print(f"Field: {params['field']}")
    print(f"Curve: {params['curve']}")
    print(f"Group order |E(K)| = {params['group_order']} = {
          params['prime_order']} * {params['cofactor']}")
    print(f"Generator G: {params['generator']}")
    print(f"Private Key (scalar mod q): {params['private_key']}")
    print(f"Public Key (point): {params['public_key']}")


if __name__ == "__main__":
    main()
