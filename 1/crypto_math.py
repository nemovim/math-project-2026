"""EL2001 small-number RSA/DH arithmetic. Educational parameters only."""
import base64
import binascii
import secrets
from dataclasses import dataclass
from math import isqrt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def gcd(a, b):
    """Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a,b)."""
    old_r, r, old_x, x, old_y, y = a, b, 1, 0, 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_r, old_x, old_y


def mod_inverse(a, modulus):
    if modulus <= 1:
        raise ValueError('modulus must be greater than 1')
    g, x, _ = extended_gcd(a % modulus, modulus)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % modulus


def mod_pow(base, exponent, modulus):
    """Square-and-multiply: do not construct the enormous base**exponent."""
    if exponent < 0 or modulus < 1:
        raise ValueError('invalid modular exponentiation arguments')
    result, base = 1 % modulus, base % modulus
    while exponent:
        if exponent & 1:
            result = result * base % modulus
        base = base * base % modulus
        exponent >>= 1
    return result


def is_prime(n):
    """Exact trial division, sufficient for the assignment's 400..500 range."""
    if not is_integer(n) or n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    return all(n % divisor for divisor in range(3, isqrt(n) + 1, 2))


def prime_factors(n):
    """Distinct prime factors for the DH generator test."""
    factors, divisor = set(), 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.add(divisor)
            n //= divisor
        divisor += 1
    if n > 1:
        factors.add(n)
    return factors


PRIMES = tuple(n for n in range(400, 501) if is_prime(n))


def is_generator(g, p):
    return (is_prime(p) and is_integer(g) and 1 < g < p
            and all(mod_pow(g, (p - 1) // r, p) != 1
                    for r in prime_factors(p - 1)))


def choose_generator(p):
    if not is_prime(p):
        raise ValueError('p must be prime')
    return next(g for g in range(2, p) if is_generator(g, p))


@dataclass(frozen=True)
class RSAKey:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int


def generate_rsa_key():
    p = secrets.choice(PRIMES)
    q = secrets.choice(tuple(prime for prime in PRIMES if prime != p))
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = next(k for k in range(3, phi, 2) if gcd(k, phi) == 1)
    return RSAKey(p, q, p * q, phi, e, mod_inverse(e, phi))


def verify_rsa_key(p, q, e, d):
    checks = {
        'p_prime': is_prime(p), 'q_prime': is_prime(q),
        'p_in_range': is_integer(p) and 400 <= p <= 500,
        'q_in_range': is_integer(q) and 400 <= q <= 500,
        'distinct_primes': is_integer(p) and is_integer(q) and p != q,
    }
    parameters_ok = all(checks.values())
    phi = (p - 1) * (q - 1) if parameters_ok else 0
    checks['e_valid'] = parameters_ok and is_integer(e) and 1 < e < phi and gcd(e, phi) == 1
    checks['inverse_valid'] = (checks['e_valid'] and is_integer(d) and d > 0
                              and e * d % phi == 1)
    checks['round_trip'] = checks['inverse_valid'] and all(
        mod_pow(mod_pow(m, e, p * q), d, p * q) == m
        for m in list(range(256)) + [p, q, p * q - 1])
    return checks


def validate_rsa_public(e, n):
    if not is_integer(n) or not 400 * 400 <= n <= 500 * 500:
        raise ValueError('RSA modulus is outside the assignment range')
    if not is_integer(e) or not 1 < e < n:
        raise ValueError('invalid RSA public exponent')


def rsa_encrypt_key(key, e, n):
    validate_rsa_public(e, n)
    if len(key) != 32:
        raise ValueError('AES-256 requires a 32-byte key')
    return [mod_pow(byte, e, n) for byte in key]


def rsa_decrypt_key(encrypted_key, d, n):
    if not isinstance(encrypted_key, list) or len(encrypted_key) != 32:
        raise ValueError('encrypted_key must contain exactly 32 integers')
    if any(not is_integer(c) or not 0 <= c < n for c in encrypted_key):
        raise ValueError('RSA ciphertext integer out of range')
    decoded = [mod_pow(c, d, n) for c in encrypted_key]
    if any(byte > 255 for byte in decoded):
        raise ValueError('decrypted RSA value is not a byte')
    return bytes(decoded)


def dh_parameter_error(p, g):
    # Exact error strings from slides 12 and 13.
    if not is_integer(p) or not 400 <= p <= 500 or not is_prime(p):
        return 'incorrect prime number'
    if not is_generator(g, p):
        return 'incorrect generator'
    return None


def dh_private(p):
    return secrets.randbelow(p - 2) + 1


def dh_shared(public, private, p):
    if not is_integer(public) or not 1 <= public < p:
        raise ValueError('invalid DH public key')
    return mod_pow(public, private, p)


def dh_aes_key(shared):
    # Follow the PPT exactly; hashing would break interoperability.
    return shared.to_bytes(2, byteorder='big') * 16


def encrypt_message(key, message):
    if len(key) != 32:
        raise ValueError('AES-256 requires a 32-byte key')
    raw = pad(message.encode('utf-8'), AES.block_size)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(raw)
    return base64.b64encode(encrypted).decode('ascii')


def decrypt_message(key, encoded):
    if len(key) != 32 or not isinstance(encoded, str):
        raise ValueError('invalid AES key or ciphertext')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError('invalid Base64 ciphertext') from exc
    if not raw or len(raw) % AES.block_size:
        raise ValueError('AES ciphertext must contain complete 16-byte blocks')
    decrypted = AES.new(key, AES.MODE_ECB).decrypt(raw)
    return unpad(decrypted, AES.block_size).decode('utf-8')


# Optional primality comparison. The protocols keep using exact trial division.
def _check_rounds(rounds):
    if not is_integer(rounds) or rounds < 1:
        raise ValueError('rounds must be a positive integer')


def is_prime_fermat(n, rounds=20):
    """Probable-prime test; composites (e.g. Carmichael numbers) can pass."""
    _check_rounds(rounds)
    if not is_integer(n) or n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        if mod_pow(a, n - 1, n) != 1:
            return False
    return True


def is_prime_miller_rabin(n, rounds=20):
    """Random-base Miller-Rabin; True means probable prime, not a proof."""
    _check_rounds(rounds)
    if not is_integer(n) or n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True
