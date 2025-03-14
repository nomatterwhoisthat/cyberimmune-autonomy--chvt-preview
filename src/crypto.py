import json
import random
import hashlib



def is_prime(n, k=5):
    """Miller–Rabin primality test."""
    if n < 2:
        return False
    # Test divisibility by small primes first.
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    # Write n-1 as 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bit_length):
    """Generate a prime number of approximately bit_length bits."""
    while True:
        # Generate a random odd integer with the desired bit length.
        candidate = random.getrandbits(bit_length)
        candidate |= (1 << (bit_length - 1)) | 1  # ensure candidate is odd and has proper bit length
        if is_prime(candidate):
            return candidate

def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Modular inverse of a mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def generate_keys(bit_length=1024):
    """
    Generate an RSA key pair.
    For demonstration we use a 1024-bit key; in practice, use 2048-bit or larger.
    Returns:
      private_key: tuple (n, d)
      public_key: tuple (n, e)
    """
    half_bits = bit_length // 2
    p = generate_prime(half_bits)
    q = generate_prime(half_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # common choice for e
    # Ensure e and phi(n) are coprime.
    if egcd(e, phi)[0] != 1:
        return generate_keys(bit_length)
    d = modinv(e, phi)
    private_key = (n, d)
    public_key = (n, e)
    return private_key, public_key

def hash_data(data):
    """
    Compute the SHA-256 hash of the data and return it as an integer.
    """
    digest = hashlib.sha256(data).hexdigest()
    return int(digest, 16)
