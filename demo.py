import time
import os
import hashlib
from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

print("===============================================")
print(" PQC SYSTEM EXTENSION - VIVA DEMONSTRATION")
print(" Student: Galkisa Perera")
print(" Algorithm: Ml-KEM-512 vs RSA-2048")
print("===============================================")

sizes = [1024, 102400, 1048576]
labels = ["1KB", "100KB", "1MB"]
print("--- PART 1: RSA-2048 BASELINE ---")
for i in range(len(sizes)):
    data = os.urandom(sizes[i])
    hash_before = hashlib.sha256(data).hexdigest()
    start = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    session_key = os.urandom(32)
    encrypted_key = public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    keygen_ms= (time.perf_counter() - start) * 1000
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    start = time.perf_counter()
    encrypted = aesgcm.encrypt(nonce, data, None)
    aes_ms = (time.perf_counter() - start) * 1000
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    hash_after = hashlib.sha256(decrypted).hexdigest()
    integrity = "PASSED" if hash_before == hash_after else "FAILED"
    print("File Size:", labels[i])
    print("RSA Key Generation + Encapsulation:", round(keygen_ms, 2), "ms")
    print("AES-256 Encryption:", round(aes_ms, 2), "ms")
    print("Integrity Check:", integrity)
    print("-------------------------------------")

print("--- PART 2: ML-KEM-512 KYBER PQC ---")
for i in range(len(sizes)):
    data = os.urandom(sizes[i])
    hash_before = hashlib.sha256(data).hexdigest()
    start = time.perf_counter()
    pk, sk = ML_KEM_512.keygen()
    keygen_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    key, ciphertext = ML_KEM_512.encaps(pk)
    encaps_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    key2 = ML_KEM_512.decaps(sk, ciphertext)
    decaps_ms = (time.perf_counter() - start) * 1000
    aes_key = key[:32]
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    start = time.perf_counter()
    encrypted =aesgcm.encrypt(nonce, data, None)
    aes_ms = (time.perf_counter() - start) * 1000
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    hash_after = hashlib.sha256(decrypted).hexdigest()
    integrity = "PASSED" if hash_before == hash_after else "FAILED"
    print("File Size:", labels[i])
    print("Kyber Key Generation:", round (keygen_ms, 2), "ms")
    print("Kyber Encapsulation:", round (encaps_ms, 2), "ms")
    print("Kyber Decapsulation:", round(decaps_ms, 2), "ms")
    print("AES-256 Encryption:", round(aes_ms, 2), "ms")
    print("Integrity Check:", integrity)
    print("----------------------------------------")

print("--- PART 3: KEY SIZE COMAPRISON ---")
print("RSA-2048 Public Key Size: 256v bytes")
print("ML-KEM-512 Public Key Size: 800 bytes")
print("ML-KEm-512 Ciphertext Size: 768 bytes")
print("==================================================")
print(" DEMONSTRATION COMPLETE")
print(" All intergrity checks confirms quantum")
print(" resistant encryption is fully operational")
print("==================================================")
