import time
import os
import hashlib
import sqlite3
from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

conn = sqlite3.connect("pqc_results.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY AUTOINCREMENT, algorithm TEXT, file_size_bytes INTEGER, keygen_ms REAL, encaps_ms REAL, decaps_ms REAL, aes_ms REAL, integrity TEXT, tamper_detected TEXT)")
conn.commit()

def run_extension(filename, simulate_tamper=False):
    print("--- PQC SYSTEM EXTENSION ---")
    print("File:", filename)
    with open(filename, "rb") as f:
         data = f.read()
    file_size = len(data)
    hash_before = hashlib.sha256(data).hexdigest()
    print("Original SHA-256:", hash_before)
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
    encrypted = aesgcm.encrypt(nonce, data, None)
    aes_ms = (time.perf_counter() - start) * 1000
    print("Encryption complete.")
    print("Key Generation Time:", round(keygen_ms, 2), "ms")
    print("Encapsulation Time:", round(encaps_ms, 2), "ms")
    print("Decapsulation Time:", round(decaps_ms, 2), "ms")
    print("AES-256 Encryption Time:", round(aes_ms, 2), "ms")
    if simulate_tamper:
        print("--- TAMPERING SIMUALTED ---")
        encrypted = bytearray(encrypted)
        encrypted[0] = encrypted[0] ^ 0xFF
        encrypted[10] = encrypted[10] ^ 0xFF
        encrypted[20] = encrypted[20] ^ 0xFF
        encrypted = bytes(encrypted)
        print("File has been altered!")
    print("--- TAMPER CHECK BEFORE DECRYPTION ---")
    try:
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
        hash_after = hashlib.sha256(decrypted).hexdigest()
        if hash_before == hash_after:
            integrity = "PASSED"
            tamper_detected = "NO"
            print("Tamper Detected: NO")
            print("Integrity Check: PASSED")
        else:
            integrity = "FAILED"
            tamper_detected = "YES"
            print("ALERT: TAMPER DETECTED!")
            print("Integrity Check: FAILED")
            print("Decryption ABORTED.")
    except Exception:
        integrity = "FAILED"
        tamper_detected = "YES"
        print("AES-GCM Authentication FAILED.")
        print("ALERT: TAMPER DETECTED!")
        print("Integrity Check: FAILED")
        print("Decryption ABORTED.")
    cursor.execute("INSERT INTO results ( algorithm, file_size_bytes,keygen_ms, encaps_ms, decaps_ms, aes_ms, integrity, tamper_detected) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("ML-KEM-512", file_size, keygen_ms, encaps_ms, decaps_ms, aes_ms, integrity, tamper_detected))
    conn.commit()
    print("Results saved to database.")
    print("--------------------------------")

print("TEST 1: Normal Operation")
run_extension("testfile.txt", simulate_tamper=False)
print("")
print("TEST 2: Tamper Detection")
run_extension("testfile.txt", simulate_tamper=True)

