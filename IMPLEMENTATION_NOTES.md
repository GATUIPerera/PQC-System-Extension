# Implementation Notes

## Environment Setup
- Ubuntu 22.04 LTS Server on Oracle VM VirtualBox
- Python 3.10 virtual environment (pqc-vm)
- SSH access via MobaXterm with X11 forwarding for GUI

## Algorithm Selection
- ML-KEM-512 selected based on NIST FIPS 203 standard
- kyber-py 1.2.0 chosen over liboqs due to stability
- AES-256-GCM selected for authenticated encryption
- RSA-2048 used as classical baseline for comparison

## Benchmarking Methodology
- 5 independent experimental runs
- File sizes: 1KB, 100KB, 1MB
- High resolution timing using time.perf_counter()
- Results logged to SQLite database

## Key Results
- ML-KEM-512 key generation: 2.93ms average (1KB)
- RSA-2048 key generation: 54.94ms average (1KB)
- Performance improvement: 18.7x faster
- Integrity verification: 100% PASSED
- Tamper detection: OPERATIONAL
- Brute force test: 100 million attempts, 0 keys cracked

## Security Features
- AES-GCM authentication tag verification before decryption
- SHA-256 hash comparison after decryption
- Two independent tamper detection layers
- Decryption aborted on any authentication failure
