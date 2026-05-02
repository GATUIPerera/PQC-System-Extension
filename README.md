# PQC System Extension
## Design and Implementation of a System Extension for the Performance Evaluation of NIST Post-Quantum Cryptographic Standards

### Student: Galkissa Perera
### Student ID: 10953268
### Degree: BSc (Hons) Computer Security
### University: University of Plymouth
### Supervisor: Mr. Chamindra Attanayaka

## Project Overview
This project implements and evaluates a post-quantum cryptographic system extension using ML-KEM-512 (Kyber) within a hybrid KEM-DEM framework. The system extension encrypts real files using NIST standardised ML-KEM-512 for key encapsulation and AES-256-GCM for data encryption, with SHA-256 integrity verification and tamper detection.

## Files
- pqc_extension.py - Core system extension with tamper detection
- pqc_gui_vm.py - GUI demonstration interface
- demo.py - Benchmarking engine comparing ML-KEM-512 vs RSA-2048
- testfile.txt - Test file used for encryption demonstrations

## Requirements
- Python 3.10
- kyber-py 1.2.0
- cryptography 46.0
- Ubuntu 22.04 LTS

## Installation
pip install kyber-py
pip install cryptography

## Usage
python3 pqc_extension.py
python3 demo.py
python3 pqc_gui_vm.py

## Algorithm
- Key Encapsulation: ML-KEM-512 (NIST FIPS 203)
- Data Encryption: AES-256-GCM
- Integrity Verification: SHA-256
- Baseline Comparison: RSA-2048

## Results Summary
- ML-KEM-512 key generation: 2.93ms average
- RSA-2048 key generation: 54.94ms average
- Performance improvement: 18.7x faster
- Integrity checks: 100% PASSED
- Tamper detection: Operational
- Brute force resistance: 100 million attempts - 0 keys cracked
