# CKKS-Implementation

A clean, minimal, from-scratch implementation of CKKS for research, backend development, and HE systems.

---

## 📦 Overview

`ckks-dev` is a **CKKS-only homomorphic encryption engine**, designed with:

* **Clean and minimal API**
* **High-performance RNS/NTT backend**
* **Modular phase-based architecture**
* **Easy extensibility for evaluation ops & bootstrapping**
* **Production-ready CMake + Docker environment**

The project implements CKKS **from the ground up**, including:

* Parameter generation
* RNS + NTT number-theoretic engine
* Polynomial operations
* Encoding / decoding (unitary FFT)
* Key generation
* Encryption / decryption
* A complete standalone test suite

This repository is meant both for **research** and **performance engineering**.

---

## 📁 Repository Structure

```
.
├── CMakeLists.txt
├── Dockerfile
├── docker_run.sh
├── build.sh
├── include/
│   ├── ckks_lib.hpp
│   ├── core/
│   │   ├── ckks.hpp
│   │   ├── params.hpp
│   │   ├── rns.hpp
│   │   ├── ntt.hpp
│   │   └── poly.hpp
│   └── crypto/
│       ├── encoder.hpp
│       ├── encrypt.hpp
│       ├── decrypt.hpp
│       ├── keygen.hpp
│       ├── keys.hpp
│       ├── plaintext.hpp
│       └── ciphertext.hpp
├── src/
│   ├── core/...
│   ├── crypto/encoder.cpp
│   ├── crypto/encrypt.cpp
│   ├── crypto/decrypt.cpp
│   ├── crypto/keygen.cpp
│   └── ...
├── tests/
│   ├── test_encoder.cpp
│   ├── test_keygen.cpp
│   ├── test_encrypt_decrypt.cpp
│   └── main.cpp
└── docs/
    ├── design.md
    ├── parameters.md
    ├── ckks_math.md
    ├── backend_design.md
    ├── bootstrap_design.md
    └── roadmap.md
```

---

## 🛠 Building the Project

### 🔧 Requirements (if building locally)

* C++20 compiler (clang or gcc)
* cmake ≥ 3.16
* make / ninja
* git

---

## 🐳 Running Inside Docker (Recommended)

The repository includes a ready-to-use development container:

### **1. Build and Run the Environment **

```bash
./docker_run.sh
```

This script mounts your project directory into the container, enabling hot-reload of source files.

You will land in `/workspace`, where you can build and test.

---

## 🏗 Build and Run (Inside Docker or Locally)

### **1. Build (Release mode)**

```bash
./build.sh
```

The script:

* configures CMake
* builds static + shared libraries
* builds unit tests
* runs tests (optional)

Artifacts appear under:

```
build/
  libckks.a
  libckks.so
  tests/ckks_tests
  bench/ckks_bench
```

### **2. Build + run tests automatically**

```bash
./build.sh --run-tests
```

### **3. Build + run benchmarks**

```bash
./build.sh --run-bench
```

---

## 🧪 Running Unit Tests

### **Run via CTest (quiet mode)**

```bash
cd build
ctest
```

### **Run with full output (to see cout logs)**

```bash
ctest -V
```

### **Run test binary directly**

```bash
./tests/ckks_tests
```

---

## 📚 Example Usage

### **Encoding, Encrypting, Decrypting**

```cpp
CKKSParams params(N, qi, log_scale, depth);
CKKSContext ctx(params);

Encoder encoder(ctx);
KeyGenerator keygen(ctx, 123);
SecretKey sk = keygen.generate_secret_key();
PublicKey pk = keygen.generate_public_key(sk);

std::vector<double> v = {1.5, -2.0, 3.25};

// Encode
Plaintext pt(ctx);
encoder.encode(v, params.default_scale, params.max_depth, pt);

// Encrypt
Ciphertext ct(ctx, 2);
Encryptor encryptor(ctx);
encryptor.encrypt(pk, pt, ct);

// Decrypt
Decryptor decryptor(ctx);
Plaintext dpt(ctx);
decryptor.decrypt(sk, ct, dpt);

// Decode
std::vector<double> out;
encoder.decode(dpt, out);
```

---

## 🧱 Architecture (Phase-Based)

The project follows a **strict phase roadmap**, documented in `docs/roadmap.md`:

1. **Phase 0:** Project skeleton, CMake, Docker
2. **Phase 1:** RNS, NTT, modulus chain
3. **Phase 2:** CKKS params, plaintext/ciphertext
4. **Phase 3:** Encoder/decoder
5. **Phase 4:** Key generation
6. **Phase 5:** Encrypt/decrypt
7. **Phase 6:** Evaluation ops (WIP)
8. **Phase 7:** Bootstrapping (future work)

Each phase is isolated and test-driven.

---

## 🧩 Tests Included

### **Core tests**

* polynomial addition, subtraction, negation
* scalar multiplication
* NTT roundtrip
* convolution correctness

### **CKKS tests**

* encoder/decoder roundtrip
* keygen structural & correctness tests
* encrypt → decrypt → decode equivalence
* multilevel encoding/decoding
* random vectors, edge cases

---

## 🚧 Work in Progress / TODO

* Homomorphic eval ops (Phase 6)

    * `EvalAdd`, `EvalSub`, `EvalMulPlain`
    * `EvalMul` + relinearization
    * `EvalRescale`
    * `EvalRotate` (Galois keys)
* Hybrid key switching
* Bootstrapping pipeline
* SIMD acceleration (AVX2/AVX512/SVE)
* GPU backend (optional)
* C API bindings
* Python bindings (pybind11)

Files Herrarchie 
```md
rns = > ntt =>
params.hpp => 
```