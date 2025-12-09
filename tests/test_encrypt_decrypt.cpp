#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <cmath>

#include "crypto/ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/keygen.hpp"

using namespace ckks;
using namespace ckks::crypto;
using namespace ckks::core;

// Compare with tolerance
static void check_close(const std::vector<double>& a,
                        const std::vector<double>& b,
                        double tol = 1e-2)
{
    assert(a.size() == b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        double diff = std::fabs(a[i] - b[i]);
        if (diff > tol) {
            std::cerr << "Mismatch at " << i
                      << ": " << a[i] << " vs " << b[i]
                      << " (diff=" << diff << ")\n";
            assert(false);
        }
    }
}

// -----------------------------------------------------------------------------
// Test 1: small vector roundtrip
// -----------------------------------------------------------------------------
void test_small_vector()
{
    std::size_t N = 16;
    std::vector<std::uint64_t> qi = {97, 193};
    int log_scale = 20;
    int depth = static_cast<int>(qi.size()) - 1;

    CKKSParams params(N, qi, log_scale, depth);
    CKKSContext ctx(params);

    Encoder encoder(ctx);
    Encryptor encryptor(ctx);
    Decryptor decryptor(ctx);

    KeyGenerator keygen(ctx, 12345);
    SecretKey sk = keygen.generate_secret_key();
    PublicKey pk = keygen.generate_public_key(sk);

    std::vector<double> v = {1.5, -2.0, 3.25};

    Plaintext pt(ctx);
    encoder.encode(v, params.default_scale, depth, pt);

    Ciphertext ct(ctx, 2);
    encryptor.encrypt(pk, pt, ct);

    Plaintext dec_pt(ctx);
    decryptor.decrypt(sk, ct, dec_pt);

    std::vector<double> v2;
    encoder.decode(dec_pt, v2);
    v2.resize(v.size());

    check_close(v, v2, 1e-2);

    std::cout << "[OK] encrypt/decrypt small-vector test passed\n";
}

// -----------------------------------------------------------------------------
// Test 2: random vector roundtrip
// -----------------------------------------------------------------------------
void test_random_vector()
{
    std::size_t N = 32;
    std::vector<std::uint64_t> qi = {193, 257};
    int log_scale = 20;
    int depth = static_cast<int>(qi.size()) - 1;

    CKKSParams params(N, qi, log_scale, depth);
    CKKSContext ctx(params);

    Encoder encoder(ctx);
    Encryptor encryptor(ctx);
    Decryptor decryptor(ctx);
    KeyGenerator keygen(ctx, 54321);

    SecretKey sk = keygen.generate_secret_key();
    PublicKey pk = keygen.generate_public_key(sk);

    std::mt19937_64 rng(9999);
    std::uniform_real_distribution<double> dist(-5.0, 5.0);

    std::vector<double> v(10);
    for (double& x : v) x = dist(rng);

    Plaintext pt(ctx);
    encoder.encode(v, params.default_scale, depth, pt);

    Ciphertext ct(ctx, 2);
    encryptor.encrypt(pk, pt, ct);

    Plaintext dec_pt(ctx);
    decryptor.decrypt(sk, ct, dec_pt);

    std::vector<double> v2;
    encoder.decode(dec_pt, v2);
    v2.resize(v.size());

    check_close(v, v2, 1e-2);

    std::cout << "[OK] encrypt/decrypt random-vector test passed\n";
}

// -----------------------------------------------------------------------------
// Test 3: different scales
// -----------------------------------------------------------------------------
void test_multi_scale()
{
    std::size_t N = 16;
    std::vector<std::uint64_t> qi = {97, 193};
    CKKSParams params(N, qi, 20, static_cast<int>(qi.size()) - 1);
    CKKSContext ctx(params);

    Encoder encoder(ctx);
    Encryptor encryptor(ctx);
    Decryptor decryptor(ctx);
    KeyGenerator keygen(ctx, 888);

    SecretKey sk = keygen.generate_secret_key();
    PublicKey pk = keygen.generate_public_key(sk);

    std::vector<double> v = {0.1, -0.2, 0.3};

    for (int log_s : {10, 15, 20}) {
        double scale = std::pow(2.0, log_s);

        Plaintext pt(ctx);
        encoder.encode(v, scale, params.max_depth, pt);

        Ciphertext ct(ctx, 2);
        encryptor.encrypt(pk, pt, ct);

        Plaintext dec_pt(ctx);
        decryptor.decrypt(sk, ct, dec_pt);

        std::vector<double> v2;
        encoder.decode(dec_pt, v2);
        v2.resize(v.size());

        check_close(v, v2, 1e-2);
    }

    std::cout << "[OK] encrypt/decrypt multi-scale tests passed\n";
}

// -----------------------------------------------------------------------------
// Test 4: repeated encryption/decryption
// -----------------------------------------------------------------------------
void test_multiple_rounds()
{
    std::size_t N = 16;
    std::vector<std::uint64_t> qi = {97, 193};
    CKKSParams params(N, qi, 20, static_cast<int>(qi.size()) - 1);
    CKKSContext ctx(params);

    Encoder encoder(ctx);
    Encryptor encryptor(ctx);
    Decryptor decryptor(ctx);
    KeyGenerator keygen(ctx, 777);

    SecretKey sk = keygen.generate_secret_key();
    PublicKey pk = keygen.generate_public_key(sk);

    std::vector<double> v = {1.234, -2.5, 0.75};

    for (int rep = 0; rep < 5; ++rep) {
        Plaintext pt(ctx);
        encoder.encode(v, params.default_scale, params.max_depth, pt);

        Ciphertext ct(ctx, 2);
        encryptor.encrypt(pk, pt, ct);

        Plaintext dec_pt(ctx);
        decryptor.decrypt(sk, ct, dec_pt);

        std::vector<double> v2;
        encoder.decode(dec_pt, v2);
        v2.resize(v.size());
        std::cout << "v:  " << v[0] << ", " << v[1] << ", " << v[2] << "\n";
        std::cout << "v2: " << v2[0] << ", " << v2[1] << ", " << v2[2] << "\n";
        check_close(v, v2, 1e-2);
    }

    std::cout << "[OK] encrypt/decrypt repeated runs passed\n";
}