#include <iostream>
#include <cassert>
#include <vector>
#include <cmath>

#include "ckks.hpp"
#include "crypto/keygen.hpp"
#include "crypto/keys.hpp"

using namespace ckks;
using namespace ckks::crypto;
using namespace ckks::core;

// -----------------------------------------------------------------------------
// Utility: test if x mod q is in {-1, 0, 1}
// -----------------------------------------------------------------------------
static bool is_ternary(uint64_t v, uint64_t q)
{
    if (v == 0) return true;     // 0 mod q
    if (v == 1) return true;     // +1
    if (v == q - 1) return true; // -1 mod q
    return false;
}

// -----------------------------------------------------------------------------
// Test 1: Secret key coefficients are small (ternary)
// -----------------------------------------------------------------------------
void test_secret_key_ternary()
{
    std::size_t N  = 16;
    std::vector<uint64_t> qi = {97, 193}; // valid for N=16
    int log_scale = 20;
    int depth     = qi.size() - 1;

    CKKSParams params(N, qi, log_scale, depth);
    CKKSContext ctx(params);

    KeyGenerator keygen(ctx, /*seed=*/12345);

    SecretKey sk = keygen.generate_secret_key();

    assert(sk.poly.degree() == N);
    assert(sk.poly.num_moduli() == qi.size());
    assert(sk.level == int(qi.size() - 1));
    assert(sk.is_ntt == false);

    for (std::size_t j = 0; j < qi.size(); j++) {
        uint64_t q = qi[j];
        for (std::size_t i = 0; i < N; i++) {
            assert(is_ternary(sk.poly[j][i], q));
        }
    }

    std::cout << "[OK] Secret key ternary test passed\n";
}

// -----------------------------------------------------------------------------
// Test 2: Deterministic RNG for secret key generation
// -----------------------------------------------------------------------------
void test_secret_key_deterministic()
{
    std::size_t N = 16;
    std::vector<uint64_t> qi = {97, 193};
    CKKSParams params(N, qi, 20, qi.size() - 1);
    CKKSContext ctx(params);

    KeyGenerator gen1(ctx, 999);
    KeyGenerator gen2(ctx, 999);
    KeyGenerator gen3(ctx, 777);

    SecretKey sk1 = gen1.generate_secret_key();
    SecretKey sk2 = gen2.generate_secret_key();
    SecretKey sk3 = gen3.generate_secret_key();

    // sk1 and sk2 must match exactly
    for (size_t j = 0; j < qi.size(); j++)
        for (size_t i = 0; i < N; i++)
            assert(sk1.poly[j][i] == sk2.poly[j][i]);

    // sk3 must differ (extremely likely)
    bool differs = false;
    for (size_t j = 0; j < qi.size(); j++)
        for (size_t i = 0; i < N; i++)
            if (sk1.poly[j][i] != sk3.poly[j][i])
                differs = true;

    assert(differs);

    std::cout << "[OK] Secret key deterministic RNG test passed\n";
}

// -----------------------------------------------------------------------------
// Test 3: Public key: check b + a*s ≈ error (small)
// -----------------------------------------------------------------------------
void test_public_key_relation()
{
    std::size_t N = 16;
    std::vector<uint64_t> qi = {97, 193};
    CKKSParams params(N, qi, 20, qi.size() - 1);
    CKKSContext ctx(params);

    KeyGenerator kg(ctx, 12345);

    SecretKey sk = kg.generate_secret_key();
    PublicKey pk = kg.generate_public_key(sk);

    const auto& a = pk.a;
    const auto& b = pk.b;
    const auto& s = sk.poly;

    assert(a.degree() == N && b.degree() == N);
    assert(a.num_moduli() == qi.size());
    assert(b.num_moduli() == qi.size());

    // Check b + a*s ≈ error
    for (size_t j = 0; j < qi.size(); j++) {
        uint64_t q = qi[j];
        for (size_t i = 0; i < N; i++) {
            // compute b + a*s mod q
            __int128 prod = (__int128)a[j][i] * (__int128)s[j][i];
            prod %= q;

            __int128 lhs = (__int128)b[j][i] + prod;
            lhs %= q;
            if (lhs < 0) lhs += q;

            // Expect lhs to be "small error": near 0 mod q
            // Since sigma = 3.2, error rarely exceeds ~10.
            // So deviation far from 0 or q indicates bug.
            long long val = (long long)lhs;
            if (val > (long long)q/2) val -= q; // center
            assert(std::llabs(val) < 20); // loose safety bound
        }
    }

    std::cout << "[OK] Public key relation test passed\n";
}

// -----------------------------------------------------------------------------
// Test 4: Public key has correct structure
// -----------------------------------------------------------------------------
void test_public_key_structure()
{
    std::size_t N = 32;
    // Only NTT-friendly primes for N=32 (mod 64 == 1)
    std::vector<uint64_t> qi = {193, 257, 769};
    CKKSParams params(N, qi, 20, qi.size() - 1);
    CKKSContext ctx(params);

    KeyGenerator kg(ctx, 54321);

    SecretKey sk = kg.generate_secret_key();
    PublicKey pk = kg.generate_public_key(sk);

    assert(pk.a.degree() == N);
    assert(pk.b.degree() == N);
    assert(pk.a.num_moduli() == qi.size());
    assert(pk.b.num_moduli() == qi.size());

    assert(pk.level == int(qi.size() - 1));
    assert(pk.is_ntt == false);

    std::cout << "[OK] Public key structure test passed\n";
}
