#include <iostream>
#include <vector>
#include <random>
#include <cassert>

#include "core/rns.hpp"
#include "core/ntt.hpp"
#include "core/poly.hpp"

using namespace ckks::core;

static std::mt19937_64 rng(123456);

static std::uint64_t rand_mod(std::uint64_t q) {
    std::uniform_int_distribution<std::uint64_t> dist(0, q - 1);
    return dist(rng);
}

/// Naive polynomial multiplication (non-NTT) for correctness tests.
/// Computes (a * b) mod (x^N + 1), mod qi.
/// Only works for a single modulus (small N for test).
static std::vector<std::uint64_t>
naive_mul(const std::vector<std::uint64_t>& a,
          const std::vector<std::uint64_t>& b,
          std::uint64_t q)
{
    std::size_t N = a.size();
    std::vector<std::uint64_t> out(N, 0);

    for (std::size_t i = 0; i < N; ++i) {
        for (std::size_t j = 0; j < N; ++j) {
            std::size_t k = i + j;
            std::uint64_t term = (__uint128_t)a[i] * b[j] % q;

            if (k < N) {
                out[k] += term;
            } else {
                // wrap around with negation (x^N = -1)
                out[k - N] += (q - term);
            }
        }
    }

    for (auto& v : out) {
        if (v >= q) v %= q;
    }
    return out;
}

void test_poly_add_sub_scalar()
{
    std::size_t N = 16;
    std::vector<std::uint64_t> qs = { 97, 193 };
    RNSContext ctx(N, qs);

    PolyRNS a(N, qs.size());
    PolyRNS b(N, qs.size());
    PolyRNS out(N, qs.size());
    PolyRNS check(N, qs.size());

    // randomize a and b
    for (std::size_t m = 0; m < qs.size(); ++m) {
        for (std::size_t i = 0; i < N; ++i) {
            a[m][i] = rand_mod(qs[m]);
            b[m][i] = rand_mod(qs[m]);
        }
    }

    // add -> check
    poly_add(out, a, b, ctx);
    for (std::size_t m = 0; m < qs.size(); ++m) {
        auto q = qs[m];
        for (std::size_t i = 0; i < N; ++i) {
            std::uint64_t expect = a[m][i] + b[m][i];
            if (expect >= q) expect -= q;
            assert(out[m][i] == expect);
        }
    }

    // sub -> check
    poly_sub(out, a, b, ctx);
    for (std::size_t m = 0; m < qs.size(); ++m) {
        auto q = qs[m];
        for (std::size_t i = 0; i < N; ++i) {
            std::uint64_t expect = a[m][i] + q - b[m][i];
            if (expect >= q) expect -= q;
            assert(out[m][i] == expect);
        }
    }

    // negate
    poly_negate(out, a, ctx);
    for (std::size_t m = 0; m < qs.size(); ++m) {
        auto q = qs[m];
        for (std::size_t i = 0; i < N; ++i) {
            std::uint64_t expect = (a[m][i] == 0 ? 0 : q - a[m][i]);
            assert(out[m][i] == expect);
        }
    }

    // scalar mul
    std::uint64_t c = 7;
    poly_scalar_mul(out, a, c, ctx);
    for (std::size_t m = 0; m < qs.size(); ++m) {
        auto q = qs[m];
        for (std::size_t i = 0; i < N; ++i) {
            std::uint64_t expect = (__uint128_t)a[m][i] * c % q;
            assert(out[m][i] == expect);
        }
    }

    std::cout << "[OK] poly add/sub/neg/scalar tests passed\n";
}

void test_ntt_roundtrip_all_moduli()
{
    std::size_t N = 16;
    std::vector<std::uint64_t> qs = { 97, 193 };
    RNSContext ctx(N, qs);

    PolyRNS p(N, qs.size());
    PolyRNS orig(N, qs.size());

    // randomize
    for (std::size_t m = 0; m < qs.size(); ++m) {
        for (std::size_t i = 0; i < N; ++i) {
            orig[m][i] = rand_mod(qs[m]);
            p[m][i]    = orig[m][i];
        }
    }

    poly_to_ntt(p, ctx);
    poly_from_ntt(p, ctx);

    // check recovery
    for (std::size_t m = 0; m < qs.size(); ++m) {
        for (std::size_t i = 0; i < N; ++i) {
            assert(p[m][i] == orig[m][i]);
        }
    }

    std::cout << "[OK] poly NTT roundtrip tests passed\n";
}

void test_ntt_convolution()
{
    // small N so naive convolution is cheap
    std::size_t N = 16;
    std::vector<std::uint64_t> qs = { 193 };  // simple prime q = k*2N+1

    RNSContext ctx(N, qs);
    std::uint64_t q = qs[0];

    PolyRNS a(N, 1);
    PolyRNS b(N, 1);
    PolyRNS c(N, 1);

    // randomize a and b
    for (std::size_t i = 0; i < N; ++i) {
        a[0][i] = rand_mod(q);
        b[0][i] = rand_mod(q);
    }

    // compute c = a * b via NTT
    poly_to_ntt(a, ctx);
    poly_to_ntt(b, ctx);
    poly_pointwise_mul(c, a, b, ctx);
    poly_from_ntt(c, ctx);

    // naive for comparison
    PolyRNS expected(N, 1);
    expected[0] = naive_mul(a[0], b[0], q);

    // compare
    for (std::size_t i = 0; i < N; ++i) {
        assert(c[0][i] == expected[0][i]);
    }

    std::cout << "[OK] poly NTT convolution tests passed\n";
}
