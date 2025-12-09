#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <cmath>

#include "crypto/ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/plaintext.hpp"

static std::mt19937_64 rng_enc(123456);

static double rand_real() {
    std::uniform_real_distribution<double> dist(-5.0, 5.0);
    return dist(rng_enc);
}

/// Compare two vectors of doubles with tolerance.
static void assert_close(const std::vector<double>& a,
                         const std::vector<double>& b,
                         double tol = 1e-6)
{
    assert(a.size() == b.size());
    for (std::size_t i = 0; i < a.size(); i++) {
        double diff = std::fabs(a[i] - b[i]);
        if (diff > tol) {
            std::cerr << "Mismatch at index " << i
                      << ": " << a[i] << " vs " << b[i]
                      << " (diff = " << diff << ")\n";
            assert(false && "Vectors differ beyond tolerance");
        }
    }
}

void test_encoder_basic_small_N()
{
    std::size_t N = 16;                    // tiny ring
    std::vector<uint64_t> qi = { 193, 257 }; // small primes
    int log_scale = 20;
    int depth = qi.size() - 1;

    ckks::CKKSParams params(N, qi, log_scale, depth);
    ckks::CKKSContext ctx(params);

    ckks::crypto::Encoder encoder(ctx);

    // One simple input
    std::vector<double> input = {1.2345, -2.5, 0.75};
    double scale = params.default_scale;
    int level = depth;

    auto pt = encoder.encode(input, scale, level);
    auto output = encoder.decode(pt);

    // Only compare first input.size() entries
    output.resize(input.size());

    assert_close(input, output, 1e-5);

    std::cout << "[OK] encoder basic small-N test passed\n";
}

void test_encoder_random_full_slots()
{
    std::size_t N = 32;                     // small but bigger
    std::vector<uint64_t> qi = { 193, 257, 769 };
    int log_scale = 30;
    int depth = qi.size() - 1;

    ckks::CKKSParams params(N, qi, log_scale, depth);
    ckks::CKKSContext ctx(params);
    ckks::crypto::Encoder encoder(ctx);

    std::size_t slots = params.num_slots;   // N/2
    std::vector<double> input(slots);

    for (std::size_t i = 0; i < slots; i++)
        input[i] = rand_real();

    double scale = params.default_scale;

    auto pt = encoder.encode(input, scale, depth);
    auto out = encoder.decode(pt);

    out.resize(slots);
    assert_close(input, out, 1e-4);

    std::cout << "[OK] encoder random full-slot test passed\n";
}

void test_encoder_multiple_levels()
{
    std::size_t N = 32;
    std::vector<uint64_t> qi = { 193, 257, 769 };
    int log_scale = 25;
    int depth = qi.size() - 1;

    ckks::CKKSParams params(N, qi, log_scale, depth);
    ckks::CKKSContext ctx(params);
    ckks::crypto::Encoder encoder(ctx);

    std::vector<double> input = {0.5, -1.0, 3.14159};
    double scale = params.default_scale;

    for (int lvl = depth; lvl >= 0; lvl--) {
        auto pt = encoder.encode(input, scale, lvl);
        auto out = encoder.decode(pt);
        out.resize(input.size());
        assert_close(input, out, 1e-5);
    }

    std::cout << "[OK] encoder multi-level test passed\n";
}

void test_encoder_edge_values()
{
    std::size_t N = 32;
    std::vector<uint64_t> qi = { 193, 257, 769 };
    int log_scale = 25;
    int depth = qi.size() - 1;

    ckks::CKKSParams params(N, qi, log_scale, depth);
    ckks::CKKSContext ctx(params);
    ckks::crypto::Encoder encoder(ctx);

    // Test values near boundaries
    std::vector<double> input = {
        0.0,
        1.0,
        -1.0,
        1e-3,
        -1e-3,
        params.default_scale / 10.0,
        -params.default_scale / 10.0
    };

    auto pt = encoder.encode(input, params.default_scale, depth);
    auto out = encoder.decode(pt);
    out.resize(input.size());

    assert_close(input, out, 1e-4);

    std::cout << "[OK] encoder edge-value test passed\n";
}
