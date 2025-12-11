#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <cmath>

#include "crypto/ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/plaintext.hpp"

using namespace ckks;
using namespace ckks::core;
using namespace ckks::crypto;

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
    CKKSParams p;

    p.set_poly_degree(8192);
    p.set_depth(3);
    p.set_scale(40);
    p.set_security(core::SecurityLevel::SL128);

    CKKSContext ctx(p);

    ckks::crypto::Encoder encoder(ctx);

    // One simple input
    std::vector<double> input = {1.2345, -2.5, 0.75};


    auto pt = encoder.encode(input, p.log_scale(), p.depth());
    auto output = encoder.decode(pt);

    // Only compare first input.size() entries
    output.resize(input.size());

    assert_close(input, output, 1e-5);

    std::cout << "[OK] encoder basic small-N test passed\n";
}

void test_encoder_random_full_slots()
{
    CKKSParams p;

    p.set_poly_degree(8192);
    p.set_depth(3);
    p.set_scale(40);
    p.set_security(core::SecurityLevel::SL128);

    CKKSContext ctx(p);
    ckks::crypto::Encoder encoder(ctx);

    std::vector<double> input(p.slots());

    for (std::size_t i = 0; i < p.slots(); i++)
        input[i] = rand_real();

    auto pt = encoder.encode(input, p.log_scale(), p.depth());
    auto out = encoder.decode(pt);

    out.resize(p.slots());
    assert_close(input, out, 1e-4);

    std::cout << "[OK] encoder random full-slot test passed\n";
}

void test_encoder_multiple_levels()
{
    CKKSParams p;

    p.set_poly_degree(8192);
    p.set_depth(3);
    p.set_scale(40);
    p.set_security(core::SecurityLevel::SL128);

    CKKSContext ctx(p);
    ckks::crypto::Encoder encoder(ctx);

    std::vector<double> input = {0.5, -1.0, 3.14159};

    for (int lvl = p.depth(); lvl >= 0; lvl--) {
        auto pt = encoder.encode(input, p.log_scale(), lvl);
        auto out = encoder.decode(pt);
        out.resize(input.size());
        assert_close(input, out, 1e-5);
    }

    std::cout << "[OK] encoder multi-level test passed\n";
}

void test_encoder_edge_values()
{
    CKKSParams p;

    p.set_poly_degree(8192);
    p.set_depth(3);
    p.set_scale(40);
    p.set_security(core::SecurityLevel::SL128);

    CKKSContext ctx(p);
    ckks::crypto::Encoder encoder(ctx);

    // Test values near boundaries
    std::vector<double> input = {
        0.0,
        1.0,
        -1.0,
        1e-3,
        -1e-3,
        p.log_scale() / 10.0,
        -p.log_scale() / 10.0
    };

    auto pt = encoder.encode(input, p.log_scale(), p.depth());
    auto out = encoder.decode(pt);
    out.resize(input.size());

    assert_close(input, out, 1e-4);

    std::cout << "[OK] encoder edge-value test passed\n";
}
