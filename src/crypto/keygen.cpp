#include "crypto/keygen.hpp"
#include "core/poly.hpp"

#include <random>
#include <cmath>
#include <cassert>

namespace ckks::crypto {

// -----------------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------------
KeyGenerator::KeyGenerator(const ckks::CKKSContext& ctx,
                           std::uint64_t seed)
  : ctx_(&ctx)
{
    if (seed == 0) {
        std::random_device rd;
        rng_.seed(rd());
    } else {
        rng_.seed(seed);
    }
}

// -----------------------------------------------------------------------------
// Resize a PolyRNS to full modulus chain (N, L)
// -----------------------------------------------------------------------------
void KeyGenerator::resize_poly_top(core::PolyRNS& out) {
    const auto& p   = ctx_->params();
    const auto& rns = ctx_->rns();

    std::size_t N   = p.N;
    std::size_t L   = rns.num_moduli();

    out = core::PolyRNS(N, L);
}

// -----------------------------------------------------------------------------
// Sample secret key coefficients in {-1, 0, 1}
// -----------------------------------------------------------------------------
void KeyGenerator::sample_secret_ternary(core::PolyRNS& out) {
    resize_poly_top(out);

    std::uniform_int_distribution<int> dist(0, 2);
    const auto& qi = ctx_->params().qi;
    std::size_t N  = ctx_->params().N;

    for (std::size_t j = 0; j < out.num_moduli(); j++) {
        uint64_t q = qi[j];
        auto& coeffs = out[j];

        for (std::size_t i = 0; i < N; i++) {
            int r = dist(rng_);   // 0,1,2
            int v = (r == 0 ? -1 : (r == 1 ? 0 : 1));

            // map to modulo q:
            if (v < 0) coeffs[i] = q - 1;  // -1 mod q
            else coeffs[i] = (uint64_t)v;
        }
    }
}

// -----------------------------------------------------------------------------
// Sample small error polynomial using discrete Gaussian
// -----------------------------------------------------------------------------
void KeyGenerator::sample_error(core::PolyRNS& out, double sigma) {
    resize_poly_top(out);

    std::normal_distribution<double> gauss(0.0, sigma);

    const auto& qi = ctx_->params().qi;
    std::size_t N  = ctx_->params().N;

    for (std::size_t j = 0; j < out.num_moduli(); j++) {
        uint64_t q = qi[j];
        auto& coeffs = out[j];

        for (std::size_t i = 0; i < N; i++) {
            double x = gauss(rng_);
            long long v = llround(x);
            // reduce mod q
            long long r = v % (long long)q;
            if (r < 0) r += q;
            coeffs[i] = (uint64_t)r;
        }
    }
}

// -----------------------------------------------------------------------------
// Sample uniform polynomial modulo Q
// -----------------------------------------------------------------------------
void KeyGenerator::sample_uniform(core::PolyRNS& out) {
    resize_poly_top(out);

    const auto& qi = ctx_->params().qi;
    std::size_t N  = ctx_->params().N;

    for (std::size_t j = 0; j < out.num_moduli(); j++) {
        uint64_t q = qi[j];
        std::uniform_int_distribution<uint64_t> dist(0, q - 1);

        auto& coeffs = out[j];
        for (std::size_t i = 0; i < N; i++) {
            coeffs[i] = dist(rng_);
        }
    }
}

// -----------------------------------------------------------------------------
// Generate secret key s(x)
// -----------------------------------------------------------------------------
SecretKey KeyGenerator::generate_secret_key() {
    SecretKey sk(*ctx_);
    sample_secret_ternary(sk.poly);

    sk.level = (int)sk.poly.num_moduli() - 1;
    sk.is_ntt = false;

    return sk;
}

// -----------------------------------------------------------------------------
// Generate public key (a, b = -a*s + e)
// -----------------------------------------------------------------------------
PublicKey KeyGenerator::generate_public_key(const SecretKey& sk) {
    PublicKey pk(*ctx_);

    // a <- uniform
    sample_uniform(pk.a);

    // e <- small noise
    core::PolyRNS e;
    sample_error(e, /* sigma */ 3.2);

    // b = -a*s + e (mod Q)
    const auto& ctx = *ctx_;
    const auto& rns = ctx.rns();
    const auto& qi  = ctx.params().qi;

    std::size_t N = ctx.params().N;
    std::size_t L = rns.num_moduli();

    // Resize pk.b
    resize_poly_top(pk.b);

    // Compute b = -a*s + e mod each qi
    for (std::size_t j = 0; j < L; j++) {
        uint64_t q = qi[j];
        auto& bj   = pk.b[j];
        const auto& aj = pk.a[j];
        const auto& sj = sk.poly[j];
        const auto& ej = e[j];

        for (std::size_t i = 0; i < N; i++) {
            __int128 term = (__int128)aj[i] * (__int128)sj[i];  // a*s
            term %= q;

            // b = e - a*s
            __int128 v = (__int128)ej[i] - term;
            v %= q;
            if (v < 0) v += q;

            bj[i] = (uint64_t)v;
        }
    }

    pk.level = (int)L - 1;
    pk.is_ntt = false;

    return pk;
}

// -----------------------------------------------------------------------------
// Stubs for now (Phase 6 will implement real versions)
// -----------------------------------------------------------------------------

RelinKey KeyGenerator::generate_relin_key(const SecretKey& sk) {
    RelinKey rk(*ctx_);
    // For now: empty dummy -- proper version in Phase 6
    return rk;
}

GaloisKeys KeyGenerator::generate_galois_keys(const SecretKey& sk,
                                              const std::vector<int>& steps)
{
    GaloisKeys out;
    // For now: empty -- Phase 6 will implement this
    return out;
}

} // namespace ckks::crypto
