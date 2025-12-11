#include "crypto/keygen.hpp"
#include "core/poly.hpp"

#include <random>
#include <cmath>
#include <cassert>
#include <stdexcept>

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
void KeyGenerator::resize_poly_top(core::PolyRNS& out) const{
    const auto& p   = ctx_->params();
    const auto& rns = ctx_->rns();

    std::size_t N   = p.N();
    std::size_t L   = rns.num_moduli();

    out = core::PolyRNS(N, L);
}

// -----------------------------------------------------------------------------
// Sample secret key coefficients in {-1, 0, 1}
// -----------------------------------------------------------------------------
void KeyGenerator::sample_secret_ternary(core::PolyRNS& out) {
    resize_poly_top(out);

    std::uniform_int_distribution<int> dist(0, 2);
    const auto& qi = ctx_->params().qi();
    std::size_t N  = ctx_->params().N();

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
void KeyGenerator::sample_error(core::PolyRNS& out, double sigma) const {
    resize_poly_top(out);

    std::normal_distribution<double> gauss(0.0, sigma);

    const auto& qi = ctx_->params().qi();
    std::size_t N  = ctx_->params().N();

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
void KeyGenerator::sample_uniform(core::PolyRNS& out) const {
    resize_poly_top(out);

    const auto& qi = ctx_->params().qi();
    std::size_t N  = ctx_->params().N();

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
    const auto& qi  = ctx.params().qi();

    std::size_t N = ctx.params().N();
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

RelinKey KeyGenerator::generate_relin_key(const SecretKey& sk) {
    const auto& ctx = *ctx_;
    const auto& rns = ctx.rns();
    const auto& qi  = ctx.params().qi();

    std::size_t N = ctx.params().N();
    std::size_t L = rns.num_moduli();

    // 1) Compute s^2 via NTT
    core::PolyRNS s_ntt = sk.poly;
    poly_to_ntt(s_ntt, rns);

    core::PolyRNS s2_ntt(N, L);
    poly_pointwise_mul(s2_ntt, s_ntt, s_ntt, rns);

    core::PolyRNS s2(N, L);
    poly_from_ntt(s2_ntt, rns);

    // 2) Construct RelinKey at top level
    RelinKey rk(*ctx_);
    rk.level = sk.level;
    rk.is_ntt = false;

    // 3) Sample a uniform a
    sample_uniform(rk.a);

    // 4) Sample error e
    core::PolyRNS e;
    sample_error(e, /*sigma=*/3.2);

    // 5) Compute prod = a * s (via NTT)
    core::PolyRNS a_ntt = rk.a;
    core::PolyRNS s_ntt2 = sk.poly;
    poly_to_ntt(a_ntt, rns);
    poly_to_ntt(s_ntt2, rns);

    core::PolyRNS prod_ntt(N, L);
    poly_pointwise_mul(prod_ntt, a_ntt, s_ntt2, rns);

    core::PolyRNS prod(N, L);
    poly_from_ntt(prod_ntt, rns);

    // 6) b = s^2 + e - prod  (mod qi)
    rk.b = core::PolyRNS(N, L);

    for (std::size_t j = 0; j < L; ++j) {
        std::uint64_t q = qi[j];
        auto& bj        = rk.b[j];
        const auto& s2j = s2[j];
        const auto& ej  = e[j];
        const auto& pj  = prod[j];

        for (std::size_t i = 0; i < N; ++i) {
            __int128 v = (__int128)s2j[i] + (__int128)ej[i] - (__int128)pj[i];
            v %= q;
            if (v < 0) v += q;
            bj[i] = (std::uint64_t)v;
        }
    }

    return rk;
}


GaloisKey KeyGenerator::generate_galois_key(const SecretKey& sk,
                                            int galois_elt) const
{
  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi();

  std::size_t N = ctx.params().N();
  std::size_t L = rns.num_moduli();

  // 1) s_sigma = σ_g(s)
  core::PolyRNS s_sigma;
  poly_apply_galois(s_sigma, sk.poly, N,
                    static_cast<std::uint64_t>(galois_elt),
                    rns);

  // 2) Initialize GaloisKey
  GaloisKey gk(ctx, galois_elt);
  gk.level = sk.level;
  gk.is_ntt = false;

  // 3) Sample uniform a
  sample_uniform(gk.a);

  // 4) Sample error e
  core::PolyRNS e;
  sample_error(e, /*sigma=*/3.2);

  // 5) prod = a * s via NTT
  core::PolyRNS a_ntt  = gk.a;
  core::PolyRNS s_ntt  = sk.poly;
  poly_to_ntt(a_ntt, rns);
  poly_to_ntt(s_ntt, rns);

  core::PolyRNS prod_ntt(N, L);
  poly_pointwise_mul(prod_ntt, a_ntt, s_ntt, rns);

  core::PolyRNS prod(N, L);
  poly_from_ntt(prod_ntt, rns);

  // 6) b = s_sigma + e - prod (mod qi)
  gk.b = core::PolyRNS(N, L);

  for (std::size_t j = 0; j < L; ++j) {
    std::uint64_t q = qi[j];
    auto&          bj     = gk.b[j];
    const auto&    sSj    = s_sigma[j];
    const auto&    ej     = e[j];
    const auto&    pj     = prod[j];

    for (std::size_t i = 0; i < N; ++i) {
      __int128 v = (__int128)sSj[i] + (__int128)ej[i] - (__int128)pj[i];
      v %= q;
      if (v < 0) v += q;
      bj[i] = (std::uint64_t)v;
    }
  }

  return gk;
}

GaloisKey KeyGenerator::generate_conjugation_key(const SecretKey& sk) const
{
  std::size_t N = ctx_->params().N();
  int g = static_cast<int>(2 * N - 1); // X -> X^{-1} mod 2N
  return generate_galois_key(sk, g);
}

// small modular exponentiation helper for modulus up to 2N
static std::uint64_t pow_mod_uint(std::uint64_t base,
                                  std::uint64_t exp,
                                  std::uint64_t mod)
{
  std::uint64_t res = 1;
  base %= mod;
  while (exp > 0) {
    if (exp & 1) {
      res = (res * base) % mod;
    }
    base = (base * base) % mod;
    exp >>= 1;
  }
  return res;
}

GaloisKey KeyGenerator::generate_rotation_key(const SecretKey& sk,
                                              int step) const
{
  const auto& ctx    = *ctx_;
  const auto& params = ctx.params();

  std::size_t N       = params.N();
  std::size_t slots   = params.slots();  // N/2
  std::size_t M       = 2 * N;             // cyclotomic index

  if (slots == 0) {
    throw std::runtime_error("generate_rotation_key: invalid slots (N=0?).");
  }

  // normalize step into [0, slots)
  int s = step % static_cast<int>(slots);
  if (s < 0) {
    s += static_cast<int>(slots);
  }

  if (s == 0) {
    // rotation by 0 -> identity -> galois_elt = 1
    return generate_galois_key(sk, 1);
  }

  // CKKS standard generator for the slot group: g = 5
  std::uint64_t g = 5;
  std::uint64_t e = pow_mod_uint(g, static_cast<std::uint64_t>(s),
                                 static_cast<std::uint64_t>(M));

  // e should be odd and lie in (Z/2N Z)*.
  if ((e & 1u) == 0u) {
    throw std::runtime_error("generate_rotation_key: computed even galois_elt.");
  }

  return generate_galois_key(sk, static_cast<int>(e));
}


} // namespace ckks::crypto
