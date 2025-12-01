#include "core/rns.hpp"
#include <stdexcept>

namespace ckks::core {

// ====================== low-level modular arithmetic ====================== //

static std::uint64_t mul_mod_128(std::uint64_t a,
                                 std::uint64_t b,
                                 std::uint64_t q) {
  // Reference implementation using 128-bit intermediate.
  __uint128_t prod = static_cast<__uint128_t>(a) * b;
  return static_cast<std::uint64_t>(prod % q);
}

std::uint64_t mul_mod(std::uint64_t a,
                      std::uint64_t b,
                      std::uint64_t q) {
  return mul_mod_128(a, b, q);
}

std::uint64_t pow_mod(std::uint64_t base,
                      std::uint64_t exp,
                      std::uint64_t q) {
  std::uint64_t res = 1;
  base %= q;
  while (exp > 0) {
    if (exp & 1ULL) {
      res = mul_mod(res, base, q);
    }
    base = mul_mod(base, base, q);
    exp >>= 1ULL;
  }
  return res;
}

std::uint64_t inv_mod(std::uint64_t a, std::uint64_t q) {
  if (a == 0 || q <= 2) {
    throw std::invalid_argument("inv_mod: invalid arguments");
  }
  // assuming q is prime, use Fermat's little theorem: a^{q-2} mod q
  return pow_mod(a, q - 2, q);
}

// ====================== NTT root utilities ====================== //

/// Find a primitive 2N-th root of unity modulo q.
/// q should be of the form k * 2N + 1 (and prime).
static std::uint64_t find_root_2N(std::size_t N, std::uint64_t q) {
  const std::uint64_t order = static_cast<std::uint64_t>(2 * N);
  const std::uint64_t phi   = q - 1; // for prime q

  if (phi % order != 0) {
    throw std::runtime_error("find_root_2N: q-1 not divisible by 2N");
  }

  std::uint64_t exponent = phi / order;

  // naive search for a generator g, then w = g^exponent
  for (std::uint64_t g = 2; g < q; ++g) {
    std::uint64_t w   = pow_mod(g, exponent, q);
    std::uint64_t w2N = pow_mod(w, order, q);
    if (w2N != 1) continue;
    std::uint64_t wN = pow_mod(w, N, q);
    if (wN == 1) continue; // order too small
    return w;
  }

  throw std::runtime_error("find_root_2N: failed to find primitive 2N-th root");
}

// ====================== RNSContext implementation ====================== //

RNSContext::RNSContext(std::size_t N,
                       const std::vector<std::uint64_t>& qi)
  : N_(N) {
  if (N == 0 || (N & (N - 1)) != 0) {
    throw std::invalid_argument("RNSContext: N must be a power of 2");
  }
  if (qi.empty()) {
    throw std::invalid_argument("RNSContext: need at least one modulus");
  }

  moduli_.resize(qi.size());

  for (std::size_t i = 0; i < qi.size(); ++i) {
    std::uint64_t q = qi[i];

    RNSModulus m;
    m.q = q;

    // For production, you should ensure q is prime and q = k * 2N + 1.
    m.root     = find_root_2N(N_, q);
    m.root_inv = inv_mod(m.root, q);
    m.n_inv    = inv_mod(static_cast<std::uint64_t>(N_), q);

    // Precompute NTT twiddle tables (forward and inverse)
    m.twiddle.clear();
    m.twiddle_inv.clear();
    m.twiddle.resize(N_);
    m.twiddle_inv.resize(N_);

    compute_twiddle_tables(
        m.q,
        m.root,
        m.root_inv,
        N_,
        m.twiddle,
        m.twiddle_inv
    );

    moduli_[i] = std::move(m);
  }
}

} // namespace ckks::core
