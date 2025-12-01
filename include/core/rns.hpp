#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ckks::core {

/// Single RNS modulus with NTT precomputation
struct RNSModulus {
  std::uint64_t q = 0;          ///< modulus
  std::uint64_t root = 0;       ///< primitive 2N-th root of unity mod q
  std::uint64_t root_inv = 0;   ///< inverse of root mod q
  std::uint64_t n_inv = 0;      ///< N^{-1} mod q

  std::vector<std::uint64_t> twiddle;      ///< forward NTT table
  std::vector<std::uint64_t> twiddle_inv;  ///< inverse NTT table
};

/// RNS context: modulus chain + N
/// After construction, each modulus contains NTT tables.
class RNSContext {
public:
  RNSContext() = default;

  /// Construct from degree N and moduli qi.
  /// Implementation will compute NTT-friendly roots for each q_i.
  RNSContext(std::size_t N, const std::vector<std::uint64_t>& qi);

  std::size_t degree() const noexcept { return N_; }
  std::size_t num_moduli() const noexcept { return moduli_.size(); }

  const std::vector<RNSModulus>& moduli() const noexcept { return moduli_; }
  const RNSModulus& modulus(std::size_t i) const noexcept { return moduli_[i]; }

private:
  std::size_t N_ = 0;
  std::vector<RNSModulus> moduli_;
};

/// Utility: modular multiplication (a * b) mod q
std::uint64_t mul_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q);

/// Utility: modular exponentiation base^exp mod q
std::uint64_t pow_mod(std::uint64_t base, std::uint64_t exp, std::uint64_t q);

/// Utility: modular inverse of a mod q (assuming q is prime)
std::uint64_t inv_mod(std::uint64_t a, std::uint64_t q);

/// Precompute NTT twiddle tables for modulus q
void compute_twiddle_tables(
    std::uint64_t q,
    std::uint64_t root,
    std::uint64_t root_inv,
    std::size_t N,
    std::vector<std::uint64_t>& tw,
    std::vector<std::uint64_t>& tw_inv);

} // namespace ckks::core
