#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "core/rns.hpp"

namespace ckks::core {

/// RNS polynomial: modulus-major layout.
/// data[mod_index][coeff_index], with coeff_index in [0, N).
struct PolyRNS {
  std::size_t N = 0;  ///< ring degree
  std::vector<std::vector<std::uint64_t>> data;

  PolyRNS() = default;

  PolyRNS(std::size_t N_, std::size_t num_moduli)
      : N(N_), data(num_moduli, std::vector<std::uint64_t>(N_)) {}

  std::size_t degree() const noexcept { return N; }
  std::size_t num_moduli() const noexcept { return data.size(); }

  std::vector<std::uint64_t>& operator[](std::size_t i) noexcept {
    return data[i];
  }

  const std::vector<std::uint64_t>& operator[](std::size_t i) const noexcept {
    return data[i];
  }
};

/// Add two RNS polynomials modulo each qi: out = a + b (mod qi)
void poly_add(PolyRNS& out,
              const PolyRNS& a,
              const PolyRNS& b,
              const RNSContext& ctx);

/// Subtract two RNS polynomials modulo each qi: out = a - b (mod qi)
void poly_sub(PolyRNS& out,
              const PolyRNS& a,
              const PolyRNS& b,
              const RNSContext& ctx);

/// Negate an RNS polynomial: out = -a (mod qi)
void poly_negate(PolyRNS& out,
                 const PolyRNS& a,
                 const RNSContext& ctx);

/// Multiply an RNS polynomial by a scalar modulo each qi: out = c * a (mod qi)
void poly_scalar_mul(PolyRNS& out,
                     const PolyRNS& a,
                     std::uint64_t c,
                     const RNSContext& ctx);

/// Convert polynomial to NTT domain (for all moduli).
void poly_to_ntt(PolyRNS& p, const RNSContext& ctx);

/// Convert polynomial from NTT domain (for all moduli).
void poly_from_ntt(PolyRNS& p, const RNSContext& ctx);

/// Pointwise multiplication in NTT domain: out = a ⊙ b (mod qi)
/// Assumes a and b are already in NTT domain.
void poly_pointwise_mul(PolyRNS& out,
                        const PolyRNS& a,
                        const PolyRNS& b,
                        const RNSContext& ctx);

} // namespace ckks::core
