#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ckks.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// CKKS plaintext:
/// - poly: polynomial in RNS representation
/// - scale: approximate scaling factor (Δ)
/// - level: index into the modulus chain (0..L)
/// - is_ntt: whether poly is in NTT domain
/// - num_slots: usable slots (typically N/2)
struct Plaintext {
  core::PolyRNS poly;
  double        scale      = 1.0;
  int           level      = 0;
  bool          is_ntt     = false;
  std::size_t   num_slots  = 0;

  Plaintext() = default;

  /// Construct an "empty" plaintext at the top level using CKKSContext.
  explicit Plaintext(const ckks::CKKSContext& ctx);

  std::size_t N() const noexcept { return poly.degree(); }

  bool empty() const noexcept {
    return poly.degree() == 0 || poly.num_moduli() == 0;
  }
};

} // namespace ckks::crypto
