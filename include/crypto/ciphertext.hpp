#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "ckks.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// CKKS ciphertext:
/// Internally stores up to 3 polynomials:
///   - fresh ciphertexts:    poly_count = 2 (c0, c1)
///   - after mul (pre-relin): poly_count = 3 (c0, c1, c2)
/// We always allocate 3 slots for performance & simplicity.
struct Ciphertext {
  std::array<core::PolyRNS, 3> polys;
  int           poly_count = 0;     ///< 2 or 3
  double        scale      = 1.0;
  int           level      = 0;     ///< index into modulus chain (0..L)
  bool          is_ntt     = false; ///< are all polys in NTT domain?
  std::size_t   num_slots  = 0;     ///< usually N/2

  Ciphertext() = default;

  /// Construct a ciphertext with given number of polys (2 or 3),
  /// at the top level, using CKKSContext parameters.
  explicit Ciphertext(const ckks::CKKSContext& ctx,
                      int poly_count = 2);

  /// Number of active polys (2 or 3).
  std::size_t size() const noexcept { return static_cast<std::size_t>(poly_count); }

  core::PolyRNS&       operator[](std::size_t i)       { return polys[i]; }
  const core::PolyRNS& operator[](std::size_t i) const { return polys[i]; }

  core::PolyRNS& c0()       { return polys[0]; }
  core::PolyRNS& c1()       { return polys[1]; }
  core::PolyRNS& c2()       { return polys[2]; }

  const core::PolyRNS& c0() const { return polys[0]; }
  const core::PolyRNS& c1() const { return polys[1]; }
  const core::PolyRNS& c2() const { return polys[2]; }

  /// Reinitialize internal polynomials to match the CKKSContext,
  /// with new_poly_count = 2 or 3.
  void resize_like(const ckks::CKKSContext& ctx, int new_poly_count);

  /// Basic structural check (degree & num_moduli) against the context.
  bool is_valid(const ckks::CKKSContext& ctx) const noexcept;
};

} // namespace ckks::crypto
