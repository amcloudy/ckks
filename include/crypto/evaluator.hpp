#pragma once

#include "ckks.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/keys.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// CKKS evaluator for basic linear operations:
///  - ciphertext + ciphertext
///  - ciphertext - ciphertext
///  - -ciphertext
///  - ciphertext + plaintext
///
/// Nonlinear ops (mul, rescale, rotations, etc.) will be added later.
class Evaluator {
public:
  explicit Evaluator(const ckks::CKKSContext& ctx)
    : ctx_(&ctx)
  {}

  const ckks::CKKSContext& context() const noexcept { return *ctx_; }

  // --- Ciphertext + Ciphertext ---

  void add(const Ciphertext& a,
           const Ciphertext& b,
           Ciphertext& out) const;

  Ciphertext add(const Ciphertext& a,
                 const Ciphertext& b) const;

  void sub(const Ciphertext& a,
           const Ciphertext& b,
           Ciphertext& out) const;

  Ciphertext sub(const Ciphertext& a,
                 const Ciphertext& b) const;

  void negate(const Ciphertext& a,
              Ciphertext& out) const;

  Ciphertext negate(const Ciphertext& a) const;

  // --- Ciphertext + Plaintext (added to c0 only) ---

  void add_plain(const Ciphertext& ct,
                 const Plaintext& pt,
                 Ciphertext& out) const;

  Ciphertext add_plain(const Ciphertext& ct,
                       const Plaintext& pt) const;

    // --- Ciphertext × Ciphertext (raw, no relinearization) ---

  // a,b must have poly_count = 2. Output has poly_count = 3.
  void multiply_raw(const Ciphertext& a,
                    const Ciphertext& b,
                    Ciphertext& out) const;

  Ciphertext multiply_raw(const Ciphertext& a,
                          const Ciphertext& b) const;

  // --- Relinearization: 3-poly → 2-poly using RelinKey ---

  void relinearize(const Ciphertext& ct3,
                   const RelinKey& rlk,
                   Ciphertext& out) const;

  Ciphertext relinearize(const Ciphertext& ct3,
                         const RelinKey& rlk) const;

  // --- Multiply + Relinearize convenience ---

  void multiply_relinearize(const Ciphertext& a,
                            const Ciphertext& b,
                            const RelinKey& rlk,
                            Ciphertext& out) const;

  Ciphertext multiply_relinearize(const Ciphertext& a,
                                  const Ciphertext& b,
                                  const RelinKey& rlk) const;

  // --- Rescale (drop last modulus, scale /= q_last) ---

  /// Rescale ciphertext to the next level (drop the last prime q_L).
  /// Requires:
  ///  - in.is_ntt == false
  ///  - in.level > 0
  void rescale_to_next(const Ciphertext& in,
                       Ciphertext& out) const;

  Ciphertext rescale_to_next(const Ciphertext& in) const;

    // --- Galois / Rotations (generic automorphism) ---

  /// Apply automorphism X -> X^{gk.galois_elt} using GaloisKey (keyswitch).
  /// Result is a 2-poly ciphertext under the original secret key.
  void apply_galois(const Ciphertext& in,
                    const GaloisKey& gk,
                    Ciphertext& out) const;

  Ciphertext apply_galois(const Ciphertext& in,
                          const GaloisKey& gk) const;

    // --- Slot rotations (built on Galois apply) ---

  /// Rotate slots using a rotation Galois key (produced for some step).
  /// This is a thin wrapper around apply_galois.
  void rotate(const Ciphertext& in,
              const GaloisKey& rot_key,
              Ciphertext& out) const;

  Ciphertext rotate(const Ciphertext& in,
                    const GaloisKey& rot_key) const;


private:
  const ckks::CKKSContext* ctx_;
};

} // namespace ckks::crypto
