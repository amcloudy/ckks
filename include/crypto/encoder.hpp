#pragma once

#include <cstddef>
#include <complex>
#include <vector>

#include "ckks.hpp"
#include "crypto/plaintext.hpp"

namespace ckks::crypto {

class Encoder {
public:
  explicit Encoder(const ckks::CKKSContext& context);

  std::size_t ring_dim() const noexcept { return N_; }
  std::size_t slot_count() const noexcept { return slots_; }

  // Encode to new plaintext
  Plaintext encode(const std::vector<double>& values,
                   double scale,
                   std::size_t level) const;

  // Encode into existing plaintext
  void encode(const std::vector<double>& values,
              double scale,
              std::size_t level,
              Plaintext& out) const;

  // Decode from plaintext → vector<double>
  std::vector<double> decode(const Plaintext& pt,
                             std::size_t max_slots = 0) const;

  void decode(const Plaintext& pt,
              std::vector<double>& out,
              std::size_t max_slots = 0) const;

private:
  const ckks::CKKSContext* ctx_;
  std::size_t N_;       // ring dimension
  std::size_t slots_;   // N/2

  // FFT helpers
  void fft_inplace(std::vector<std::complex<double>>& a) const;
  void ifft_inplace(std::vector<std::complex<double>>& a) const;

  // CKKS core encode/decode
  void ckks_encode_complex(const std::vector<std::complex<double>>& slots,
                           double scale,
                           std::size_t level,
                           Plaintext& out) const;

  void ckks_decode_complex(const Plaintext& pt,
                           std::vector<std::complex<double>>& out) const;
};

} // namespace ckks::crypto
