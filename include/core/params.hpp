#pragma once

namespace ckks::core {

enum class SecurityLevel {
  SL128,
  SL192,
  SL256
};

struct ChainDesign {
  int depth;
  int log_scale;
  int margin_bits;
};

int max_logq_classical_ternary(std::size_t N, SecurityLevel sec);

std::vector<std::uint64_t>
generate_modulus_chain(std::size_t N,
                       SecurityLevel sec,
                       const ChainDesign& d);

} // namespace ckks::core
