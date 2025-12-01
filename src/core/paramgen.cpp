#include "core/paramgen.hpp"

namespace ckks::core {

RNSContext make_rns_context(std::size_t N,
                            SecurityLevel sec,
                            const ChainDesign& d)
{
  // Generate NTT-friendly primes respecting security constraints
  auto qi = generate_modulus_chain(N, sec, d);

  // Build RNS context with full modulus metadata
  return RNSContext(N, qi);
}

} // namespace ckks::core
