#include "crypto/plaintext.hpp"

namespace ckks::crypto
{

  Plaintext::Plaintext(const ckks::CKKSContext &ctx)
  {
    const auto &p = ctx.params();
    const auto &rns = ctx.rns();

    std::size_t N = p.N();
    std::size_t L = rns.num_moduli();

    poly = core::PolyRNS(N, L);
    scale = p.default_scale();
    level = static_cast<int>(L) - 1; // highest level
    is_ntt = false;
    num_slots = p.slots();
  }

} // namespace ckks::crypto
