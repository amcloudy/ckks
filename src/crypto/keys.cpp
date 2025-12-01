#include "crypto/keys.hpp"

namespace ckks::crypto {

// --------------------------- SecretKey --------------------------------------

SecretKey::SecretKey(const ckks::CKKSContext& ctx)
{
  const auto& p   = ctx.params();
  const auto& rns = ctx.rns();

  std::size_t N = p.N;
  std::size_t L = rns.num_moduli();

  poly   = core::PolyRNS(N, L);
  level  = static_cast<int>(L) - 1;
  is_ntt = false;
}

// --------------------------- PublicKey --------------------------------------

PublicKey::PublicKey(const ckks::CKKSContext& ctx)
{
  const auto& p   = ctx.params();
  const auto& rns = ctx.rns();

  std::size_t N = p.N;
  std::size_t L = rns.num_moduli();

  a      = core::PolyRNS(N, L);
  b      = core::PolyRNS(N, L);
  level  = static_cast<int>(L) - 1;
  is_ntt = false;
}

// --------------------------- RelinKey ---------------------------------------

RelinKey::RelinKey(const ckks::CKKSContext& ctx)
{
  const auto& p   = ctx.params();
  const auto& rns = ctx.rns();

  std::size_t N = p.N;
  std::size_t L = rns.num_moduli();

  a      = core::PolyRNS(N, L);
  b      = core::PolyRNS(N, L);
  level  = static_cast<int>(L) - 1;
  is_ntt = false;
}

} // namespace ckks::crypto
