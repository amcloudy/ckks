#include "crypto/ciphertext.hpp"
#include <stdexcept>

namespace ckks::crypto {

Ciphertext::Ciphertext(const ckks::CKKSContext& ctx,
                       int poly_count_)
{
  resize_like(ctx, poly_count_);
  const auto& p = ctx.params();
  scale      = p.default_scale();
  level      = static_cast<int>(ctx.rns().num_moduli()) - 1;
  is_ntt     = false;
  num_slots  = p.slots();
}

void Ciphertext::resize_like(const ckks::CKKSContext& ctx,
                             int new_poly_count)
{
  if (new_poly_count != 2 && new_poly_count != 3) {
    throw std::invalid_argument("Ciphertext::resize_like: poly_count must be 2 or 3");
  }

  const auto& rns = ctx.rns();
  std::size_t N   = rns.degree();
  std::size_t L   = rns.num_moduli();

  for (int i = 0; i < 3; ++i) {
    polys[i] = core::PolyRNS(N, L);
  }

  poly_count = new_poly_count;
}

bool Ciphertext::is_valid(const ckks::CKKSContext& ctx) const noexcept
{
  const auto& rns = ctx.rns();
  std::size_t N   = rns.degree();
  std::size_t L   = rns.num_moduli();

  if (poly_count < 0 || poly_count > 3) return false;

  for (int i = 0; i < poly_count; ++i) {
    if (polys[i].degree() != N) return false;
    if (polys[i].num_moduli() != L) return false;
  }
  return true;
}

} // namespace ckks::crypto
