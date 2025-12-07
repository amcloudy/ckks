#include "crypto/decrypt.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

using namespace ckks::core;

void Decryptor::decrypt(const SecretKey& sk,
                        const Ciphertext& ct,
                        Plaintext& pt_out)
{
  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi;

  std::size_t N = ctx.params().N;
  std::size_t L_total = rns.num_moduli();
  std::size_t level   = static_cast<std::size_t>(ct.level);
  std::size_t L       = std::min(level + 1, L_total);

  // Prepare output plaintext
  pt_out.poly      = PolyRNS(N, L);
  pt_out.scale     = ct.scale;
  pt_out.level     = ct.level;
  pt_out.num_slots = ct.num_slots;
  pt_out.is_ntt    = false;

  // tmp = c1 * s (using NTT)
  PolyRNS c1_ntt = ct[1];
  PolyRNS s_ntt  = sk.poly;
  poly_to_ntt(c1_ntt, rns);
  poly_to_ntt(s_ntt, rns);

  PolyRNS prod(N, L);
  poly_pointwise_mul(prod, c1_ntt, s_ntt, rns);
  poly_from_ntt(prod, rns);

  // m = c0 + prod
  poly_add(pt_out.poly, ct[0], prod, rns);
}

} // namespace ckks::crypto
