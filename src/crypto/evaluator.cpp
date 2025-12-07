#include "crypto/evaluator.hpp"
#include "core/poly.hpp"

#include <stdexcept>
#include <vector>
#include <cmath>

namespace ckks::crypto {

using namespace ckks::core;

static void check_compatible_for_ct_ct(const Ciphertext& a,
                                       const Ciphertext& b)
{
  if (a.poly_count != b.poly_count) {
    throw std::invalid_argument("Evaluator: poly_count mismatch in ct+ct.");
  }
  if (a.level != b.level) {
    throw std::invalid_argument("Evaluator: level mismatch in ct+ct.");
  }
  if (a.is_ntt != b.is_ntt) {
    throw std::invalid_argument("Evaluator: NTT form mismatch in ct+ct.");
  }
}

static void check_compatible_for_ct_pt(const Ciphertext& ct,
                                       const Plaintext& pt)
{
  if (ct.level != pt.level) {
    throw std::invalid_argument("Evaluator: level mismatch in ct+pt.");
  }
  if (ct.is_ntt || pt.is_ntt) {
    throw std::invalid_argument("Evaluator: ct/pt must be in coeff domain.");
  }
}

// Center-lift one PolyRNS (using primes qi[0..level]) into Z with full CRT.
static void center_lift_poly(const CKKSParams& params,
                             const PolyRNS& poly,
                             std::size_t level,
                             std::vector<long double>& out)
{
  std::size_t N = poly.degree();
  std::size_t L = level + 1;
  const auto& qi = params.qi;

  out.assign(N, 0.0L);

  // Compute Q = product_{j=0..L-1} qi[j]
  __int128 Q = 1;
  for (std::size_t j = 0; j < L; ++j) {
    Q *= (__int128)qi[j];
  }

  // Q_hat[j] = Q / qi[j]
  std::vector<__int128> Qh(L);
  for (std::size_t j = 0; j < L; ++j) {
    Qh[j] = Q / (__int128)qi[j];
  }

  auto modinv = [](uint64_t a, uint64_t m) -> uint64_t {
    long long t = 0, newt = 1;
    long long r = m, newr = a;
    while (newr != 0) {
      long long q = r / newr;
      long long tmp = t - q * newt;
      t = newt; newt = tmp;
      tmp = r - q * newr;
      r = newr; newr = tmp;
    }
    if (r > 1) {
      throw std::runtime_error("center_lift_poly: not invertible.");
    }
    if (t < 0) t += m;
    return static_cast<uint64_t>(t);
  };

  // inv(Q_hat[j] mod qi[j])
  std::vector<uint64_t> invQh(L);
  for (std::size_t j = 0; j < L; ++j) {
    uint64_t q  = qi[j];
    uint64_t a  = static_cast<uint64_t>(Qh[j] % q);
    invQh[j]    = modinv(a, q);
  }

  // Reconstruct each coefficient
  for (std::size_t i = 0; i < N; ++i) {
    __int128 sum = 0;

    for (std::size_t j = 0; j < L; ++j) {
      uint64_t c = poly[j][i];

      __int128 t = (__int128)c * (__int128)invQh[j];
      t %= (__int128)qi[j];

      sum += t * Qh[j];
      sum %= Q;
    }

    if (sum > Q / 2) sum -= Q;
    out[i] = static_cast<long double>(sum);
  }
}

// ----------------- Ciphertext + Ciphertext -----------------------------------

void Evaluator::add(const Ciphertext& a,
                    const Ciphertext& b,
                    Ciphertext& out) const
{
  check_compatible_for_ct_ct(a, b);

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();

  out.resize_like(ctx, a.poly_count);
  out.poly_count = a.poly_count;
  out.level      = a.level;
  out.is_ntt     = a.is_ntt;
  out.num_slots  = std::min(a.num_slots, b.num_slots);
  out.scale      = a.scale; // assume scales matched by design

  for (int k = 0; k < a.poly_count; ++k) {
    poly_add(out[k], a[k], b[k], rns);
  }
}

Ciphertext Evaluator::add(const Ciphertext& a,
                          const Ciphertext& b) const
{
  Ciphertext out(*ctx_, a.poly_count);
  add(a, b, out);
  return out;
}

void Evaluator::sub(const Ciphertext& a,
                    const Ciphertext& b,
                    Ciphertext& out) const
{
  check_compatible_for_ct_ct(a, b);

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();

  out.resize_like(ctx, a.poly_count);
  out.poly_count = a.poly_count;
  out.level      = a.level;
  out.is_ntt     = a.is_ntt;
  out.num_slots  = std::min(a.num_slots, b.num_slots);
  out.scale      = a.scale;

  for (int k = 0; k < a.poly_count; ++k) {
    poly_sub(out[k], a[k], b[k], rns);
  }
}

Ciphertext Evaluator::sub(const Ciphertext& a,
                          const Ciphertext& b) const
{
  Ciphertext out(*ctx_, a.poly_count);
  sub(a, b, out);
  return out;
}

void Evaluator::negate(const Ciphertext& a,
                       Ciphertext& out) const
{
  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();

  out.resize_like(ctx, a.poly_count);
  out.poly_count = a.poly_count;
  out.level      = a.level;
  out.is_ntt     = a.is_ntt;
  out.num_slots  = a.num_slots;
  out.scale      = a.scale;

  for (int k = 0; k < a.poly_count; ++k) {
    poly_negate(out[k], a[k], rns);
  }
}

Ciphertext Evaluator::negate(const Ciphertext& a) const
{
  Ciphertext out(*ctx_, a.poly_count);
  negate(a, out);
  return out;
}

// ----------------- Ciphertext + Plaintext ------------------------------------

void Evaluator::add_plain(const Ciphertext& ct,
                          const Plaintext& pt,
                          Ciphertext& out) const
{
  check_compatible_for_ct_pt(ct, pt);

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();

  out.resize_like(ctx, ct.poly_count);
  out.poly_count = ct.poly_count;
  out.level      = ct.level;
  out.is_ntt     = ct.is_ntt;
  out.num_slots  = std::max(ct.num_slots, pt.num_slots);
  out.scale      = ct.scale; // assume same scale; caller responsible

  // c0' = c0 + m
  poly_add(out[0], ct[0], pt.poly, rns);

  // copy remaining polys unchanged
  for (int k = 1; k < ct.poly_count; ++k) {
    out[k] = ct[k];
  }
}

Ciphertext Evaluator::add_plain(const Ciphertext& ct,
                                const Plaintext& pt) const
{
  Ciphertext out(*ctx_, ct.poly_count);
  add_plain(ct, pt, out);
  return out;
}

void Evaluator::multiply_raw(const Ciphertext& a,
                             const Ciphertext& b,
                             Ciphertext& out) const
{
  if (a.poly_count != 2 || b.poly_count != 2) {
    throw std::invalid_argument("Evaluator::multiply_raw: only supports 2x2 ciphertexts.");
  }
  if (a.level != b.level) {
    throw std::invalid_argument("Evaluator::multiply_raw: level mismatch.");
  }
  if (a.is_ntt || b.is_ntt) {
    throw std::invalid_argument("Evaluator::multiply_raw: coefficient-domain only for now.");
  }

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi;

  std::size_t N = ctx.params().N;
  std::size_t L = rns.num_moduli();

  // NTT copies
  PolyRNS a0_ntt = a[0];
  PolyRNS a1_ntt = a[1];
  PolyRNS b0_ntt = b[0];
  PolyRNS b1_ntt = b[1];

  poly_to_ntt(a0_ntt, rns);
  poly_to_ntt(a1_ntt, rns);
  poly_to_ntt(b0_ntt, rns);
  poly_to_ntt(b1_ntt, rns);

  PolyRNS t00(N, L), t01(N, L), t10(N, L), t11(N, L);

  poly_pointwise_mul(t00, a0_ntt, b0_ntt, rns); // c0*d0
  poly_pointwise_mul(t01, a0_ntt, b1_ntt, rns); // c0*d1
  poly_pointwise_mul(t10, a1_ntt, b0_ntt, rns); // c1*d0
  poly_pointwise_mul(t11, a1_ntt, b1_ntt, rns); // c1*d1

  poly_from_ntt(t00, rns);
  poly_from_ntt(t01, rns);
  poly_from_ntt(t10, rns);
  poly_from_ntt(t11, rns);

  out.resize_like(ctx, 3);
  out.poly_count = 3;
  out.level      = a.level;
  out.is_ntt     = false;
  out.num_slots  = std::min(a.num_slots, b.num_slots);
  out.scale      = a.scale * b.scale;

  // e0 = t00; e2 = t11
  out[0] = t00;
  out[2] = t11;

  // e1 = t01 + t10
  for (std::size_t j = 0; j < L; ++j) {
    std::uint64_t q = qi[j];
    auto& e1j       = out[1][j];
    const auto& u   = t01[j];
    const auto& v   = t10[j];

    for (std::size_t i = 0; i < N; ++i) {
      std::uint64_t x = u[i] + v[i];
      if (x >= q) x -= q;
      e1j[i] = x;
    }
  }
}

Ciphertext Evaluator::multiply_raw(const Ciphertext& a,
                                   const Ciphertext& b) const
{
  Ciphertext out(*ctx_, 3);
  multiply_raw(a, b, out);
  return out;
}

void Evaluator::relinearize(const Ciphertext& ct3,
                            const RelinKey& rlk,
                            Ciphertext& out) const
{
  if (ct3.poly_count != 3) {
    throw std::invalid_argument("Evaluator::relinearize: input must have 3 polys.");
  }

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi;

  std::size_t N = ctx.params().N;
  std::size_t L = rns.num_moduli();

  // KeySwitch on c2 using RLK = (a,b)
  const PolyRNS& e0 = ct3[0];
  const PolyRNS& e1 = ct3[1];
  const PolyRNS& e2 = ct3[2];

  // NTT transform e2, a, b
  PolyRNS e2_ntt = e2;
  PolyRNS a_ntt  = rlk.a;
  PolyRNS b_ntt  = rlk.b;

  poly_to_ntt(e2_ntt, rns);
  poly_to_ntt(a_ntt, rns);
  poly_to_ntt(b_ntt, rns);

  PolyRNS k0_ntt(N, L), k1_ntt(N, L);

  // k0_ntt = e2 * b
  poly_pointwise_mul(k0_ntt, e2_ntt, b_ntt, rns);

  // k1_ntt = e2 * a
  poly_pointwise_mul(k1_ntt, e2_ntt, a_ntt, rns);

  PolyRNS k0(N, L), k1(N, L);
  poly_from_ntt(k0_ntt, rns);
  poly_from_ntt(k1_ntt, rns);

  // out has 2 polys: f0 = e0 + k0, f1 = e1 + k1
  out.resize_like(ctx, 2);
  out.poly_count = 2;
  out.level      = ct3.level;
  out.is_ntt     = false;
  out.num_slots  = ct3.num_slots;
  out.scale      = ct3.scale;

  // f0 = e0 + k0
  poly_add(out[0], e0, k0, rns);

  // f1 = e1 + k1
  poly_add(out[1], e1, k1, rns);
}

Ciphertext Evaluator::relinearize(const Ciphertext& ct3,
                                  const RelinKey& rlk) const
{
  Ciphertext out(*ctx_, 2);
  relinearize(ct3, rlk, out);
  return out;
}

void Evaluator::multiply_relinearize(const Ciphertext& a,
                                     const Ciphertext& b,
                                     const RelinKey& rlk,
                                     Ciphertext& out) const
{
  Ciphertext tmp(*ctx_, 3);
  multiply_raw(a, b, tmp);
  relinearize(tmp, rlk, out);
}

Ciphertext Evaluator::multiply_relinearize(const Ciphertext& a,
                                           const Ciphertext& b,
                                           const RelinKey& rlk) const
{
  Ciphertext out(*ctx_, 2);
  multiply_relinearize(a, b, rlk, out);
  return out;
}

void Evaluator::rescale_to_next(const Ciphertext& in,
                                Ciphertext& out) const
{
  if (in.is_ntt) {
    throw std::invalid_argument("Evaluator::rescale_to_next: ciphertext must be in coeff domain.");
  }
  if (in.level <= 0) {
    throw std::invalid_argument("Evaluator::rescale_to_next: level must be > 0.");
  }

  const auto& ctx    = *ctx_;
  const auto& params = ctx.params();
  const auto& rns    = ctx.rns();
  const auto& qi     = params.qi;

  std::size_t N        = params.N;
  std::size_t L_total  = rns.num_moduli();
  std::size_t level    = static_cast<std::size_t>(in.level);

  if (level + 1 > L_total) {
    throw std::runtime_error("Evaluator::rescale_to_next: in.level inconsistent with RNSContext.");
  }

  std::size_t L_use    = level + 1;
  uint64_t    q_last   = qi[level];
  long double q_last_ld = static_cast<long double>(q_last);

  out.resize_like(ctx, in.poly_count);
  out.poly_count = in.poly_count;
  out.level      = in.level - 1;
  out.is_ntt     = false;
  out.num_slots  = in.num_slots;

  // Update scale: scale' = scale / q_last
  out.scale = in.scale / static_cast<double>(q_last);

  // For each polynomial component
  for (int k = 0; k < in.poly_count; ++k) {
    const PolyRNS& poly_in = in[k];
    PolyRNS&       poly_out = out[k];

    // 1) Center-lift to integers using moduli qi[0..level]
    std::vector<long double> coeff;
    center_lift_poly(params, poly_in, level, coeff); // size N

    // 2) Divide by q_last and round
    std::vector<long double> coeff_div(coeff.size());
    for (std::size_t i = 0; i < coeff.size(); ++i) {
      long double x = coeff[i] / q_last_ld;
      coeff_div[i]  = std::llround(x);
    }

    // 3) Reduce into qi[0..level-1] (new active chain)
    for (std::size_t j = 0; j < level; ++j) {
      uint64_t     q     = qi[j];
      long double  q_ld  = static_cast<long double>(q);
      auto&        dest  = poly_out[j];

      for (std::size_t i = 0; i < N; ++i) {
        long double v = std::fmod(coeff_div[i], q_ld);
        if (v < 0) v += q_ld;
        dest[i] = static_cast<uint64_t>(v);
      }
    }

    // For j >= level, we leave poly_out[j] as whatever resize_like initialized
    // (typically zeros); decrypt/encode logic should only use moduli up to 'level'.
  }
}

Ciphertext Evaluator::rescale_to_next(const Ciphertext& in) const
{
  Ciphertext out(*ctx_, in.poly_count);
  rescale_to_next(in, out);
  return out;
}

void Evaluator::apply_galois(const Ciphertext& in,
                             const GaloisKey& gk,
                             Ciphertext& out) const
{
  if (in.poly_count != 2) {
    throw std::invalid_argument("Evaluator::apply_galois: input must have 2 polys.");
  }
  if (in.is_ntt) {
    throw std::invalid_argument("Evaluator::apply_galois: coeff domain only for now.");
  }

  const auto& ctx = *ctx_;
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi;

  std::size_t N = ctx.params().N;
  std::size_t L = rns.num_moduli();

  // 1) Apply automorphism to c0, c1
  PolyRNS c0_sigma, c1_sigma;
  poly_apply_galois(c0_sigma, in[0], N,
                    static_cast<std::uint64_t>(gk.galois_elt),
                    rns);
  poly_apply_galois(c1_sigma, in[1], N,
                    static_cast<std::uint64_t>(gk.galois_elt),
                    rns);

  // 2) Key-switch using GaloisKey (a,b)
  // k0 = c1_sigma * b   (NTT)
  // k1 = c1_sigma * a

  PolyRNS c1_ntt = c1_sigma;
  PolyRNS a_ntt  = gk.a;
  PolyRNS b_ntt  = gk.b;

  poly_to_ntt(c1_ntt, rns);
  poly_to_ntt(a_ntt, rns);
  poly_to_ntt(b_ntt, rns);

  PolyRNS k0_ntt(N, L), k1_ntt(N, L);
  poly_pointwise_mul(k0_ntt, c1_ntt, b_ntt, rns);
  poly_pointwise_mul(k1_ntt, c1_ntt, a_ntt, rns);

  PolyRNS k0(N, L), k1(N, L);
  poly_from_ntt(k0_ntt, rns);
  poly_from_ntt(k1_ntt, rns);

  // 3) New ciphertext under original secret:
  //   f0 = c0_sigma + k0
  //   f1 = k1

  out.resize_like(ctx, 2);
  out.poly_count = 2;
  out.level      = in.level;
  out.is_ntt     = false;
  out.num_slots  = in.num_slots;
  out.scale      = in.scale;

  poly_add(out[0], c0_sigma, k0, rns);
  out[1] = k1;
}

Ciphertext Evaluator::apply_galois(const Ciphertext& in,
                                   const GaloisKey& gk) const
{
  Ciphertext out(*ctx_, 2);
  apply_galois(in, gk, out);
  return out;
}

void Evaluator::rotate(const Ciphertext& in,
                       const GaloisKey& rot_key,
                       Ciphertext& out) const
{
  // For now, rotation is just "apply the corresponding Galois automorphism".
  apply_galois(in, rot_key, out);
}

Ciphertext Evaluator::rotate(const Ciphertext& in,
                             const GaloisKey& rot_key) const
{
  Ciphertext out(*ctx_, 2);
  rotate(in, rot_key, out);
  return out;
}




} // namespace ckks::crypto
