#include "core/poly.hpp"
#include "core/ntt.hpp"
#include <stdexcept>

namespace ckks::core {

static void ensure_compat(const PolyRNS& p,
                          const RNSContext& ctx,
                          const char* name) {
  if (p.N != ctx.degree()) {
    throw std::invalid_argument(std::string(name) + ": N mismatch");
  }
  if (p.num_moduli() != ctx.num_moduli()) {
    throw std::invalid_argument(std::string(name) + ": num_moduli mismatch");
  }
}

static void ensure_compat_binary(const PolyRNS& a,
                                 const PolyRNS& b,
                                 const RNSContext& ctx,
                                 const char* name) {
  if (a.N != b.N || a.N != ctx.degree()) {
    throw std::invalid_argument(std::string(name) + ": N mismatch");
  }
  if (a.num_moduli() != b.num_moduli()
      || a.num_moduli() != ctx.num_moduli()) {
    throw std::invalid_argument(std::string(name) + ": num_moduli mismatch");
  }
}

void poly_add(PolyRNS& out,
              const PolyRNS& a,
              const PolyRNS& b,
              const RNSContext& ctx) {
  ensure_compat_binary(a, b, ctx, "poly_add");

  if (out.N != a.N || out.num_moduli() != a.num_moduli()) {
    out = PolyRNS(a.N, a.num_moduli());
  }

  std::size_t N = a.N;
  std::size_t L = a.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    const auto q = ctx.modulus(i).q;
    const auto& ai = a.data[i];
    const auto& bi = b.data[i];
    auto& oi       = out.data[i];

    for (std::size_t j = 0; j < N; ++j) {
      std::uint64_t s = ai[j] + bi[j];
      if (s >= q) s -= q;
      oi[j] = s;
    }
  }
}

void poly_sub(PolyRNS& out,
              const PolyRNS& a,
              const PolyRNS& b,
              const RNSContext& ctx) {
  ensure_compat_binary(a, b, ctx, "poly_sub");

  if (out.N != a.N || out.num_moduli() != a.num_moduli()) {
    out = PolyRNS(a.N, a.num_moduli());
  }

  std::size_t N = a.N;
  std::size_t L = a.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    const auto q = ctx.modulus(i).q;
    const auto& ai = a.data[i];
    const auto& bi = b.data[i];
    auto& oi       = out.data[i];

    for (std::size_t j = 0; j < N; ++j) {
      std::uint64_t d = ai[j] + q - bi[j];
      if (d >= q) d -= q;
      oi[j] = d;
    }
  }
}

void poly_negate(PolyRNS& out,
                 const PolyRNS& a,
                 const RNSContext& ctx) {
  ensure_compat(a, ctx, "poly_negate");

  if (out.N != a.N || out.num_moduli() != a.num_moduli()) {
    out = PolyRNS(a.N, a.num_moduli());
  }

  std::size_t N = a.N;
  std::size_t L = a.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    const auto q = ctx.modulus(i).q;
    const auto& ai = a.data[i];
    auto& oi       = out.data[i];

    for (std::size_t j = 0; j < N; ++j) {
      oi[j] = ai[j] == 0 ? 0 : (q - ai[j]);
    }
  }
}

void poly_scalar_mul(PolyRNS& out,
                     const PolyRNS& a,
                     std::uint64_t c,
                     const RNSContext& ctx) {
  ensure_compat(a, ctx, "poly_scalar_mul");

  if (out.N != a.N || out.num_moduli() != a.num_moduli()) {
    out = PolyRNS(a.N, a.num_moduli());
  }

  std::size_t N = a.N;
  std::size_t L = a.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    const auto q = ctx.modulus(i).q;
    const auto& ai = a.data[i];
    auto& oi       = out.data[i];

    for (std::size_t j = 0; j < N; ++j) {
      oi[j] = static_cast<std::uint64_t>(
          (static_cast<__uint128_t>(ai[j]) * c) % q);
    }
  }
}

void poly_to_ntt(PolyRNS& p, const RNSContext& ctx) {
  ensure_compat(p, ctx, "poly_to_ntt");

  std::size_t N = p.N;
  std::size_t L = p.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    auto& vec       = p.data[i];
    const auto& mod = ctx.modulus(i);
    ntt_inplace(vec.data(), mod, N);
  }
}

void poly_from_ntt(PolyRNS& p, const RNSContext& ctx) {
  ensure_compat(p, ctx, "poly_from_ntt");

  std::size_t N = p.N;
  std::size_t L = p.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    auto& vec       = p.data[i];
    const auto& mod = ctx.modulus(i);
    intt_inplace(vec.data(), mod, N);
  }
}

void poly_pointwise_mul(PolyRNS& out,
                        const PolyRNS& a,
                        const PolyRNS& b,
                        const RNSContext& ctx) {
  ensure_compat_binary(a, b, ctx, "poly_pointwise_mul");

  if (out.N != a.N || out.num_moduli() != a.num_moduli()) {
    out = PolyRNS(a.N, a.num_moduli());
  }

  std::size_t N = a.N;
  std::size_t L = a.num_moduli();

  for (std::size_t i = 0; i < L; ++i) {
    const auto q  = ctx.modulus(i).q;
    const auto& ai = a.data[i];
    const auto& bi = b.data[i];
    auto& oi        = out.data[i];

    for (std::size_t j = 0; j < N; ++j) {
      oi[j] = static_cast<std::uint64_t>(
          (static_cast<__uint128_t>(ai[j]) * bi[j]) % q);
    }
  }
}

} // namespace ckks::core
