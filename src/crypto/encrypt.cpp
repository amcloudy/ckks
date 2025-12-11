#include "crypto/encrypt.hpp"
#include "core/poly.hpp"

#include <random>
#include <cmath>

namespace ckks::crypto {

using namespace ckks::core;

void Encryptor::encrypt(const PublicKey& pk,
                        const Plaintext& pt,
                        Ciphertext& ct)
{
    const auto& ctx = *ctx_;
    const auto& rns = ctx.rns();
    const auto& qi  = ctx.params().qi();

    std::size_t N = ctx.params().N();
    std::size_t L = rns.num_moduli();

    // Prepare ciphertext with 2 polys (c0, c1)
    ct.resize_like(ctx, 2);
    ct.poly_count = 2;
    ct.scale      = pt.scale;
    ct.level      = pt.level;
    ct.num_slots  = pt.num_slots;
    ct.is_ntt     = false;

    // RNG
    std::mt19937_64 rng(std::random_device{}());

    // Sample u in {-1,0,1}
    auto sample_ternary = [&](PolyRNS& out) {
        out = PolyRNS(N, L);
        std::uniform_int_distribution<int> dist(0, 2);
        for (std::size_t j = 0; j < L; ++j) {
            uint64_t q = qi[j];
            auto& coeffs = out[j];
            for (std::size_t i = 0; i < N; ++i) {
                int r = dist(rng); // 0,1,2
                int v = (r == 0 ? -1 : (r == 1 ? 0 : 1));
                coeffs[i] = (v < 0 ? q - 1 : static_cast<uint64_t>(v));
            }
        }
    };

    // Sample Gaussian noise
    auto sample_gauss = [&](PolyRNS& out, double sigma) {
        out = PolyRNS(N, L);
        std::normal_distribution<double> gauss(0.0, sigma);
        for (std::size_t j = 0; j < L; ++j) {
            uint64_t q = qi[j];
            auto& coeffs = out[j];
            for (std::size_t i = 0; i < N; ++i) {
                long long x = std::llround(gauss(rng));
                long long r = x % static_cast<long long>(q);
                if (r < 0) r += q;
                coeffs[i] = static_cast<uint64_t>(r);
            }
        }
    };

    PolyRNS u, e1, e2;
    sample_ternary(u);
    sample_gauss(e1, 3.2);
    sample_gauss(e2, 3.2);

    // Compute bu = b*u and au = a*u using NTT
    PolyRNS b_ntt = pk.b;
    PolyRNS a_ntt = pk.a;
    PolyRNS u_ntt = u;

    poly_to_ntt(b_ntt, rns);
    poly_to_ntt(a_ntt, rns);
    poly_to_ntt(u_ntt, rns);

    PolyRNS bu(N, L), au(N, L);
    poly_pointwise_mul(bu, b_ntt, u_ntt, rns);
    poly_pointwise_mul(au, a_ntt, u_ntt, rns);

    poly_from_ntt(bu, rns);
    poly_from_ntt(au, rns);

    // c0 = bu + e1 + pt.poly
    // c1 = au + e2
    PolyRNS tmp(N, L);

    // tmp = bu + e1
    poly_add(tmp, bu, e1, rns);
    // ct[0] = tmp + pt.poly
    poly_add(ct[0], tmp, pt.poly, rns);

    // ct[1] = au + e2
    poly_add(ct[1], au, e2, rns);
}

} // namespace ckks::crypto
