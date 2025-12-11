#include "crypto/encoder.hpp"

#include <algorithm>
#include <cmath>
#include <complex>
#include <stdexcept>
#include <vector>

#include "core/poly.hpp"

namespace ckks::crypto {

using namespace ckks::core;

// ----------------------------- Constructor -----------------------------------

Encoder::Encoder(const ckks::CKKSContext& context)
    : ctx_(&context)
{
    const auto& p = context.params();
    N_ = p.N();
    if ((N_ & (N_ - 1)) != 0) {
        throw std::invalid_argument("Encoder: N must be power of 2.");
    }
    slots_ = p.slots(); // N/2
}

// ----------------------------- FFT helpers ----------------------------------

// bit-reversal for FFT
static void bit_reverse(std::vector<std::complex<double>>& a) {
    std::size_t n = a.size();
    std::size_t j = 0;
    for (std::size_t i = 1; i < n; ++i) {
        std::size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) {
            j ^= bit;
        }
        j ^= bit;
        if (i < j) {
            std::swap(a[i], a[j]);
        }
    }
}

// Unitary FFT
void Encoder::fft_inplace(std::vector<std::complex<double>>& a) const {
    std::size_t n = a.size();
    if (n == 0) return;

    bit_reverse(a);

    for (std::size_t len = 2; len <= n; len <<= 1) {
        double ang = -2.0 * M_PI / double(len);
        std::complex<double> wlen(std::cos(ang), std::sin(ang));

        for (std::size_t i = 0; i < n; i += len) {
            std::complex<double> w(1.0, 0.0);
            for (std::size_t j = 0; j < len / 2; ++j) {
                auto u = a[i + j];
                auto v = a[i + j + len / 2] * w;
                a[i + j]             = u + v;
                a[i + j + len / 2]   = u - v;
                w *= wlen;
            }
        }
    }

    // Unitary normalization 1/sqrt(n)
    double inv_sqrt_n = 1.0 / std::sqrt(static_cast<double>(n));
    for (auto& z : a) {
        z *= inv_sqrt_n;
    }
}

// Unitary IFFT (conj → FFT → conj)
void Encoder::ifft_inplace(std::vector<std::complex<double>>& a) const {
    for (auto& z : a) {
        z = std::conj(z);
    }

    fft_inplace(a);

    for (auto& z : a) {
        z = std::conj(z);
    }
}

// ----------------------------- Public Encode ---------------------------------

Plaintext Encoder::encode(const std::vector<double>& values,
                          double scale,
                          std::size_t level) const
{
    Plaintext pt(*ctx_);
    encode(values, scale, level, pt);
    return pt;
}

void Encoder::encode(const std::vector<double>& values,
                     double scale,
                     std::size_t level,
                     Plaintext& out) const
{
    if (scale <= 0.0) {
        throw std::invalid_argument("Encoder::encode: scale must be > 0.");
    }

    const auto& p   = ctx_->params();
    const auto& rns = ctx_->rns();

    if (level >= rns.num_moduli()) {
        throw std::invalid_argument("Encoder::encode: level >= num_moduli.");
    }

    // Build complex slot vector of length slots_ (N/2)
    std::vector<std::complex<double>> cs(slots_);
    std::size_t used = std::min(values.size(), slots_);

    for (std::size_t i = 0; i < used; ++i) {
        cs[i] = std::complex<double>(values[i], 0.0);
    }
    for (std::size_t i = used; i < slots_; ++i) {
        cs[i] = std::complex<double>(0.0, 0.0);
    }

    ckks_encode_complex(cs, scale, level, out);

    out.scale     = scale;
    out.level     = static_cast<int>(level);
    out.num_slots = used;
    out.is_ntt    = false;
}

// ----------------------------- Internal Encode -------------------------------

void Encoder::ckks_encode_complex(const std::vector<std::complex<double>>& slots_vec,
                                  double scale,
                                  std::size_t level,
                                  Plaintext& out) const
{
    PolyRNS& poly = out.poly;

    if (poly.degree() != N_) {
        throw std::runtime_error("Encoder::encode: PolyRNS wrong size.");
    }

    const auto& params = ctx_->params();
    const auto& qi     = params.qi();
    const auto& rns    = ctx_->rns();

    std::size_t L_total = rns.num_moduli();
    if (level >= L_total) {
        throw std::invalid_argument("Encoder::ckks_encode_complex: level >= L_total.");
    }

    std::size_t L_use = level + 1;

    // Build Hermitian symmetric vector a[N_]
    std::vector<std::complex<double>> a(N_);

    // Copy slot values
    for (std::size_t i = 0; i < slots_; ++i) {
        a[i] = slots_vec[i];
    }

    // Enforce Hermitian symmetry
    a[0] = std::complex<double>(a[0].real(), 0.0);
    a[N_ / 2] = std::complex<double>(0.0, 0.0);

    for (std::size_t i = 1; i < slots_; ++i) {
        a[N_ - i] = std::conj(a[i]);
    }

    // IFFT to coefficient domain (unitary)
    ifft_inplace(a);

    // Scale and round to integers
    std::vector<long double> coeff(N_);
    for (std::size_t i = 0; i < N_; ++i) {
        long double x = static_cast<long double>(a[i].real()) * scale;
        coeff[i] = std::llround(x);
    }

    // Reduce mod qi[0..level]
    for (std::size_t j = 0; j < L_use; ++j) {
        uint64_t    q     = qi[j];
        long double q_ld  = static_cast<long double>(q);
        auto&       polyj = poly[j];

        for (std::size_t i = 0; i < N_; ++i) {
            long double v = std::fmod(coeff[i], q_ld);
            if (v < 0) v += q_ld;
            polyj[i] = static_cast<uint64_t>(v);
        }
    }

    // Higher levels (if any) left as zero by Plaintext constructor
}

// ----------------------------- Public Decode ---------------------------------

std::vector<double> Encoder::decode(const Plaintext& pt,
                                    std::size_t max_slots) const
{
    std::vector<double> out;
    decode(pt, out, max_slots);
    return out;
}

void Encoder::decode(const Plaintext& pt,
                     std::vector<double>& out,
                     std::size_t max_slots) const
{
    if (pt.is_ntt) {
        throw std::invalid_argument("Encoder::decode: plaintext must be in coeff domain.");
    }

    if (pt.scale <= 0.0) {
        throw std::invalid_argument("Encoder::decode: scale must be > 0.");
    }

    std::vector<std::complex<double>> cs(slots_);
    ckks_decode_complex(pt, cs);

    std::size_t use = pt.num_slots;
    if (max_slots > 0 && max_slots < use) {
        use = max_slots;
    }

    out.resize(use);
    for (std::size_t i = 0; i < use; ++i) {
        out[i] = cs[i].real();
    }
}

// --------------------- CRT center-lift helper --------------------------------

static void center_lift(const CKKSParams& params,
                        const PolyRNS& poly,
                        std::size_t level,
                        std::vector<long double>& out)
{
    std::size_t N = poly.degree();
    std::size_t L = level + 1;
    const auto& qi = params.qi();

    out.assign(N, 0.0L);

    // Compute Q = product(qi[0..level])
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
            throw std::runtime_error("center_lift: modinv not invertible");
        }
        if (t < 0) t += m;
        return static_cast<uint64_t>(t);
    };

    // inv(Qh[j] mod qi[j])
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

// ----------------------------- Internal Decode -------------------------------

void Encoder::ckks_decode_complex(const Plaintext& pt,
                                  std::vector<std::complex<double>>& out) const
{
    const PolyRNS& poly = pt.poly;
    std::size_t level   = static_cast<std::size_t>(pt.level);
    long double  scale  = pt.scale;

    if (poly.degree() != N_) {
        throw std::runtime_error("Encoder::decode: PolyRNS wrong size.");
    }

    std::vector<long double> coeff;
    center_lift(ctx_->params(), poly, level, coeff);

    // Scale back and FFT
    std::vector<std::complex<double>> a(N_);
    long double inv_scale = 1.0L / scale;

    for (std::size_t i = 0; i < N_; ++i) {
        a[i] = std::complex<double>(coeff[i] * inv_scale, 0.0);
    }

    fft_inplace(a);

    if (out.size() != slots_) {
        out.resize(slots_);
    }

    for (std::size_t i = 0; i < slots_; ++i) {
        out[i] = a[i];
    }
}

} // namespace ckks::crypto
