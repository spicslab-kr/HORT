#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#if defined(__has_include)
#if __has_include("/cipherfix/cipherfix/examples/cipherfix_interface.h")
#include "/cipherfix/cipherfix/examples/cipherfix_interface.h"
#else
#include "../cipherfix_interface.h"
#endif
#else
#include "/cipherfix/cipherfix/examples/cipherfix_interface.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define SIGMA 3.2

#ifndef N
#define N 65536
#endif

#define LEVEL 2

#define REENC_MAX 2

char *no_taint;
char *e2e = 0; // End-to-End evaluation flag. 1 : e2e mode, 0 : Local mode. e2e mode performs socket communication.
char *enc = 0;
char *decrypt = 0;

const char *input_path = NULL;
const char *output_path = NULL;
const char *key_path = NULL;

// timer function (nanoseconds)
double elapsed_ns(struct timespec start, struct timespec end)
{
    time_t sec = end.tv_sec - start.tv_sec;
    long nsec = end.tv_nsec - start.tv_nsec;

    if (nsec < 0)
    {
        sec -= 1;
        nsec += 1000000000L;
    }

    return (double)sec * 1e9 + (double)nsec;
}

// ===================== 복소수 구조체 =====================

typedef struct
{
    double real;
    double imag;
} ComplexDouble;

ComplexDouble complex_add(ComplexDouble a, ComplexDouble b)
{
    return (ComplexDouble){a.real + b.real, a.imag + b.imag};
}

ComplexDouble complex_sub(ComplexDouble a, ComplexDouble b)
{
    return (ComplexDouble){a.real - b.real, a.imag - b.imag};
}

ComplexDouble complex_mul(ComplexDouble a, ComplexDouble b)
{
    return (ComplexDouble){a.real * b.real - a.imag * b.imag,
                           a.real * b.imag + a.imag * b.real};
}

ComplexDouble complex_div_scalar(ComplexDouble a, double s)
{
    return (ComplexDouble){a.real / s, a.imag / s};
}

ComplexDouble complex_conjugate(ComplexDouble a)
{
    return (ComplexDouble){a.real, -a.imag};
}

void swap_complex(ComplexDouble *a, ComplexDouble *b)
{
    ComplexDouble temp = *a;
    *a = *b;
    *b = temp;
}

void swap(double *a, double *b)
{
    double temp = *a;
    *a = *b;
    *b = temp;
}

int64_t my_llround(long double x)
{
    if (x >= 0.0L)
    {
        return (int64_t)floorl(x + 0.5L);
    }
    else
    {
        return (int64_t)ceill(x - 0.5L);
    }
}

static inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t q)
{
    unsigned __int128 res = (unsigned __int128)a * b;
    return (uint64_t)(res % q);
}

static inline uint64_t submod(uint64_t a, uint64_t b, uint64_t q)
{
    uint64_t res = a - b;
    uint64_t mask = -(uint64_t)(a < b);

    return res + (mask & q);
}

static inline uint64_t addmod(uint64_t a, uint64_t b, uint64_t q)
{
    uint64_t sum = a + b;
    uint64_t mask = -(uint64_t)(sum >= q || sum < a);

    return sum - (mask & q);
}

uint64_t modinv(uint64_t a, uint64_t m)
{
    int64_t m0 = (int64_t)m;
    volatile int64_t y = 0, x = 1;
    int64_t a_signed = (int64_t)a;
    int64_t m_signed = (int64_t)m;

    if (m == 1)
        return 0;

    while (a_signed > 1)
    {
        int64_t q = a_signed / m_signed;
        int64_t t = m_signed;

        m_signed = a_signed % m_signed;
        a_signed = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return (uint64_t)x;
}

uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t res = 1;
    base %= mod;
    while (exp > 0)
    {
        if (exp & 1)
            res = mulmod(res, base, mod);
        base = mulmod(base, base, mod);
        exp >>= 1;
    }
    return res;
}

// ======================= modulus chain and Poly struct =========================
typedef struct
{
    size_t L;     // length of Chain
    uint64_t *qs; // uint64_t array
} ModulusChain;

typedef struct
{
    size_t n;                  // number of coefficients
    size_t L;                  // number of qs
    uint64_t coeffs[LEVEL][N]; // uint64_t 2D array
} PolyRNS;

long double CRTInterpolate_128bit_Clean(uint64_t *residues, const ModulusChain *mc, long double scale)
{

    unsigned __int128 Q = 1;
    for (size_t l = 0; l < mc->L; l++)
    {
        Q *= (unsigned __int128)mc->qs[l];
    }

    unsigned __int128 result = 0;

    for (size_t l = 0; l < mc->L; l++)
    {
        uint64_t ql = mc->qs[l];

        unsigned __int128 Ql = Q / ql;

        uint64_t Ql_mod = (uint64_t)(Ql % ql);
        uint64_t inv = modinv(Ql_mod, ql);

        // term = (residue * inv) % ql
        unsigned __int128 term_val = ((unsigned __int128)residues[l] * inv) % ql;

        // result += term * Ql
        unsigned __int128 term_full = term_val * Ql;
        result = (result + term_full) % Q;
    }

    if (result > (Q >> 1))
    {
        unsigned __int128 diff = Q - result;
        long double negative_val = -(long double)diff;
        return negative_val / scale;
    }
    else
    {
        return (long double)result / scale;
    }
}

// ========================== Random Sampling func. ==========================
void SampleSecretKey(PolyRNS *sk, size_t ringDim, const ModulusChain *mc)
{

    int *temp_key = malloc(sizeof(int) * N);
    size_t n = ringDim;
    for (size_t i = 0; i < n; ++i)
    {
        temp_key[i] = (rand() % 3) - 1;
    }
    for (size_t l = 0; l < sk->L; ++l)
    {
        uint64_t q = mc->qs[l];
        for (size_t i = 0; i < n; ++i)
        {
            int r = temp_key[i];
            if (r >= 0)
                sk->coeffs[l][i] = (uint64_t)r;
            else
                sk->coeffs[l][i] = q - 1;
        }
    }
}

double gaussian_noise(double sigma)
{
    static int haveSpare = 0;
    static double rand1, rand2;

    if (haveSpare)
    {
        haveSpare = 0;
        return sqrt(rand1) * sin(rand2);
    }

    haveSpare = 1;

    rand1 = rand() / ((double)RAND_MAX);
    if (rand1 < 1e-100)
        rand1 = 1e-100;
    rand1 = -2 * log(rand1);
    rand2 = (rand() / ((double)RAND_MAX)) * 2.0 * M_PI;

    return sigma * sqrt(rand1) * cos(rand2);
}

int64_t SampleError()
{
    return (int64_t)my_llround(gaussian_noise(SIGMA));
}

// ========================== NTT / iNTT ==========================

static void bit_reverse_inplace_u64(uint64_t *a, size_t n)
{
    size_t j = 0;
    for (size_t i = 1; i < n - 1; ++i)
    {
        size_t bit = n >> 1;
        while (j & bit)
        {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if (i < j)
        {
            uint64_t tmp = a[i];
            a[i] = a[j];
            a[j] = tmp;
        }
    }
}

void NTT_Forward(uint64_t *a, size_t n, uint64_t q, uint64_t w, uint64_t psi)
{
    // Keep this routine identical to the reference implementation in ntt_toy_compare.cpp
    // so that our engine uses the exact same NTT that was validated against OpenFHE.
    uint64_t psi_pow = 1;
    for (size_t i = 0; i < n; ++i)
    {
        a[i] = mulmod(a[i], psi_pow, q);
        psi_pow = mulmod(psi_pow, psi, q);
    }

    bit_reverse_inplace_u64(a, n);
    for (size_t len = 2; len <= n; len <<= 1)
    {
        size_t step = n / len;
        uint64_t wLen = modexp(w, step, q);
        size_t half = len >> 1;
        for (size_t i = 0; i < n; i += len)
        {
            uint64_t wFactor = 1;
            for (size_t j = 0; j < half; ++j)
            {
                uint64_t u = a[i + j];
                uint64_t v = mulmod(a[i + j + half], wFactor, q);
                a[i + j] = addmod(u, v, q);
                a[i + j + half] = submod(u, v, q);
                wFactor = mulmod(wFactor, wLen, q);
            }
        }
    }
    bit_reverse_inplace_u64(a, n);
}

void NTT_Inverse(uint64_t *a, size_t n, uint64_t q, uint64_t w_inv, uint64_t psi_inv)
{
    bit_reverse_inplace_u64(a, n);

    for (size_t len = n; len >= 2; len >>= 1)
    {
        size_t step = n / len;
        uint64_t wLen = modexp(w_inv, step, q);
        size_t half = len >> 1;
        for (size_t i = 0; i < n; i += len)
        {
            uint64_t wFactor = 1;
            for (size_t j = 0; j < half; ++j)
            {
                uint64_t u = a[i + j];
                uint64_t v = a[i + j + half];
                a[i + j] = addmod(u, v, q);
                uint64_t diff = submod(u, v, q);
                a[i + j + half] = mulmod(diff, wFactor, q);
                wFactor = mulmod(wFactor, wLen, q);
            }
        }
    }

    bit_reverse_inplace_u64(a, n);

    uint64_t N_inv = modinv(n, q);
    for (size_t i = 0; i < n; ++i)
    {
        a[i] = mulmod(a[i], N_inv, q);
    }

    uint64_t psi_pow = 1;
    for (size_t i = 0; i < n; ++i)
    {
        a[i] = mulmod(a[i], psi_pow, q);
        psi_pow = mulmod(psi_pow, psi_inv, q);
    }
}

// OpenFHE-compatible NTT (no extra psi pre/post factors).
static void NTT_Forward_OpenFHE(uint64_t *a, size_t n, uint64_t q, uint64_t w)
{
    bit_reverse_inplace_u64(a, n);
    for (size_t len = 2; len <= n; len <<= 1)
    {
        size_t step = n / len;
        uint64_t wLen = modexp(w, step, q);
        size_t half = len >> 1;
        for (size_t i = 0; i < n; i += len)
        {
            uint64_t wFactor = 1;
            for (size_t j = 0; j < half; ++j)
            {
                uint64_t u = a[i + j];
                uint64_t v = mulmod(a[i + j + half], wFactor, q);
                a[i + j] = addmod(u, v, q);
                a[i + j + half] = submod(u, v, q);
                wFactor = mulmod(wFactor, wLen, q);
            }
        }
    }
}

static void NTT_Inverse_OpenFHE(uint64_t *a, size_t n, uint64_t q, uint64_t w_inv)
{
    bit_reverse_inplace_u64(a, n);
    for (size_t len = n; len >= 2; len >>= 1)
    {
        size_t step = n / len;
        uint64_t wLen = modexp(w_inv, step, q);
        size_t half = len >> 1;
        for (size_t i = 0; i < n; i += len)
        {
            uint64_t wFactor = 1;
            for (size_t j = 0; j < half; ++j)
            {
                uint64_t u = a[i + j];
                uint64_t v = a[i + j + half];
                a[i + j] = addmod(u, v, q);
                uint64_t diff = submod(u, v, q);
                a[i + j + half] = mulmod(diff, wFactor, q);
                wFactor = mulmod(wFactor, wLen, q);
            }
        }
    }
    uint64_t N_inv = modinv(n, q);
    for (size_t i = 0; i < n; ++i)
    {
        a[i] = mulmod(a[i], N_inv, q);
    }
}

// ===================== Precomputed Values (FFT용) ============
typedef struct
{
    uint32_t m_M;
    uint32_t m_Nh;
    uint32_t *m_rotGroup;
    ComplexDouble *m_ksiPows;
} PrecomputedValues;

PrecomputedValues *PrecomputedValues_Init(uint32_t m, uint32_t nh)
{
    PrecomputedValues *prep = (PrecomputedValues *)malloc(sizeof(PrecomputedValues));
    prep->m_M = m;
    prep->m_Nh = nh;

    prep->m_rotGroup = malloc(sizeof(uint32_t) * nh);
    uint32_t fivePows = 1;
    for (size_t i = 0; i < nh; ++i)
    {
        prep->m_rotGroup[i] = fivePows;
        fivePows = (fivePows * 5) % m;
    }

    prep->m_ksiPows = malloc(sizeof(ComplexDouble) * (m + 1));
    for (size_t j = 0; j < m; ++j)
    {
        double angle = 2.0 * M_PI * j / m;
        prep->m_ksiPows[j].real = cos(angle);
        prep->m_ksiPows[j].imag = sin(angle);
    }
    prep->m_ksiPows[m] = prep->m_ksiPows[0];

    return prep;
}

void BitReverse_complex(ComplexDouble *vals, size_t size)
{
    for (size_t i = 1, j = 0; i < size; ++i)
    {
        size_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j)
            swap_complex(&vals[i], &vals[j]);
    }
}

void BitReverse(double *vals, size_t size)
{
    for (size_t i = 1, j = 0; i < size; ++i)
    {
        size_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j)
        {
            swap(&vals[i], &vals[j]);
        }
    }
}

void FFTSpecial(double *real, double *imag, size_t size, const PrecomputedValues *prep)
{
    size_t size_n = size;
    BitReverse(real, size_n);
    BitReverse(imag, size_n);
    for (size_t len = 2; len <= size; len <<= 1)
    {
        size_t lenh = len >> 1;
        size_t lenq = len << 2;
        size_t gap = prep->m_M / lenq;
        for (size_t i = 0; i < size; i += len)
        {
            for (size_t j = 0; j < lenh; ++j)
            {
                int64_t idx = (prep->m_rotGroup[j] % lenq) * gap;
                double u_real = real[i + j];
                double u_imag = imag[i + j];
                double v_real = real[i + j + lenh];
                double v_imag = imag[i + j + lenh];
                double v_real_temp = v_real * prep->m_ksiPows[idx].real - v_imag * prep->m_ksiPows[idx].imag;
                double v_imag_temp = v_real * prep->m_ksiPows[idx].imag + v_imag * prep->m_ksiPows[idx].real;
                real[i + j] = u_real + v_real_temp;
                imag[i + j] = u_imag + v_imag_temp;
                real[i + j + lenh] = u_real - v_real_temp;
                imag[i + j + lenh] = u_imag - v_imag_temp;
            }
        }
    }
}

void FFTSpecialInv(double *real, double *imag, size_t size, const PrecomputedValues *prep)
{
    size_t size_n = size;

    for (size_t len = size; len >= 1; len >>= 1)
    {
        for (size_t i = 0; i < size; i += len)
        {
            size_t lenh = len >> 1;
            size_t lenq = len << 2;
            size_t gap = prep->m_M / lenq;
            for (size_t j = 0; j < lenh; ++j)
            {
                size_t idx = (lenq - (prep->m_rotGroup[j] % lenq)) * gap;

                double u_r = real[i + j] + real[i + j + lenh];
                double u_i = imag[i + j] + imag[i + j + lenh];

                double v_r = real[i + j] - real[i + j + lenh];
                double v_i = imag[i + j] - imag[i + j + lenh];

                double tw_r = prep->m_ksiPows[idx].real;
                double tw_i = prep->m_ksiPows[idx].imag;

                double v_new_r = v_r * tw_r - v_i * tw_i;
                double v_new_i = v_r * tw_i + v_i * tw_r;

                real[i + j] = u_r;
                imag[i + j] = u_i;
                real[i + j + lenh] = v_new_r;
                imag[i + j + lenh] = v_new_i;
            }
        }
    }

    BitReverse(real, size_n);
    BitReverse(imag, size_n);

    double invN = 1.0 / (double)size;
    for (size_t i = 0; i < size_n; ++i)
    {
        real[i] *= invN;
        imag[i] *= invN;
    }
}

// // ===================== Ciphertext RNS struct =================
typedef struct
{
    PolyRNS *c0;
    PolyRNS *c1;
} CiphertextRNS;

// ===================== Encrypt / Decrypt =====================
CiphertextRNS *CKKS_Encrypt(const PolyRNS *pt, const uint64_t *sk_ntt, const ModulusChain *mc, uint64_t *W,
                            uint64_t *Psi)
{

    CiphertextRNS *ct = (CiphertextRNS *)malloc(sizeof(CiphertextRNS));
    ct->c0 = malloc(sizeof(PolyRNS));
    ct->c1 = malloc(sizeof(PolyRNS));
    ct->c0->n = ct->c1->n = pt->n;
    ct->c0->L = ct->c1->L = pt->L;

    uint64_t a[N];
    uint64_t s_ntt[N];
    uint64_t e_ntt[N];
    uint64_t m_ntt[N];

    size_t n = pt->n;
    size_t L = pt->L;

    int64_t *error_poly = malloc(sizeof(int64_t) * N);

    /////// 1 ///////
    for (int i = 0; i < N; i++)
        error_poly[i] = SampleError();
    classify((void *)error_poly, sizeof(int64_t) * N);

    for (size_t l = 0; l < L; l++)
    { // for each level.
        uint64_t q = mc->qs[l];

        for (size_t i = 0; i < n; i++)
        {
            a[i] = (uint64_t)rand() % q;

            int64_t err = error_poly[i];
            if (err < 0)
                e_ntt[i] = (uint64_t)(err + (int64_t)q);
            else
                e_ntt[i] = (uint64_t)err;

            m_ntt[i] = pt->coeffs[l][i];
        }

        NTT_Forward(a, N, q, W[l], Psi[l]);
        NTT_Forward(e_ntt, N, q, W[l], Psi[l]);
        NTT_Forward(m_ntt, N, q, W[l], Psi[l]);

        for (size_t i = 0; i < n; i++)
        {
            // c0 = a*s + e + m
            uint64_t as = mulmod(a[i], sk_ntt[l * N + i], q);
            uint64_t ase = addmod(as, e_ntt[i], q);
            uint64_t asem = addmod(ase, m_ntt[i], q);
            ct->c0->coeffs[l][i] = asem;

            // c1 = -a
            ct->c1->coeffs[l][i] = submod(0, a[i], q); // 0 - a mod q
        }
    }

    return ct;
}

PolyRNS *CKKS_Decrypt(CiphertextRNS *ct, const uint64_t *sk_ntt, const ModulusChain *mc, uint64_t *W, uint64_t *W_inv,
                      uint64_t *Psi, uint64_t *Psi_inv)
{
    PolyRNS *res = (PolyRNS *)malloc(sizeof(PolyRNS));
    res->n = ct->c0->n;
    res->L = mc->L;

    uint64_t c0_val, c1_val, sk_val;
    uint64_t prod, sum;

    size_t L = ct->c0->L;
    size_t n = ct->c0->n;

    for (size_t l = 0; l < L; l++)
    {
        uint64_t q = mc->qs[l];

        for (size_t i = 0; i < n; i++)
        {
            c0_val = ct->c0->coeffs[l][i];
            c1_val = ct->c1->coeffs[l][i];
            sk_val = sk_ntt[l * N + i];

            prod = mulmod(c1_val, sk_val, q);
            sum = addmod(c0_val, prod, q);

            res->coeffs[l][i] = sum;
        }

        NTT_Inverse(res->coeffs[l], N, q, W_inv[l], Psi_inv[l]);
    }

    return res;
}

PolyRNS *CKKS_Encode(const ComplexDouble *input,
                     size_t ringDim, long double scale,
                     const ModulusChain *mc,
                     const PrecomputedValues *prep)
{

    const size_t slots = ringDim / 2;
    long double scale_ld = scale;

    double buf_real[N] = {0.0};
    double buf_imag[N] = {0.0};
    for (size_t i = 0; i < slots; i++)
    {
        buf_real[i] = (double)input[i].real;
        buf_imag[i] = (double)input[i].imag;
    }

    FFTSpecialInv(buf_real, buf_imag, slots, prep);

    PolyRNS *pt = (PolyRNS *)malloc(sizeof(PolyRNS));
    pt->L = mc->L;
    pt->n = ringDim;

    for (size_t l = 0; l < mc->L; l++)
    {
        uint64_t q = mc->qs[l];
        for (size_t i = 0; i < slots; i++)
        {
            long double re_scaled = (long double)buf_real[i] * scale_ld;
            long double im_scaled = (long double)buf_imag[i] * scale_ld;

            int64_t re_rounded = my_llround(re_scaled);
            int64_t im_rounded = my_llround(im_scaled);

            int64_t rem_re = re_rounded % (int64_t)q;
            if (rem_re < 0)
                rem_re += (int64_t)q;

            int64_t rem_im = im_rounded % (int64_t)q;
            if (rem_im < 0)
                rem_im += (int64_t)q;

            pt->coeffs[l][i] = (uint64_t)rem_re;
            pt->coeffs[l][i + slots] = (uint64_t)rem_im;
        }
    }

    return pt;
}

ComplexDouble *CKKS_Decode(const PolyRNS *poly,
                           const PolyRNS *c0,
                           size_t ringDim,
                           long double scale,
                           const ModulusChain *mc,
                           const PrecomputedValues *prep)
{
    const size_t slots = ringDim / 2;
    double cur_real[N] = {0.0};
    double cur_imag[N] = {0.0};
    uint64_t residues[LEVEL] = {0};

    // Reconstruct real/imag parts in coefficient domain (length = slots).
    for (size_t i = 0; i < slots; i++)
    {
        for (size_t l = 0; l < mc->L; l++)
        {
            residues[l] = poly->coeffs[l][i];
        }
        long double re = CRTInterpolate_128bit_Clean(residues, mc, scale);

        for (size_t l = 0; l < mc->L; l++)
        {
            residues[l] = poly->coeffs[l][i + slots];
        }
        long double im = CRTInterpolate_128bit_Clean(residues, mc, scale);

        cur_real[i] = (double)re;
        cur_imag[i] = (double)im;
    }

    // Apply FFT of length = slots (matches OpenFHE CKKS decode path).
    FFTSpecial(cur_real, cur_imag, slots, prep);

    ComplexDouble *out = (ComplexDouble *)malloc(sizeof(ComplexDouble) * slots);
    for (size_t i = 0; i < slots; i++)
    {
        out[i].real = cur_real[i];
        out[i].imag = cur_imag[i];
    }

    return out;
}

static ssize_t read_full(int fd, void *buf, size_t count)
{
    size_t left = count;
    char *ptr = (char *)buf;
    while (left > 0)
    {
        ssize_t r = read(fd, ptr, left);
        if (r == 0)
            break; // EOF
        left -= r;
        ptr += r;
    }
    return (ssize_t)(count - left);
}

static ssize_t write_full(int fd, const void *buf, size_t count)
{
    size_t left = count;
    const char *ptr = (const char *)buf;
    while (left > 0)
    {
        ssize_t w = write(fd, ptr, left);
        left -= w;
        ptr += w;
    }
    return (ssize_t)(count - left);
}

int main(int argc, char *argv[])
{

    srand(time(NULL));
    no_taint = getenv("NO_TAINT");
    e2e = getenv("E2E");
    enc = getenv("ENC");
    decrypt = getenv("DEC");

    const size_t coeff_per_ct = 2 * LEVEL * N;
    const size_t byte_count = coeff_per_ct * sizeof(uint64_t);
    const size_t msg_count = (N / 2) * sizeof(double);

    uint64_t *in_buf = malloc(sizeof(uint64_t) * 2 * LEVEL * N);
    uint64_t *out_buf = malloc(sizeof(uint64_t) * 2 * LEVEL * N);
    double *msg_buf = (double *)malloc(10); // dummy allocation
    double *msg_real = (double *)malloc(msg_count);

    if (e2e != 0)
    {
        if (argc < 4)
        {
            fprintf(stderr,
                    "Usage: %s <input_bin> <output_bin> <key_path> [input_scale] [output_scale]\n"
                    "  input_bin   : 2*LEVEL*N uint64_t coefficients (c0 || c1)\n"
                    "  output_bin  : output coefficients after re-encryption\n"
                    "  key_path    : secret key path\n"
                    "  input_scale : optional, scale of incoming ciphertext (default 2^40)\n"
                    "  output_scale: optional, scale to use for re-encryption (default = input_scale)\n",
                    argv[0]);
            return 1;
        }
        input_path = argv[1];
        output_path = argv[2];
        key_path = argv[3];

        int fd_in = open(input_path, O_RDONLY);
        if (fd_in < 0)
        {
            perror("open(input)");
            return 1;
        }
        if (enc != 0)
        {
            msg_buf = (double *)malloc(msg_count);
            ssize_t nread = read_full(fd_in, msg_buf, msg_count);

            if (nread != msg_count)
            {
                fprintf(stderr, "ENC Input size mismatch: expected %zu bytes, got %zu\n",
                        msg_count, nread);
                return 1;
            }
        }
        else
        {
            ssize_t nread = read_full(fd_in, in_buf, byte_count);

            if (nread != byte_count)
            {
                fprintf(stderr, "Input size mismatch: expected %zu bytes, got %zu\n",
                        byte_count, nread);
                return 1;
            }
        }
        close(fd_in);
    }

    size_t n = N;
    size_t slots = n / 2;
    long double input_scale = (long double)(1ULL << 40); // 2^40
    long double output_scale = input_scale;

    if (e2e != 0)
    {
        if (argc >= 5)
        {
            input_scale = strtold(argv[4], NULL);
        }
        if (argc >= 6)
        {
            output_scale = strtold(argv[5], NULL);
        }
        else
        {
            output_scale = input_scale;
        }
    }
    uint64_t qs[LEVEL] = {
        // N = 16384
        // 1152921504606748673ULL,
        // 1099511922689ULL

        // N = 65536
        1152921504606584833ULL,
        1099512938497ULL};

    PrecomputedValues *prep = PrecomputedValues_Init(slots * 4, slots);

    ModulusChain mc = {LEVEL, qs};

    PolyRNS *sk = malloc(sizeof(PolyRNS));
    sk->n = N;
    sk->L = LEVEL;

    classify((void *)sk->coeffs, sizeof(long long) * sk->L * sk->n);

    if (e2e != 0)
    {
        int fd_key = open(key_path, O_RDONLY);
        if (fd_key < 0)
        {
            perror("[Engine] open(secret.key) failed");
            return 1;
        }

        size_t key_size = sizeof(uint64_t) * LEVEL * N;
        ssize_t nread_key = read_full(fd_key, sk->coeffs, key_size);
        close(fd_key);

        if (nread_key != (ssize_t)key_size)
        {
            fprintf(stderr, "[Engine] Key size mismatch: expected %zu, got %zd\n", key_size, nread_key);
            return 1;
        }
    }

    uint64_t base_W[LEVEL];
    uint64_t base_W_inv[LEVEL];
    uint64_t base_Psi[LEVEL];
    uint64_t base_Psi_inv[LEVEL];

    // OpenFHE-sourced parameters
    // LEVEL = 16384
    // base_Psi[0] = 62213374832584;
    // base_Psi[1] = 36692422;
    // base_Psi_inv[0] = modinv(62213374832584, qs[0]);
    // base_Psi_inv[1] = modinv(36692422, qs[1]);
    // base_W[0] = 371171015325506197;
    // base_W[1] = 531238854748;
    // base_W_inv[0] = modinv(371171015325506197, qs[0]);
    // base_W_inv[1] = modinv(531238854748, qs[1]);

    // LEVEL = 65536
    base_Psi[0] = 18043022392882;
    base_Psi[1] = 3622970;
    base_Psi_inv[0] = modinv(18043022392882, qs[0]);
    base_Psi_inv[1] = modinv(3622970, qs[1]);
    base_W[0] = 829644590865031485;
    base_W[1] = 1031269297433;
    base_W_inv[0] = modinv(829644590865031485, qs[0]);
    base_W_inv[1] = modinv(1031269297433, qs[1]);

    int client_fd = -1;
    int server_fd = -1;

    uint64_t *sk_ntt = malloc(sizeof(uint64_t *) * LEVEL * N);

    for (size_t l = 0; l < LEVEL; l++)
    {
        for (size_t i = 0; i < N; i++)
        {
            sk_ntt[l * N + i] = sk->coeffs[l][i];
        }
        NTT_Forward(&sk_ntt[l * N], N, qs[l], base_W[l], base_Psi[l]);
    }

    double cpu_time_Encrypt = 0.0, cpu_time_Decrypt = 0.0, cpu_time_Encode = 0.0, cpu_time_Decode = 0.0, total = 0.0;

    CiphertextRNS ct_in;
    PolyRNS c0_poly;
    PolyRNS c1_poly;
    ct_in.c0 = &c0_poly;
    ct_in.c1 = &c1_poly;
    c0_poly.n = c1_poly.n = N;
    c0_poly.L = c1_poly.L = LEVEL;

    for (size_t l = 0; l < LEVEL; ++l)
    {
        for (size_t i = 0; i < N; ++i)
        {
            size_t idx_c0 = l * N + i;
            size_t idx_c1 = LEVEL * N + l * N + i;
            c0_poly.coeffs[l][i] = in_buf[idx_c0];
            c1_poly.coeffs[l][i] = in_buf[idx_c1];
        }
    }

    // ===== Decrypt =====
    // struct timespec t1, t2;
    PolyRNS *dec = CKKS_Decrypt(&ct_in, sk_ntt, &mc, base_W, base_W_inv, base_Psi, base_Psi_inv);

    // ===== Decode =====
    ComplexDouble *msg = malloc(sizeof(ComplexDouble) * N / 2);
    msg = CKKS_Decode(dec, ct_in.c0, N, input_scale, &mc, prep);

    if (enc != 0)
    {
        msg = malloc(sizeof(ComplexDouble) * N / 2);
        for (int i = 0; i < N / 2; i++)
        {
            msg[i].real = msg_buf[i];
            msg[i].imag = 0.0;
        }
    }

    for (size_t i = 0; i < N / 2; ++i)
    {
        msg_real[i] = msg[i].real;
    }

    declassify((void *)msg_real, sizeof(double) * (N / 2));

    if (decrypt != 0)
    {
        int fd_out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ssize_t nw = write_full(fd_out, msg_real, msg_count);
        close(fd_out);
        if (nw != msg_count)
        {
            fprintf(stderr, "DEC Output size mismatch\n");
            return 1;
        }
        return 0;
    }

    classify((void *)msg, sizeof(ComplexDouble) * N / 2);
    for (int i = 0; i < N / 2; i++)
    {
        msg[i].real = msg[i].real;
        msg[i].imag = msg[i].imag;
    }

    // ===== Encode =====
    PolyRNS *pt = CKKS_Encode(msg, n, output_scale, &mc, prep);

    // ===== Re-encrypt =====
    CiphertextRNS *ct_out = CKKS_Encrypt(pt, sk_ntt, &mc, base_W, base_Psi);

    for (size_t l = 0; l < LEVEL; ++l)
    {
        for (size_t i = 0; i < N; ++i)
        {
            size_t idx_c0 = l * N + i;
            size_t idx_c1 = LEVEL * N + l * N + i;

            out_buf[idx_c0] = ct_out->c0->coeffs[l][i];
            out_buf[idx_c1] = ct_out->c1->coeffs[l][i];
        }
    }

    declassify((void *)out_buf, sizeof(uint64_t) * 2 * LEVEL * N);

    if (e2e != 0)
    {
        int fd_out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ssize_t nw = write_full(fd_out, out_buf, byte_count);
        close(fd_out);
        if (nw != byte_count)
        {
            fprintf(stderr, "Output size mismatch\n");
            return 1;
        }
    }

    return 0;
}
