#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

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
#define N 630
#endif

#define LEVEL 2

#define REENC_MAX 2
#define LWE_BIT_WIDTH 15

char *no_taint;
char *e2e = 0; // End-to-End evaluation flag. 1 : e2e mode, 0 : Local mode. e2e mode performs socket communication.
char *enc = 0;
char *dec = 0;
char *bitwise = 0;

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

int64_t my_llround(double x)
{
    if (x >= 0.0)
    {
        return (int64_t)floor(x + 0.5);
    }
    else
    {
        return (int64_t)ceil(x - 0.5);
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

// ======================= modulus chain 및 Poly =========================
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

// ========================== Random Sampling func. ==========================
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

// 에러 샘플링 후 int64_t 반환
int64_t SampleError()
{
    return (int64_t)my_llround(gaussian_noise(SIGMA));
}

// ======================================================================================
// [BinFHE Implementation] OpenFHE Style LWE for BinFHE
// ======================================================================================

typedef struct
{
    size_t n;    // Lattice dimension
    uint64_t q;  // Modulus
    uint64_t *a; // Vector a
    uint64_t b;  // Scalar b
} LWECiphertext;

// BinFHE: 1-bit Encryption (message m \in {0, 1})

LWECiphertext *BinFHE_Encrypt(uint64_t message_bit, uint64_t *sk, size_t n, uint64_t q)
{
    LWECiphertext *ct = (LWECiphertext *)malloc(sizeof(LWECiphertext));
    ct->n = n;
    ct->q = q;
    ct->a = (uint64_t *)malloc(sizeof(uint64_t) * n);
    // 1. Encode message m
    uint64_t delta = q / 4;
    uint64_t encoded_m = (message_bit & 1) ? delta : 0; // If 1 then q/4, else 0.

    // 2. Sample Error e
    int64_t err = SampleError();

    classify((void *)&err, sizeof(int64_t));

    uint64_t e_mod;
    if (err < 0)
        e_mod = submod(0, (uint64_t)(-err), q);
    else
        e_mod = (uint64_t)err;

    // 3. Encrypt: b = <a, s> + m*delta + e
    uint64_t inner_prod = 0;
    for (size_t i = 0; i < n; i++)
    {
        // Uniform Random 'a'
        ct->a[i] = (uint64_t)rand() % q;

        // Accumulate <a, s>
        uint64_t term = mulmod(ct->a[i], sk[i], q);
        inner_prod = addmod(inner_prod, term, q);
    }

    // b = inner_prod + encoded_m + e
    uint64_t temp = addmod(inner_prod, encoded_m, q);
    ct->b = addmod(temp, e_mod, q);

    return ct;
}

// BinFHE: Encrypt plaintext modulo p (e.g., p = 256)
LWECiphertext *BinFHE_EncryptPlain(uint64_t message, uint64_t p, uint64_t *sk, size_t n, uint64_t q)
{
    LWECiphertext *ct = (LWECiphertext *)malloc(sizeof(LWECiphertext));
    ct->n = n;
    ct->q = q;
    ct->a = (uint64_t *)malloc(sizeof(uint64_t) * n);

    uint64_t delta = q / p;
    uint64_t encoded_m = (message % p) * delta;

    int64_t err = SampleError();

    classify((void *)&err, sizeof(int64_t));

    uint64_t e_mod;
    if (err < 0)
        e_mod = submod(0, (uint64_t)(-err), q);
    else
        e_mod = (uint64_t)err;

    uint64_t inner_prod = 0;
    for (size_t i = 0; i < n; i++)
    {
        ct->a[i] = (uint64_t)rand() % q;
        uint64_t term = mulmod(ct->a[i], sk[i], q);
        inner_prod = addmod(inner_prod, term, q);
    }

    uint64_t temp = addmod(inner_prod, encoded_m, q);
    ct->b = addmod(temp, e_mod, q);

    return ct;
}

// BinFHE: Decrypt to 1-bit
uint64_t BinFHE_Decrypt(LWECiphertext *ct, uint64_t *sk)
{
    uint64_t q = ct->q;
    uint64_t inner_prod = 0;

    // Calculate <a, s>
    for (size_t i = 0; i < ct->n; i++)
    {
        uint64_t term = mulmod(ct->a[i], sk[i], q);
        inner_prod = addmod(inner_prod, term, q);
    }

    // Phase = b - <a, s> = m*delta + e
    uint64_t phase = submod(ct->b, inner_prod, q);

    uint64_t q_8 = q / 8;
    uint64_t q_3_8 = q_8 * 3;

    if (phase >= q_8 && phase <= q_3_8)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
// ======================================================================================

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
    // Optional E2E flag for parity with CKKS reenc engine
    e2e = getenv("E2E");
    enc = getenv("ENC");
    dec = getenv("DEC");
    bitwise = getenv("BITWISE");

    size_t lwe_n = 630;
    uint64_t *ct_buf = (uint64_t *)malloc(sizeof(uint64_t) * 630); // dummy alloc
    uint64_t *lwe_sk = (uint64_t *)malloc(sizeof(uint64_t) * lwe_n);
    uint64_t *msg_buf = (uint64_t *)malloc(630);               // dummy alloc
    uint64_t *out_buf = (uint64_t *)malloc(630);               // dummy alloc
    double *out_bits = (double *)malloc(sizeof(double) * 630); // dummy alloc

    classify((void *)lwe_sk, sizeof(uint64_t) * N);

    if (e2e != 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "Usage: %s <input_bin> <output_bin> <key_path>\n", argv[0]);
            return 1;
        }

        input_path = argv[1];
        output_path = argv[2];
        key_path = argv[3];

        // Read secret key
        int fd_key = open(key_path, O_RDONLY);
        if (fd_key < 0)
        {
            perror("open(key)");
            return 1;
        }
        struct stat st_key;
        if (fstat(fd_key, &st_key) < 0)
        {
            perror("fstat(key)");
            close(fd_key);
            return 1;
        }
        lwe_sk = (uint64_t *)malloc(sizeof(uint64_t) * lwe_n);
        if (!lwe_sk)
        {
            fprintf(stderr, "Key alloc failed\n");
            close(fd_key);
            return 1;
        }
        size_t key_bytes = sizeof(uint64_t) * lwe_n;
        if (read_full(fd_key, lwe_sk, key_bytes) != key_bytes)
        {
            fprintf(stderr, "Key read mismatch\n");
            close(fd_key);
            return 1;
        }
        close(fd_key);

        // Read input ciphertext [a || b]
        int fd_in = open(input_path, O_RDONLY);
        if (fd_in < 0)
        {
            perror("open(input)");
            return 1;
        }
        struct stat st_ct;
        if (fstat(fd_in, &st_ct) < 0)
        {
            perror("fstat(input)");
            close(fd_in);
            return 1;
        }
        size_t ct_bytes = (size_t)st_ct.st_size;
        size_t expected_ct_bytes = (lwe_n + 1) * sizeof(uint64_t);
        if (enc != 0 && ct_bytes != expected_ct_bytes)
        {
            if (ct_bytes % sizeof(uint64_t) != 0)
            {
                fprintf(stderr, "Batch input size mismatch: got %ld bytes\n", (long)ct_bytes);
                close(fd_in);
                return 1;
            }
            size_t msg_count = ct_bytes / sizeof(uint64_t);
            msg_buf = (uint64_t *)malloc(ct_bytes);
            if (!msg_buf)
            {
                fprintf(stderr, "Batch message alloc failed\n");
                close(fd_in);
                return 1;
            }
            if (read_full(fd_in, msg_buf, ct_bytes) != (ssize_t)ct_bytes)
            {
                fprintf(stderr, "Batch message read mismatch\n");
                close(fd_in);
                return 1;
            }
            close(fd_in);

            size_t out_count = msg_count * (bitwise ? LWE_BIT_WIDTH : 1) * (lwe_n + 1);
            size_t out_bytes = out_count * sizeof(uint64_t);
            out_buf = (uint64_t *)malloc(out_bytes);
            if (!out_buf)
            {
                fprintf(stderr, "Batch output alloc failed %zu\n", out_bytes);
                return 1;
            }

            // uint64_t q = 1152921504606748673ULL;
            uint64_t q = 1024ULL;
            for (size_t i = 0; i < msg_count; ++i)
            {
                if (bitwise)
                {
                    uint64_t msg = msg_buf[i];
                    for (size_t bit_idx = 0; bit_idx < LWE_BIT_WIDTH; ++bit_idx)
                    {
                        size_t shift = (LWE_BIT_WIDTH - 1) - bit_idx;
                        uint64_t bit = (msg >> shift) & 1;
                        LWECiphertext *ct_out = BinFHE_Encrypt(bit, lwe_sk, lwe_n, q);
                        size_t offset = ((i * LWE_BIT_WIDTH) + bit_idx) * (lwe_n + 1);
                        memcpy(&out_buf[offset], ct_out->a, sizeof(uint64_t) * lwe_n);
                        out_buf[offset + lwe_n] = ct_out->b;
                        free(ct_out->a);
                        free(ct_out);
                    }
                }
                else
                {
                    LWECiphertext *ct_out = BinFHE_EncryptPlain(msg_buf[i], 256, lwe_sk, lwe_n, q);
                    size_t offset = i * (lwe_n + 1);
                    memcpy(&out_buf[offset], ct_out->a, sizeof(uint64_t) * lwe_n);
                    out_buf[offset + lwe_n] = ct_out->b;
                    free(ct_out->a);
                    free(ct_out);
                }
            }
            free(msg_buf);

            if (e2e != 0)
            {
                int fd_out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out < 0)
                {
                    perror("open(output)");
                    return 1;
                }
                if (write_full(fd_out, out_buf, out_bytes) != (ssize_t)out_bytes)
                {
                    perror("write(output)");
                    close(fd_out);
                    return 1;
                }
                close(fd_out);
            }
            free(out_buf);
            return 0;
        }
        if (dec != 0 && ct_bytes != expected_ct_bytes)
        {
            if (ct_bytes % (off_t)expected_ct_bytes != 0)
            {
                fprintf(stderr, "Batch ciphertext size mismatch: expected multiple of %zu bytes, got %ld bytes\n",
                        expected_ct_bytes, (long)ct_bytes);
                close(fd_in);
                return 1;
            }
            size_t ct_count = ct_bytes / expected_ct_bytes;
            ct_buf = (uint64_t *)malloc(ct_bytes);
            if (!ct_buf)
            {
                fprintf(stderr, "Ciphertext alloc failed\n");
                close(fd_in);
                return 1;
            }
            if (read_full(fd_in, ct_buf, ct_bytes) != (ssize_t)ct_bytes)
            {
                fprintf(stderr, "Ciphertext read mismatch\n");
                close(fd_in);
                return 1;
            }
            close(fd_in);

            uint64_t q = 1024ULL;
            out_bits = (double *)malloc(sizeof(double) * ct_count);
            if (!out_bits)
            {
                fprintf(stderr, "Output alloc failed\n");
                return 1;
            }
            // printf("ct_count: %zu\n", ct_count);

            for (size_t i = 0; i < ct_count; ++i)
            {
                uint64_t *ct_ptr = ct_buf + i * (lwe_n + 1);
                LWECiphertext ct_in = {0};
                ct_in.n = lwe_n;
                ct_in.q = q;
                ct_in.a = ct_ptr;
                ct_in.b = ct_ptr[lwe_n];
                uint64_t bit = BinFHE_Decrypt(&ct_in, lwe_sk);
                out_bits[i] = (double)bit;
            }

            if (e2e != 0)
            {
                int fd_out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out < 0)
                {
                    perror("open(output)");
                    return 1;
                }
                size_t out_bytes = ct_count * sizeof(double);
                if (write_full(fd_out, out_bits, out_bytes) != (ssize_t)out_bytes)
                {
                    perror("write(output)");
                    close(fd_out);
                    return 1;
                }
                close(fd_out);
            }
            free(out_bits);
            free(ct_buf);
            return 0;
        }
        if ((size_t)ct_bytes != expected_ct_bytes)
        {
            fprintf(stderr, "Ciphertext size mismatch: expected %zu bytes, got %ld bytes\n",
                    expected_ct_bytes, (long)ct_bytes);
            close(fd_in);
            return 1;
        }
        ct_buf = (uint64_t *)malloc(expected_ct_bytes);
        if (!ct_buf)
        {
            fprintf(stderr, "Ciphertext alloc failed\n");
            close(fd_in);
            return 1;
        }
        if (read_full(fd_in, ct_buf, expected_ct_bytes) != (ssize_t)expected_ct_bytes)
        {
            fprintf(stderr, "Ciphertext read mismatch\n");
            close(fd_in);
            return 1;
        }
        close(fd_in);
    }

    LWECiphertext ct_in = {0};
    ct_in.n = lwe_n;
    // ct_in.q = 1152921504606748673ULL; // match generator modulus
    ct_in.q = 1024ULL; // match generator modulus
    ct_in.a = ct_buf;
    ct_in.b = ct_buf[lwe_n];

    // Decrypt -> Encrypt
    uint64_t bit = BinFHE_Decrypt(&ct_in, lwe_sk);

    if (enc != 0)
    {
        bit = ct_buf[lwe_n];
    }

    classify((void *)&bit, sizeof(uint64_t));

    LWECiphertext *ct_out = BinFHE_Encrypt(bit, lwe_sk, lwe_n, ct_in.q);

    declassify((void *)ct_out, sizeof(LWECiphertext) + sizeof(uint64_t) * lwe_n);

    if (e2e != 0)
    {
        // Write output ciphertext [a || b]
        int fd_out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (write_full(fd_out, ct_out->a, sizeof(uint64_t) * lwe_n) != (ssize_t)(sizeof(uint64_t) * lwe_n) ||
            write_full(fd_out, &ct_out->b, sizeof(uint64_t)) != (ssize_t)sizeof(uint64_t))
        {
            perror("write(output)");
            close(fd_out);
            return 1;
        }
        close(fd_out);
    }

    return 0;
}
