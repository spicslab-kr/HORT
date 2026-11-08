// controller.c (Server Mode)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>     // for read, write, close
#include <fcntl.h>      // for open, O_RDONLY, O_WRONLY, etc.
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>

#ifndef N
#define N 16384
#endif

#ifndef LEVEL
#define LEVEL 2
#endif

#ifdef USE_INSTRUMENTED_ENGINE
#define REENC_ENGINE_LD "../ld-linux-x86-64.so.2 --library-path . "
#else
#define REENC_ENGINE_LD ""
#endif

static const uint32_t SEV_REENC_MAGIC = 0x52454e43; // "RENC"
enum SevReencRequest {
    SEV_REQ_RLWE_COEFF_ENC  = 1,
    SEV_REQ_RLWE_COEFF_DEC  = 2,
    SEV_REQ_RLWE_COEFF_REENC  = 3,
    SEV_REQ_RLWE_SLOT_ENC  = 4,
    SEV_REQ_RLWE_SLOT_DEC  = 5,
    SEV_REQ_RLWE_SLOT_REENC = 6,
    SEV_REQ_LWE_ENC        = 7,
    SEV_REQ_LWE_DEC        = 8,
    SEV_REQ_LWE_REENC       = 9,
    SEV_REQ_RLWE_SLOT_DEC_LWE_CT = 10,
    SEV_REQ_LWE_DEC_SLOT_ENC = 11,
    SEV_REQ_LWE_DEC_COEFF_ENC = 12,
    SEV_REQ_RLWE_COEFF_DEC_LWE_CT = 13,
};

static const size_t LWE_BIT_WIDTH = 15;
#define CMD_BUF_SIZE 1024

double elapsed_ns(struct timespec start, struct timespec end) {
    time_t sec = end.tv_sec - start.tv_sec;
    long nsec = end.tv_nsec - start.tv_nsec;

    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    }

    return (double)sec * 1e9 + (double)nsec;
}

static int read_sysctl_int(const char* path, int* out) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -1;
    long val = 0;
    int rc = fscanf(f, "%ld", &val);
    fclose(f);
    if (rc != 1)
        return -1;
    if (val < 0)
        return -1;
    if (val > INT_MAX)
        val = INT_MAX;
    *out = (int)val;
    return 0;
}

static void tune_socket(int fd) {
    int one = 1;
    int snd = 0;
    int rcv = 0;
    if (read_sysctl_int("/proc/sys/net/core/wmem_max", &snd) != 0)
        snd = 16 * 1024 * 1024;
    if (read_sysctl_int("/proc/sys/net/core/rmem_max", &rcv) != 0)
        rcv = 16 * 1024 * 1024;

    // Try to raise socket buffers to the kernel maximum.
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

// Writes exactly 'count' bytes to the file descriptor 'fd'.
static ssize_t write_full(int fd, const void* buf, size_t count) {
    size_t left = count;
    const char* ptr = (const char*)buf;

    while (left > 0) {
        ssize_t w = write(fd, ptr, left);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0) // Should not happen for files unless disk full, etc.
            break;
        left -= w;
        ptr  += w;
    }
    return (ssize_t)(count - left);
}

// Reads exactly 'count' bytes from the file descriptor 'fd'.
static ssize_t read_full(int fd, void* buf, size_t count) {
    size_t left = count;
    char* ptr = (char*)buf;

    while (left > 0) {
        ssize_t r = read(fd, ptr, left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0) // EOF
            break;
        left -= r;
        ptr  += r;
    }
    return (ssize_t)(count - left);
}

static void print_u64_bits(const char* label, uint64_t value) {
    // printf("%s", label);
    for (int i = 63; i >= 0; --i) {
        // printf("%u", (unsigned)((value >> i) & 1ULL));
    }
    // printf("\n");
}

static int read_request_header(int fd, uint32_t* req_type, uint64_t* payload_bytes) {
    uint32_t magic = 0;
    ssize_t r = read_full(fd, &magic, sizeof(magic));
    if (r == 0)
        return 0;
    if (r != (ssize_t)sizeof(magic)) {
        perror("read_full (magic)");
        return -1;
    }
    if (magic != SEV_REENC_MAGIC) {
        fprintf(stderr, "Invalid request magic: 0x%08x\n", magic);
        return -1;
    }
    if (read_full(fd, req_type, sizeof(*req_type)) != (ssize_t)sizeof(*req_type)) {
        perror("read_full (req_type)");
        return -1;
    }
    if (read_full(fd, payload_bytes, sizeof(*payload_bytes)) != (ssize_t)sizeof(*payload_bytes)) {
        perror("read_full (payload_bytes)");
        return -1;
    }
    return 1;
}

// Executes the reenc_engine for generating initial ciphertext from message received from server.
static int run_reenc_engine_enc(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_db_mueoc && E2E=1 ENC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the slot-encoding reenc_engine for generating initial ciphertext from message received from server.
static int run_reenc_engine_slot_enc(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 ENC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the slot-encoding reenc_engine for generating initial ciphertext from message received from server.
static int run_reenc_engine_slot_dec(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 DEC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes slot-decoding reenc_engine with explicit input scale (argv[4], argv[5])
static int run_reenc_engine_slot_dec_scale(const char* in_path, const char* out_path, const char* key_path,
                                           long double input_scale) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 DEC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s %.0Lf %.0Lf",
             in_path, out_path, key_path, input_scale, input_scale);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the reenc_engine for decoding ciphertext to plaintext coefficients.
static int run_reenc_engine_dec(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_db_mueoc && E2E=1 DEC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the lwe reenc_engine for generating initial ciphertext from message received from server.
static int run_reenc_engine_lwe_enc(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_lwe && E2E=1 ENC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_lwe %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the lwe reenc_engine in dec mode to output plaintext bits.
static int run_reenc_engine_lwe_dec(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_lwe && E2E=1 DEC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_lwe %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the lwe reenc_engine in bitwise enc mode (64 LWE per input value).
static int run_reenc_engine_lwe_enc_bitwise(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_lwe && E2E=1 ENC=1 BITWISE=1 " REENC_ENGINE_LD "./reenc_e2e_engine_lwe %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the reenc_engine binary on the specified input and output files.
static int run_reenc_engine(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_db_mueoc && E2E=1 " REENC_ENGINE_LD "./reenc_e2e_engine_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the slot-encoding reenc_engine binary on the specified input and output files.
static int run_reenc_engine_slot(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes slot-encoding reenc_engine with explicit input/output scales (argv[4], argv[5])
static int run_reenc_engine_slot_rescale(const char* in_path, const char* out_path, const char* key_path,
                                         long double input_scale, long double output_scale, int enc_only) {
    char cmd[512];
    if (enc_only) {
        snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 ENC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s %.0Lf %.0Lf",
                 in_path, out_path, key_path, input_scale, output_scale);
    } else {
        snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_slot_db_mueoc && E2E=1 " REENC_ENGINE_LD "./reenc_e2e_engine_slot_db_mueoc %s %s %s %.0Lf %.0Lf",
                 in_path, out_path, key_path, input_scale, output_scale);
    }
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine_slot (rescale) failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes the lwe reenc_engine binary on the specified input and output files.
static int run_reenc_engine_lwe(const char* in_path, const char* out_path, const char* key_path) {
    char cmd[512];
    // Simple: ./reenc_engine input.bin output.bin
    snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_lwe && E2E=1 " REENC_ENGINE_LD "./reenc_e2e_engine_lwe %s %s %s", in_path, out_path, key_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

// Executes reenc_engine with explicit input/output scales (passed as argv[4], argv[5])
static int run_reenc_engine_rescale(const char* in_path, const char* out_path, const char* key_path,
                                    long double input_scale, long double output_scale, int enc_only) {
    char cmd[512];
    if (enc_only) {
        snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_db_mueoc && E2E=1 ENC=1 " REENC_ENGINE_LD "./reenc_e2e_engine_db_mueoc %s %s %s %.0Lf %.0Lf",
                 in_path, out_path, key_path, input_scale, output_scale);
    } else {
        snprintf(cmd, sizeof(cmd), "cd ./reenc_e2e_engine_db_mueoc && E2E=1 " REENC_ENGINE_LD "./reenc_e2e_engine_db_mueoc %s %s %s %.0Lf %.0Lf",
                 in_path, out_path, key_path, input_scale, output_scale);
    }
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "reenc_engine (rescale) failed with code %d\n", ret);
        return -1;
    }
    return 0;
}

typedef struct {
    size_t L;       // length of Chain
    uint64_t* qs;   // uint64_t array
} ModulusChain;

typedef struct {
    size_t n;           // number of coefficients
    size_t L;           // number of qs
    uint64_t coeffs[LEVEL][N]; // uint64_t 2D array
} PolyRNS;

void SampleSecretKey(PolyRNS* sk, size_t ringDim, const ModulusChain* mc) {
    int* temp_key = malloc(sizeof(int) * N);
    size_t n = ringDim;
    for (size_t i = 0; i < n; ++i) {
        temp_key[i] = (rand() % 3) - 1;
    }
    for (size_t l = 0; l < sk->L; ++l) {
        uint64_t q = mc->qs[l];
        for (size_t i = 0; i < n; ++i) {
            int r = temp_key[i];
            if (r >= 0) sk->coeffs[l][i] = (uint64_t)r;
            else sk->coeffs[l][i] = q - 1; 
        }
    }
}

static int ValidateSecretKey(const uint64_t* secret_key, size_t ringDim, const ModulusChain* mc) {
    if (!secret_key || !mc || mc->L == 0)
        return 0;

    const uint64_t q0 = mc->qs[0];
    for (size_t i = 0; i < ringDim; ++i) {
        uint64_t v0 = secret_key[i];
        int ternary = 0;
        if (v0 == 0) {
            ternary = 0;
        }
        else if (v0 == 1) {
            ternary = 1;
        }
        else if (v0 == q0 - 1) {
            ternary = -1;
        }
        else {
            return 0;
        }

        for (size_t l = 1; l < mc->L; ++l) {
            uint64_t expected = (ternary >= 0) ? (uint64_t)ternary : (mc->qs[l] - 1);
            uint64_t coeff = secret_key[l * ringDim + i];
            if (coeff != expected || coeff >= mc->qs[l])
                return 0;
        }
    }
    return 1;
}

int main(int argc, char* argv[]) {
    struct timespec t1, t2;
    // Arguments check
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <listen_port> <max_iters> <engine_input_dir>\n"
            "  listen_port     : TCP port to listen on\n"
            "  max_iters       : number of requests to process\n"
            "  engine_input_dir: directory for temporary input/output files\n",
            argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    long max_iters = atol(argv[2]);
    const char* dir = argv[3];

    srand(time(NULL));
    
    uint64_t qs[LEVEL] = {
#if N == 16384
        1152921504606748673ULL,
        1099503894529ULL
#elif N == 65536
        1152921504606584833ULL,
        1099500617729ULL
#else
#error "Unsupported controller N; add the matching OpenFHE RNS moduli"
#endif
    };
    ModulusChain mc = {LEVEL, qs};
    
    PolyRNS* sk = malloc(sizeof(PolyRNS));
    sk->n = N;
    sk->L = LEVEL;
    
    size_t key_entries = (size_t)LEVEL * (size_t)N;
    uint64_t* secret_key = malloc(sizeof(uint64_t) * key_entries);
    if (!secret_key) {
        fprintf(stderr, "secret key alloc failed\n");
        free(sk);
        return 1;
    }
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "/cipherfix/secret_key_db_mueoc.bin");
    char lwe_key_path[512];
    snprintf(lwe_key_path, sizeof(lwe_key_path), "/cipherfix/lwe_secret_key_db_mueoc.bin");
    printf("[Controller] CKKS key path: %s\n", key_path);
    printf("[Controller] LWE key path: %s\n", lwe_key_path);
    size_t key_size = sizeof(uint64_t) * key_entries;

    int fd_existing_key = open(key_path, O_RDONLY);
    if (fd_existing_key >= 0) {
        ssize_t nread_key = read_full(fd_existing_key, secret_key, key_size);
        close(fd_existing_key);
        if (nread_key == (ssize_t)key_size && ValidateSecretKey(secret_key, N, &mc)) {
            memcpy(sk->coeffs, secret_key, key_size);
            printf("[Controller] Loaded existing %s (%zu bytes)\n", key_path, key_size);
        }
        else if (nread_key == (ssize_t)key_size) {
            fprintf(stderr, "[Controller] Existing %s is incompatible with current moduli; regenerating\n",
                    key_path);
            SampleSecretKey(sk, N, &mc);
            memcpy(secret_key, sk->coeffs, key_size);
        }
        else {
            fprintf(stderr, "[Controller] Existing %s size mismatch: expected %zu, got %zd; regenerating\n",
                    key_path, key_size, nread_key);
            SampleSecretKey(sk, N, &mc);
            memcpy(secret_key, sk->coeffs, key_size);
        }
    }
    else {
        SampleSecretKey(sk, N, &mc);
        memcpy(secret_key, sk->coeffs, key_size);
    }
    
    int fd_key = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_key < 0) {
        perror("open(secret_key.bin)");
        free(sk);
        return 1;
    }
    
    if (write_full(fd_key, secret_key, key_size) != (ssize_t)key_size) {
        perror("write(secret_key.bin)");
        close(fd_key);
        free(secret_key);
        free(sk);
        return 1;
    }
    close(fd_key);
    
    // printf("[Controller] Secret Key saved to %s (%zu bytes)\n", key_path, key_size);

    const size_t lwe_n = 630;  // must match reenc_e2e_engine_lwe.c
    if (N < lwe_n) {
        fprintf(stderr, "LWE n (%zu) exceeds RLWE N (%d)\n", lwe_n, N);
        free(secret_key);
        free(sk);
        return 1;
    }
    uint64_t* lwe_secret_key = malloc(sizeof(uint64_t) * lwe_n);
    if (!lwe_secret_key) {
        fprintf(stderr, "lwe secret key alloc failed\n");
        free(secret_key);
        free(sk);
        return 1;
    }
    for (size_t i = 0; i < lwe_n; ++i) {
        lwe_secret_key[i] = secret_key[i];
    }
    int fd_lwe = open(lwe_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_lwe < 0) {
        perror("open(lwe_secret_key.bin)");
        free(lwe_secret_key);
        free(secret_key);
        free(sk);
        return 1;
    }
    size_t lwe_key_size = sizeof(uint64_t) * lwe_n;
    if (write_full(fd_lwe, lwe_secret_key, lwe_key_size) != (ssize_t)lwe_key_size) {
        perror("write(lwe_secret_key.bin)");
        close(fd_lwe);
        free(lwe_secret_key);
        free(secret_key);
        free(sk);
        return 1;
    }
    close(fd_lwe);
    free(lwe_secret_key);
    // printf("[Controller] LWE Secret Key saved to %s (%zu bytes)\n", lwe_key_path, lwe_key_size);
    free(sk);

    const size_t coeff_per_ct = 2 * (size_t)LEVEL * (size_t)N;
    size_t byte_count = coeff_per_ct * sizeof(uint64_t);
    size_t msg_count = N / 2 * sizeof(double);
    size_t coeff_msg_count = N / 2 * sizeof(double);
    size_t slot_u64_count = N / 2;
    size_t slot_u64_bytes = slot_u64_count * sizeof(uint64_t);
    size_t lwe_ct_u64 = lwe_n + 1;
    size_t lwe_ct_batch = slot_u64_count * LWE_BIT_WIDTH * lwe_ct_u64;
    size_t lwe_ct_bytes = lwe_ct_batch * sizeof(uint64_t);
    size_t lwe_ct_slot_bytes = slot_u64_count * lwe_ct_u64 * sizeof(uint64_t);
    size_t lwe_bit_count = slot_u64_count * LWE_BIT_WIDTH;
    size_t lwe_bit_bytes = lwe_bit_count * sizeof(double);

    // Build temp file paths
    char in_path[512], out_path[512];
    snprintf(in_path,  sizeof(in_path),  "/cipherfix/reenc_in.bin");
    snprintf(out_path, sizeof(out_path), "/cipherfix/reenc_out.bin");

    // 1. Create Listening Socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    // Set SO_REUSEADDR
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);

    // 2. Bind
    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    // 3. Listen
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("Controller listening on port %d... Waiting for connection.\n", listen_port);

    // 4. Accept
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (conn_fd < 0) {
        perror("accept");
        close(listen_fd);
        return 1;
    }
    // tune_socket(conn_fd);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Connected from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
    uint64_t key_count = key_entries;
    if (write_full(conn_fd, &key_count, sizeof(key_count)) != sizeof(key_count)) {
        fprintf(stderr, "Failed to send secret key header\n");
        free(secret_key);
        close(conn_fd);
        close(listen_fd);
        return 1;
    }
    if (write_full(conn_fd, secret_key, key_size) != (ssize_t)key_size) {
        fprintf(stderr, "Failed to send secret key body\n");
        free(secret_key);
        close(conn_fd);
        close(listen_fd);
        return 1;
    }
    free(secret_key);

    // Allocate buffers
    uint64_t* in_buf  = (uint64_t*)malloc(byte_count);
    uint64_t* out_buf = (uint64_t*)malloc(byte_count);

    double* msg_buf = (double*)malloc(msg_count);
    double* coeff_msg_buf = (double*)malloc(coeff_msg_count);
    double* bit_buf = (double*)malloc(lwe_bit_bytes);

    if (!in_buf || !out_buf || !msg_buf || !coeff_msg_buf || !bit_buf) {
        fprintf(stderr, "malloc failed\n");
        close(conn_fd);
        close(listen_fd);
        free(in_buf);
        free(out_buf);
        free(msg_buf);
        free(coeff_msg_buf);
        free(bit_buf);
        return 1;
    }

    uint8_t* lwe_buf = NULL;
    size_t lwe_buf_cap = 0;

    for (long iter = 0; iter < max_iters; ++iter) {
        uint32_t req_type = 0;
        uint64_t payload_bytes = 0;
        int hdr = read_request_header(conn_fd, &req_type, &payload_bytes);
        if (hdr == 0) {
            // printf("Remote side closed connection\n");
            break;
        }
        if (hdr < 0) {
            fprintf(stderr, "Failed to read request header\n");
            break;
        }

        if (req_type == SEV_REQ_RLWE_COEFF_ENC) {
            // printf("Received RLWE coeff enc request\n");
            if (payload_bytes != coeff_msg_count) {
                fprintf(stderr, "RLWE coeff enc size mismatch: expected %zu, got %llu\n",
                        coeff_msg_count, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t r = read_full(conn_fd, coeff_msg_buf, coeff_msg_count);
            if (r != (ssize_t)coeff_msg_count) {
                fprintf(stderr, "Failed to read RLWE coeff enc payload (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, coeff_msg_buf, coeff_msg_count);
            close(fd_in_file);
            if (nw != (ssize_t)coeff_msg_count) {
                fprintf(stderr, "Failed to write RLWE coeff enc input file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_enc(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_enc failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE coeff enc time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, out_buf, byte_count);
            close(fd_out_file);
            if (nr != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeff enc output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_COEFF_DEC) {
            // printf("Received RLWE coeff dec request\n");
            if (payload_bytes != byte_count) {
                fprintf(stderr, "RLWE coeff dec size mismatch: expected %zu, got %llu\n",
                        byte_count, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeff dec payload (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeff dec input file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_dec(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_dec failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE coeff dec time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, coeff_msg_buf, coeff_msg_count);
            close(fd_out_file);
            if (nr != (ssize_t)coeff_msg_count) {
                fprintf(stderr, "Failed to read RLWE coeff dec output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, coeff_msg_buf, coeff_msg_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_COEFF_REENC) {
            // printf("Received RLWE coeff reenc request\n");
            size_t expected_payload = sizeof(long double) * 2 + byte_count;
            if (payload_bytes != expected_payload) {
                fprintf(stderr, "RLWE coeff reenc size mismatch: expected %zu, got %llu\n",
                        expected_payload, (unsigned long long)payload_bytes);
                break;
            }

            long double scales[2] = {0};
            if (read_full(conn_fd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
                fprintf(stderr, "Failed to read RLWE coeff scales\n");
                break;
            }
            long double input_scale  = scales[0];
            long double output_scale = scales[1];

            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeff payload (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeff input file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_rescale(in_path, out_path, key_path, input_scale, output_scale, 0) != 0) {
                fprintf(stderr, "run_reenc_engine_rescale failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE coeff reenc time = %.2f ms (in_scale=%.0Lf, out_scale=%.0Lf)\n", reenc_time / 1e6, input_scale, output_scale);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, out_buf, byte_count);
            close(fd_out_file);
            if (nr != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeff reenc output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_SLOT_ENC) {
            // printf("Received RLWE slot enc request\n");
            if (payload_bytes != msg_count) {
                fprintf(stderr, "RLWE slot enc size mismatch: expected %zu, got %llu\n",
                        msg_count, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t r = read_full(conn_fd, msg_buf, msg_count);
            if (r != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read RLWE enc payload (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, msg_buf, msg_count);
            close(fd_in_file);
            if (nw != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to write RLWE enc input file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_slot_enc(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_slot_enc failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE slot enc time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, out_buf, byte_count);
            close(fd_out_file);
            if (nr != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE enc output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_SLOT_DEC) {
            // printf("Received RLWE slot dec request\n");
            if (payload_bytes != byte_count) {
                fprintf(stderr, "RLWE slot dec size mismatch: expected %zu, got %llu\n",
                        byte_count, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeffs (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeffs file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_slot_dec(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_slot_dec failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE slot dec time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, msg_buf, msg_count);
            close(fd_out_file);
            if (nr != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read RLWE output (got %zd) expected %zd\n", nr, (ssize_t)msg_count);
                break;
            }

            if (write_full(conn_fd, msg_buf, msg_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_SLOT_DEC_LWE_CT) {
            // printf("Received RLWE slot dec + LWE bitwise enc request\n");
            if (payload_bytes != byte_count + sizeof(long double)) {
                fprintf(stderr, "RLWE slot dec+lwe size mismatch: expected %zu, got %llu\n",
                        byte_count + sizeof(long double), (unsigned long long)payload_bytes);
                break;
            }

            long double input_scale = 0.0L;
            if (read_full(conn_fd, &input_scale, sizeof(input_scale)) != (ssize_t)sizeof(input_scale)) {
                fprintf(stderr, "Failed to read input scale\n");
                break;
            }
            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeffs (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeffs file\n");
                break;
            }

            struct timespec t_total_start, t_total_end;
            clock_gettime(CLOCK_MONOTONIC, &t_total_start);

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_slot_dec_scale(in_path, out_path, key_path, input_scale) != 0) {
                fprintf(stderr, "run_reenc_engine_slot_dec_scale failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE slot dec time = %.2f ms (scale=%.0Lf)\n", reenc_time / 1e6, input_scale);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, msg_buf, msg_count);
            close(fd_out_file);
            if (nr != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read RLWE output (got %zd) expected %zd\n", nr, (ssize_t)msg_count);
                break;
            }

            for (size_t i = 0; i < slot_u64_count; ++i) {
                uint64_t bits = 0;
                memcpy(&bits, &msg_buf[i], sizeof(bits));
                out_buf[i] = bits;
            }
            // printf("Extracted %zu slots for LWE bitwise encryption\n", slot_u64_count);
            // if (slot_u64_count >= 2) {
            //     print_u64_bits("[Controller bits slot 0] ", out_buf[0]);
            //     print_u64_bits("[Controller bits slot 1] ", out_buf[1]);
            // }

            int fd_lwe_in = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_lwe_in < 0) {
                perror("open(lwe_in)");
                break;
            }
            ssize_t nw_lwe = write_full(fd_lwe_in, out_buf, slot_u64_bytes);
            close(fd_lwe_in);
            if (nw_lwe != (ssize_t)slot_u64_bytes) {
                fprintf(stderr, "Failed to write LWE plaintexts\n");
                break;
            }
            // printf("Wrote %zu bytes of LWE plaintexts for bitwise encryption\n", slot_u64_bytes);

            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_lwe_enc_bitwise(in_path, out_path, lwe_key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_lwe_enc_bitwise failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("LWE bitwise enc time = %.2f ms\n", reenc_time / 1e6);

            clock_gettime(CLOCK_MONOTONIC, &t_total_end);
            double total_time = elapsed_ns(t_total_start, t_total_end);
            // printf("RLWE->LWE total time = %.2f ms\n", total_time / 1e6);


            if (lwe_ct_bytes > lwe_buf_cap) {
                uint8_t* new_buf = (uint8_t*)realloc(lwe_buf, lwe_ct_bytes);
                if (!new_buf) {
                    fprintf(stderr, "lwe buffer alloc failed\n");
                    break;
                }
                lwe_buf = new_buf;
                lwe_buf_cap = lwe_ct_bytes;
            }

            int fd_lwe_out = open(out_path, O_RDONLY);
            if (fd_lwe_out < 0) {
                perror("open(lwe_out)");
                break;
            }
            double readtime = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            ssize_t nr_lwe = read_full(fd_lwe_out, lwe_buf, lwe_ct_bytes);
            close(fd_lwe_out);
            if (nr_lwe != (ssize_t)lwe_ct_bytes) {
                fprintf(stderr, "Failed to read LWE ciphertexts (got %zd)\n", nr_lwe);
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            readtime = elapsed_ns(t1, t2);

            double writetime = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (write_full(conn_fd, lwe_buf, lwe_ct_bytes) < 0) {
                perror("write_full (socket)");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            writetime = elapsed_ns(t1, t2);

            // printf("LWE ciphertext read time = %.2f ms, write time = %.2f ms\n", readtime / 1e6, writetime / 1e6);
            fflush(stdout);
            continue;
        }

        if (req_type == SEV_REQ_RLWE_COEFF_DEC_LWE_CT) {
            // printf("Received RLWE coeff dec + LWE bitwise enc request\n");
            if (payload_bytes != byte_count) {
                fprintf(stderr, "RLWE coeff dec+lwe size mismatch: expected %zu, got %llu\n",
                        byte_count, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeffs (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeffs file\n");
                break;
            }

            if (run_reenc_engine_dec(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_dec failed\n");
                break;
            }
            // printf("RLWE coeff dec completed\n");

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, msg_buf, msg_count);
            close(fd_out_file);
            if (nr != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read RLWE output (got %zd) expected %zd\n", nr, (ssize_t)msg_count);
                break;
            }

            for (size_t i = 0; i < slot_u64_count; ++i) {
                uint64_t bits = 0;
                memcpy(&bits, &msg_buf[i], sizeof(bits));
                out_buf[i] = bits;
            }

            int fd_lwe_in = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_lwe_in < 0) {
                perror("open(lwe_in)");
                break;
            }
            ssize_t nw_lwe = write_full(fd_lwe_in, out_buf, slot_u64_bytes);
            close(fd_lwe_in);
            if (nw_lwe != (ssize_t)slot_u64_bytes) {
                fprintf(stderr, "Failed to write LWE plaintexts\n");
                break;
            }

            if (run_reenc_engine_lwe_enc_bitwise(in_path, out_path, lwe_key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_lwe_enc_bitwise failed\n");
                break;
            }
            // printf("LWE bitwise enc completed\n");

            if (lwe_ct_bytes > lwe_buf_cap) {
                uint8_t* new_buf = (uint8_t*)realloc(lwe_buf, lwe_ct_bytes);
                if (!new_buf) {
                    fprintf(stderr, "lwe buffer alloc failed\n");
                    break;
                }
                lwe_buf = new_buf;
                lwe_buf_cap = lwe_ct_bytes;
            }
            fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr_lwe = read_full(fd_out_file, lwe_buf, lwe_ct_bytes);
            close(fd_out_file);
            if (nr_lwe != (ssize_t)lwe_ct_bytes) {
                fprintf(stderr, "Failed to read LWE ciphertexts (got %zd)\n", nr_lwe);
                break;
            }

            if (write_full(conn_fd, msg_buf, msg_count) < 0) {
                perror("write_full (socket msg_buf)");
                break;
            }
            if (write_full(conn_fd, lwe_buf, lwe_ct_bytes) < 0) {
                perror("write_full (socket lwe_buf)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_RLWE_SLOT_REENC) {
            // printf("Received RLWE slot reenc request\n");
            size_t expected_payload = sizeof(long double) * 2 + byte_count;
            if (payload_bytes != expected_payload) {
                fprintf(stderr, "RLWE slot reenc size mismatch: expected %zu, got %llu\n",
                        expected_payload, (unsigned long long)payload_bytes);
                break;
            }

            long double scales[2] = {0};
            if (read_full(conn_fd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
                fprintf(stderr, "Failed to read RLWE scales\n");
                break;
            }
            long double input_scale  = scales[0];
            long double output_scale = scales[1];

            ssize_t r = read_full(conn_fd, in_buf, byte_count);
            if (r != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE coeffs (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, in_buf, byte_count);
            close(fd_in_file);
            if (nw != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to write RLWE coeffs file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_slot_rescale(in_path, out_path, key_path, input_scale, output_scale, 0) != 0) {
                fprintf(stderr, "run_reenc_engine_slot_rescale failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE slot reenc time = %.2f ms (in_scale=%.0Lf, out_scale=%.0Lf)\n", reenc_time / 1e6, input_scale, output_scale);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, out_buf, byte_count);
            close(fd_out_file);
            if (nr != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_LWE_DEC_SLOT_ENC) {
            // printf("Received LWE dec + slot enc request\n");
            // printf("[Controller] expected LWE payload bytes=%zu\n", lwe_ct_slot_bytes);
            if (payload_bytes != lwe_ct_slot_bytes) {
                fprintf(stderr, "LWE dec+slot enc size mismatch: expected %zu, got %llu\n",
                        lwe_ct_slot_bytes, (unsigned long long)payload_bytes);
                break;
            }

            if (lwe_ct_slot_bytes > lwe_buf_cap) {
                uint8_t* new_buf = (uint8_t*)realloc(lwe_buf, lwe_ct_slot_bytes);
                if (!new_buf) {
                    fprintf(stderr, "lwe buffer alloc failed\n");
                    break;
                }
                lwe_buf = new_buf;
                lwe_buf_cap = lwe_ct_slot_bytes;
            }

            ssize_t r = read_full(conn_fd, lwe_buf, lwe_ct_slot_bytes);
            if (r != (ssize_t)lwe_ct_slot_bytes) {
                fprintf(stderr, "Failed to read LWE ciphertexts (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, lwe_buf, lwe_ct_slot_bytes);
            close(fd_in_file);
            if (nw != (ssize_t)lwe_ct_slot_bytes) {
                fprintf(stderr, "Failed to write LWE ciphertext file\n");
                break;
            }
            // printf("Wrote %zu bytes of LWE ciphertexts for decryption\n", lwe_ct_slot_bytes);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_lwe_dec(in_path, out_path, lwe_key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_lwe_dec failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            double reenc_time = elapsed_ns(t1, t2);
            // printf("LWE dec time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, msg_buf, msg_count);
            close(fd_out_file);
            if (nr != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read LWE dec output (got %zd)\n", nr);
                break;
            }

            int fd_slot_in = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_slot_in < 0) {
                perror("open(in_path) for slot enc");
                break;
            }
            ssize_t nw_slot = write_full(fd_slot_in, msg_buf, msg_count);
            close(fd_slot_in);
            if (nw_slot != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to write slot message file\n");
                break;
            }

            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (run_reenc_engine_slot_enc(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_slot_enc failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("RLWE slot enc time = %.2f ms\n", reenc_time / 1e6);

            int fd_out_file2 = open(out_path, O_RDONLY);
            if (fd_out_file2 < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr2 = read_full(fd_out_file2, out_buf, byte_count);
            close(fd_out_file2);
            if (nr2 != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE enc output (got %zd)\n", nr2);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_LWE_DEC_COEFF_ENC) {
            // printf("Received LWE dec + coeff enc request\n");
            size_t expected_payload = msg_count + lwe_ct_bytes;
            if (payload_bytes != expected_payload) {
                fprintf(stderr, "LWE dec+coeff enc size mismatch: expected %zu, got %llu\n",
                        expected_payload, (unsigned long long)payload_bytes);
                break;
            }

            ssize_t nr0 = read_full(conn_fd, msg_buf, msg_count);
            if (nr0 != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to read base slot values (got %zd)\n", nr0);
                break;
            }

            if (lwe_ct_bytes > lwe_buf_cap) {
                uint8_t* new_buf = (uint8_t*)realloc(lwe_buf, lwe_ct_bytes);
                if (!new_buf) {
                    fprintf(stderr, "lwe buffer alloc failed\n");
                    break;
                }
                lwe_buf = new_buf;
                lwe_buf_cap = lwe_ct_bytes;
            }
            ssize_t r = read_full(conn_fd, lwe_buf, lwe_ct_bytes);
            if (r != (ssize_t)lwe_ct_bytes) {
                fprintf(stderr, "Failed to read LWE ciphertexts (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, lwe_buf, lwe_ct_bytes);
            close(fd_in_file);
            if (nw != (ssize_t)lwe_ct_bytes) {
                fprintf(stderr, "Failed to write LWE ciphertext file\n");
                break;
            }

            if (run_reenc_engine_lwe_dec(in_path, out_path, lwe_key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_lwe_dec failed\n");
                break;
            }
            // printf("LWE decryption completed\n");

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, bit_buf, lwe_bit_bytes);
            close(fd_out_file);
            if (nr != (ssize_t)lwe_bit_bytes) {
                fprintf(stderr, "Failed to read LWE bits (got %zd)\n", nr);
                break;
            }

            for (size_t slot = 0; slot < slot_u64_count; ++slot) {
                uint64_t raw = 0;
                memcpy(&raw, &msg_buf[slot], sizeof(raw));
                size_t base = slot * LWE_BIT_WIDTH;
                for (size_t b = 0; b < LWE_BIT_WIDTH; ++b) {
                    uint64_t bit = (uint64_t)llround(bit_buf[base + b]) & 1ULL;
                    uint64_t mask = 1ULL << b;
                    if (bit)
                        raw |= mask;
                    else
                        raw &= ~mask;
                }
                memcpy(&msg_buf[slot], &raw, sizeof(raw));
            }

            fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path) for coeff enc");
                break;
            }
            nw = write_full(fd_in_file, msg_buf, msg_count);
            close(fd_in_file);
            if (nw != (ssize_t)msg_count) {
                fprintf(stderr, "Failed to write coeff enc input\n");
                break;
            }

            if (run_reenc_engine_enc(in_path, out_path, key_path) != 0) {
                fprintf(stderr, "run_reenc_engine_enc failed\n");
                break;
            }
            // printf("RLWE coefficient encryption completed\n");

            fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            nr = read_full(fd_out_file, out_buf, byte_count);
            close(fd_out_file);
            if (nr != (ssize_t)byte_count) {
                fprintf(stderr, "Failed to read RLWE enc output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, out_buf, byte_count) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        if (req_type == SEV_REQ_LWE_ENC || req_type == SEV_REQ_LWE_REENC) {
            if (payload_bytes == 0) {
                fprintf(stderr, "Invalid LWE payload size\n");
                break;
            }
            if (payload_bytes > (uint64_t)SIZE_MAX) {
                fprintf(stderr, "LWE payload too large\n");
                break;
            }
            size_t lwe_payload = (size_t)payload_bytes;
            if (lwe_payload > lwe_buf_cap) {
                uint8_t* new_buf = (uint8_t*)realloc(lwe_buf, lwe_payload);
                if (!new_buf) {
                    fprintf(stderr, "LWE buffer alloc failed\n");
                    break;
                }
                lwe_buf = new_buf;
                lwe_buf_cap = lwe_payload;
            }

            ssize_t r = read_full(conn_fd, lwe_buf, lwe_payload);
            if (r != (ssize_t)lwe_payload) {
                fprintf(stderr, "Failed to read LWE payload (got %zd)\n", r);
                break;
            }

            int fd_in_file = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in_file < 0) {
                perror("open(in_path)");
                break;
            }
            ssize_t nw = write_full(fd_in_file, lwe_buf, lwe_payload);
            close(fd_in_file);
            if (nw != (ssize_t)lwe_payload) {
                fprintf(stderr, "Failed to write LWE input file\n");
                break;
            }

            double reenc_time = 0.0;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int ret = (req_type == SEV_REQ_LWE_ENC)
                          ? run_reenc_engine_lwe_enc(in_path, out_path, lwe_key_path)
                          : run_reenc_engine_lwe(in_path, out_path, lwe_key_path);
            if (ret != 0) {
                fprintf(stderr, "run_reenc_engine_lwe failed\n");
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
            reenc_time = elapsed_ns(t1, t2);
            // printf("LWE %s time = %.2f ms\n", req_type == SEV_REQ_LWE_ENC ? "enc" : "reenc", reenc_time / 1e6);

            int fd_out_file = open(out_path, O_RDONLY);
            if (fd_out_file < 0) {
                perror("open(out_path)");
                break;
            }
            ssize_t nr = read_full(fd_out_file, lwe_buf, lwe_payload);
            close(fd_out_file);
            if (nr != (ssize_t)lwe_payload) {
                fprintf(stderr, "Failed to read LWE output (got %zd)\n", nr);
                break;
            }

            if (write_full(conn_fd, lwe_buf, lwe_payload) < 0) {
                perror("write_full (socket)");
                break;
            }
            continue;
        }

        fprintf(stderr, "Unknown request type: %u\n", req_type);
        break;
    }

    // Cleanup
    free(lwe_buf);
    free(in_buf);
    free(out_buf);
    free(msg_buf);
    free(coeff_msg_buf);
    free(bit_buf);
    close(conn_fd);   // Close the active connection
    close(listen_fd); // Close the listening socket

    // printf("Controller finished\n");
    return 0;
}
