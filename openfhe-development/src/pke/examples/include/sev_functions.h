#define LOG_STEP(msg) std::cout << "[LOG] " << msg << std::endl

// === SEV VM connection settings ===
//static const char* SEV_VM_IP   = "127.0.0.1"; // replace with the actual SEV VM IP
static const char* SEV_VM_IP   = "192.168.100.2"; // replace with the actual SEV VM IP
static const int   SEV_VM_PORT = 8080;        // port where reenc_e2e is listening
// Must match the N and LEVEL used to build reenc_e2e
static const size_t SEV_LEVEL  = 2;
static const size_t SEV_N      = 65536;       // example: if reenc_e2e was built with N=16384
static const size_t SEV_LWE_N  = 630; 
static const size_t SEV_LWE_CT = SEV_LWE_N + 1;
static constexpr double SEV_SCALE = static_cast<double>(uint64_t(1) << 40);

static const int   PER_SLOT_BIT= 15;

static const uint32_t SEV_REENC_MAGIC = 0x52454e43; // "RENC"
enum SevReencRequest : uint32_t {
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

const size_t coeffCount = 2 * SEV_LEVEL * SEV_N;
const size_t msgCount = SEV_N / 2;

// Write exactly "count" bytes, blocking until all data is sent or an error occurs
static ssize_t write_full(int fd, const void* buf, size_t count) {
    size_t left = count;
    const char* ptr = static_cast<const char*>(buf);

    while (left > 0) {
        ssize_t w = ::write(fd, ptr, left);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            break;
        left -= w;
        ptr  += w;
    }
    return static_cast<ssize_t>(count - left);
}

// Read exactly "count" bytes, blocking until all data is received or an error occurs
static ssize_t read_full(int fd, void* buf, size_t count) {
    size_t left = count;
    char* ptr = static_cast<char*>(buf);

    while (left > 0) {
        ssize_t r = ::read(fd, ptr, left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        left -= r;
        ptr  += r;
    }
    return static_cast<ssize_t>(count - left);
}


static int connect_to_sev(const char* ip, int port) {
    int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
    
    if (::inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        ::close(sockfd);
        return -1;
    }
    
    if (::connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        ::close(sockfd);
        return -1;
    }
    
    return sockfd;
}

static std::vector<uint64_t> recv_sev_secret_key(int sockfd) {
    uint64_t count = 0;
    if (read_full(sockfd, &count, sizeof(count)) != sizeof(count)) {
        throw std::runtime_error("Failed to read SEV secret key header");
    }
    size_t totalBytes = static_cast<size_t>(count) * sizeof(uint64_t);
    std::vector<uint64_t> coeffs(count);
    if (read_full(sockfd, coeffs.data(), totalBytes) != static_cast<ssize_t>(totalBytes)) {
        throw std::runtime_error("Failed to read SEV secret key payload");
    }
    return coeffs;
}



static bool sev_send_header(int sockfd, uint32_t req_type, uint64_t payload_bytes) {
    if (write_full(sockfd, &SEV_REENC_MAGIC, sizeof(SEV_REENC_MAGIC)) != sizeof(SEV_REENC_MAGIC)) {
        perror("write_full (magic)");
        return false;
    }
    if (write_full(sockfd, &req_type, sizeof(req_type)) != sizeof(req_type)) {
        perror("write_full (req_type)");
        return false;
    }
    if (write_full(sockfd, &payload_bytes, sizeof(payload_bytes)) != sizeof(payload_bytes)) {
        perror("write_full (payload_bytes)");
        return false;
    }
    return true;
}

static bool sev_remote_reenc_slot_enc(int sockfd,
                             const double* in_buf,
                             size_t coeff_count,
                             uint64_t* out_buf) {
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_ENC, msg_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, msg_count) != (ssize_t)msg_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_enc" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_enc" << std::endl;
    return true;
}

static bool sev_remote_reenc_slot_dec(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             double* out_buf) {
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
        if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_DEC, byte_count)) {
                return false;
            }
            if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
    return true;
}

static bool sev_remote_reenc_coeff_enc(int sockfd,
                             const double* in_buf,
                             size_t coeff_count,
                             uint64_t* out_buf) {
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_ENC, msg_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, msg_count) != (ssize_t)msg_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_enc" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_enc" << std::endl;
    return true;
}

static bool sev_remote_reenc_coeff_dec(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             double* out_buf) {
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
        if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_DEC, byte_count)) {
                return false;
            }
            if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
    return true;
}

static bool sev_remote_reenc_coeff_reenc(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             uint64_t* out_buf) {
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
        if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_REENC, byte_count)) {
                return false;
            }
            if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
    return true;
}


static bool sev_remote_reenc_slot_rescale(int sockfd,
                                     const uint64_t* in_buf,
                                     size_t coeff_count,
                                     long double input_scale,
                                     long double output_scale,
                                     uint64_t* out_buf) {
    const size_t byte_count = coeff_count * sizeof(uint64_t);
    long double scales[2]   = {input_scale, output_scale};
    const size_t payload_bytes = sizeof(scales) + byte_count;
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_REENC, payload_bytes)) {
        return false;
    }
    // send scales
    if (write_full(sockfd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
        perror("write_full (scales)");
        return false;
    }
    // send ciphertext coefficients
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full (ciphertext)");
        return false;
    }
    // receive re-encrypted coefficients
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    return true;
}


static bool sev_remote_reenc_coeff_rescale(int sockfd,
                                     const uint64_t* in_buf,
                                     size_t coeff_count,
                                     long double input_scale,
                                     long double output_scale,
                                     uint64_t* out_buf) {
    const size_t byte_count = coeff_count * sizeof(uint64_t);
    long double scales[2]   = {input_scale, output_scale};
    const size_t payload_bytes = sizeof(scales) + byte_count;
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_REENC, payload_bytes)) {
        return false;
    }
    // send scales
    if (write_full(sockfd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
        perror("write_full (scales)");
        return false;
    }
    // send ciphertext coefficients
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full (ciphertext)");
        return false;
    }
    // receive re-encrypted coefficients
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_reenc_lwe_enc(int sockfd,
                                      const uint64_t* in_buf,
                                      size_t msg_count,
                                      uint64_t* out_buf) {
    const size_t in_byte_count = msg_count * sizeof(uint64_t);
    const size_t out_byte_count = msg_count * SEV_LWE_CT * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_ENC, in_byte_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, in_byte_count) != (ssize_t)in_byte_count) {
        perror("write_full (lwe enc)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, out_byte_count);
    if (r != (ssize_t)out_byte_count) {
        if (r < 0)
            perror("read_full (lwe enc)");
        else
            fprintf(stderr, "short read (lwe enc): %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_reenc_lwe_dec(int sockfd,
                                      const uint64_t* in_buf,
                                      size_t ckks_n,
                                      uint64_t* out_buf) {
    const size_t in_byte_count = ckks_n * SEV_LWE_CT * sizeof(uint64_t);
    const size_t out_byte_count = ckks_n * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_DEC, in_byte_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, in_byte_count) != (ssize_t)in_byte_count) {
        perror("write_full (lwe dec)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, out_byte_count);
    if (r != (ssize_t)out_byte_count) {
        if (r < 0)
            perror("read_full (lwe dec)");
        else
            fprintf(stderr, "short read (lwe dec): %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_reenc_coeff_dec_lwe_ct(int sockfd,
                                              const uint64_t* in_buf,
                                              size_t coeff_count,
                                              double* out_slots,
                                              size_t slot_count,
                                              uint64_t* out_lwe_buf,
                                              size_t out_lwe_u64_count) {
    const size_t in_bytes = coeff_count * sizeof(uint64_t);
    const size_t slot_bytes = slot_count * sizeof(double);
    const size_t lwe_bytes = out_lwe_u64_count * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_DEC_LWE_CT, in_bytes)) {
        return false;
    }
    if (write_full(sockfd, in_buf, in_bytes) != (ssize_t)in_bytes) {
        perror("write_full (coeff dec + lwe ct)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_slots, slot_bytes);
    if (r != (ssize_t)slot_bytes) {
        if (r < 0)
            perror("read_full (coeff dec + lwe ct slots)");
        else
            fprintf(stderr, "short read (coeff dec + lwe ct slots): %zd bytes\n", r);
        return false;
    }
    r = read_full(sockfd, out_lwe_buf, lwe_bytes);
    if (r != (ssize_t)lwe_bytes) {
        if (r < 0)
            perror("read_full (coeff dec + lwe ct lwe)");
        else
            fprintf(stderr, "short read (coeff dec + lwe ct lwe): %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_lwe_dec_coeff_enc(int sockfd,
                                         const double* base_slots,
                                         size_t slot_count,
                                         const uint64_t* lwe_buf,
                                         size_t lwe_u64_count,
                                         uint64_t* out_buf) {
    const size_t base_bytes = slot_count * sizeof(double);
    const size_t lwe_bytes  = lwe_u64_count * sizeof(uint64_t);
    const size_t payload_bytes = base_bytes + lwe_bytes;
    const size_t out_bytes = coeffCount * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_DEC_COEFF_ENC, payload_bytes)) {
        return false;
    }
    if (write_full(sockfd, base_slots, base_bytes) != (ssize_t)base_bytes) {
        perror("write_full (base_slots)");
        return false;
    }
    if (write_full(sockfd, lwe_buf, lwe_bytes) != (ssize_t)lwe_bytes) {
        perror("write_full (lwe_buf)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, out_bytes);
    if (r != (ssize_t)out_bytes) {
        if (r < 0)
            perror("read_full (lwe dec coeff enc)");
        else
            fprintf(stderr, "short read (lwe dec coeff enc): %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_reenc_lwe(int sockfd,
                                 const uint64_t* in_buf,
                                 size_t ckks_n,
                                 uint64_t* out_buf) {
    const size_t byte_count = ckks_n * SEV_LWE_CT * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_REENC, byte_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full (lwe)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full (lwe)");
        else
            fprintf(stderr, "short read (lwe): %zd bytes\n", r);
        return false;
    }
    return true;
}

std::vector<uint64_t> doubleVecToBitVector(const std::vector<double>& input) {
    std::vector<uint64_t> bits;
    bits.reserve(input.size() * 64);

    for (double d : input) {
        uint64_t raw;
        static_assert(sizeof(double) == sizeof(uint64_t),
                      "double must be 64-bit");
        std::memcpy(&raw, &d, sizeof(double));

        // bit 0 (LSB) -> bit 63 (MSB)
        for (int i = 0; i < 64; ++i) {
            bits.push_back((raw >> i) & 0x1);
        }
    }
    return bits;
}


double bitsToDouble(const std::vector<uint64_t>& bits, size_t offset) {
    // bits[offset + 0]  = LSB
    // bits[offset + 63] = MSB
    uint64_t raw = 0;

    for (int i = 0; i < 64; i++) {
        raw |= (bits[offset + i] & 0x1ULL) << i;
    }

    double value;
    std::memcpy(&value, &raw, sizeof(double));
    return value;
}

std::vector<double> bitVectorToDoubleVec(const std::vector<uint64_t>& bits, size_t CKKS_N) {
    std::vector<double> output;
    output.reserve(CKKS_N);

    for (size_t k = 0; k < CKKS_N; k++) {
        size_t base = k * 64;
        output.push_back(bitsToDouble(bits, base));
    }
    return output;
}
