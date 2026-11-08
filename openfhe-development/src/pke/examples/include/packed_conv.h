void calculate_output_dimensions(const ConvParam& cp, int& H_out, int& W_out);
void cheetah_encode_image(const ConvParam& cp, int CKKS_N,
                          const std::vector<std::vector<std::vector<int>>>& image,
                          std::vector<double>& encoded);
void cheetah_encode_image_flat(const ConvParam& cp, int CKKS_N, const std::vector<double>& image_flat, std::vector<double>& encoded);

void cheetah_encode_kernel(const ConvParam& cp, int CKKS_N,
                           const std::vector<std::vector<std::vector<std::vector<int>>>>& kernel,
                           std::vector<double>& encoded);
void cheetah_convolution(const std::vector<double>& encoded_image,
                         const std::vector<double>& encoded_kernel,
                         std::vector<double>& output,
                         const ConvParam& cp, int CKKS_N);
void reference_convolution(const std::vector<std::vector<std::vector<int>>>& image,
                           const std::vector<std::vector<std::vector<std::vector<int>>>>& kernel,
                           std::vector<std::vector<std::vector<int>>>& output,
                           const ConvParam& cp);
void extractConvResults(const std::vector<double>& product,
                        std::vector<double>& output,
                        const ConvParam& cp, int CKKS_N);
void polynomialMultiply(const std::vector<double>& a, const std::vector<double>& b,
                        std::vector<double>& result, int N);


void extract_avgpool_intermediate(
    const std::vector<double>& product,
    std::vector<double>& output,
    int H, int W,
    int C,
    int k, int stride
);


void calculate_output_dimensions(const ConvParam& cp, int& H_out, int& W_out) {
    H_out = (cp.H - cp.kernelSize) / cp.stride + 1;
    W_out = (cp.W - cp.kernelSize) / cp.stride + 1;
}

// CHEETAH image encoding - eq. 5
void cheetah_encode_image(const ConvParam& cp, int CKKS_N,
                          const std::vector<std::vector<std::vector<int>>>& image,
                          std::vector<double>& encoded) {
    encoded.assign(CKKS_N, 0.0);

    int H = cp.H;
    int W = cp.W;
    int C = cp.inputChannel;

    for (int c = 0; c < C; ++c) {
        for (int h = 0; h < H; ++h) {
            for (int w = 0; w < W; ++w) {
                int poly_idx = c * H * W + h * W + w;
                if (poly_idx < CKKS_N) {
                    encoded[poly_idx] = static_cast<double>(image[c][h][w]);
                }
            }
        }
    }
}

void cheetah_encode_image_flat(
    const ConvParam& cp, int CKKS_N,
    const std::vector<double>& image_flat, 
    std::vector<double>& encoded
) {
    int H = cp.H;
    int W = cp.W;
    int C = cp.inputChannel;

    encoded.assign(CKKS_N, 0.0);

    for (int c = 0; c < C; ++c) {
        for (int h = 0; h < H; ++h) {
            for (int w = 0; w < W; ++w) {

                int idx_flat = c * H * W + h * W + w;
                int poly_idx = idx_flat;

                if (poly_idx < CKKS_N)
                    encoded[poly_idx] = image_flat[idx_flat];
            }
        }
    }
}

// CHEETAH kernel encoding - eq. 5
void cheetah_encode_kernel(const ConvParam& cp, int CKKS_N,
                           const std::vector<std::vector<std::vector<std::vector<int>>>>& kernel,
                           std::vector<double>& encoded) {
    encoded.assign(CKKS_N, 0.0);

    int H = cp.H;
    int W = cp.W;
    int C = cp.inputChannel;
    int M = cp.outputChannel;
    int K = cp.kernelSize;

    int O = H * W * (M * C - 1) + W * (K - 1) + (K - 1);

    for (int m = 0; m < M; ++m) {
        for (int c = 0; c < C; ++c) {
            for (int kh = 0; kh < K; ++kh) {
                for (int kw = 0; kw < K; ++kw) {
                    int poly_idx = O - m * C * H * W - c * H * W - kh * W - kw;
                    poly_idx = poly_idx % CKKS_N;
                    if (poly_idx < 0) poly_idx += CKKS_N;
                    encoded[poly_idx] = static_cast<double>(kernel[m][c][kh][kw]);
                }
            }
        }
    }
}

// Polynomial multiplication 
void polynomialMultiply(const std::vector<double>& a, const std::vector<double>& b,
                        std::vector<double>& result, int N) {
    result.assign(N, 0.0);
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            int k = (i + j) % N;
            double term = a[i] * b[j];
            if (i + j >= N) term = -term;  
            result[k] += term;
        }
    }
}

// Extract convolution results
void extractConvResults(const std::vector<double>& product,
                        std::vector<double>& output,
                        const ConvParam& cp, int CKKS_N) {
    int H_out, W_out;
    calculate_output_dimensions(cp, H_out, W_out);
    output.assign(cp.outputChannel * H_out * W_out, 0.0);

    int H = cp.H;
    int W = cp.W;
    int C = cp.inputChannel;
    int M = cp.outputChannel;
    int K = cp.kernelSize;
    int stride = cp.stride;

    int O = H * W * (M * C - 1) + W * (K - 1) + (K - 1);

    for (int m = 0; m < M; ++m) {
        for (int out_h = 0; out_h < H_out; ++out_h) {
            for (int out_w = 0; out_w < W_out; ++out_w) {
                int poly_idx = O - m * C * H * W + out_h * stride * W + out_w * stride;
                poly_idx = poly_idx % CKKS_N;
                if (poly_idx < 0) poly_idx += CKKS_N;
                output[m * H_out * W_out + out_h * W_out + out_w] = product[poly_idx];
            }
        }
    }
}

// CHEETAH convolution
// TODO : Add zero padding layout
void cheetah_convolution(const std::vector<double>& encoded_image,
                         const std::vector<double>& encoded_kernel,
                         std::vector<double>& output,
                         const ConvParam& cp, int CKKS_N) {
    std::vector<double> product;
    polynomialMultiply(encoded_image, encoded_kernel, product, CKKS_N);
    extractConvResults(product, output, cp, CKKS_N);
}

// Reference convolution for verification 
void reference_convolution(const std::vector<std::vector<std::vector<int>>>& image,
                           const std::vector<std::vector<std::vector<std::vector<int>>>>& kernel,
                           std::vector<std::vector<std::vector<int>>>& output,
                           const ConvParam& cp) {
    int H_out, W_out;
    calculate_output_dimensions(cp, H_out, W_out);

    output.assign(cp.outputChannel,
                  std::vector<std::vector<int>>(H_out, std::vector<int>(W_out, 0)));

    for (int m = 0; m < cp.outputChannel; ++m) {
        for (int out_h = 0; out_h < H_out; ++out_h) {
            for (int out_w = 0; out_w < W_out; ++out_w) {
                int val = 0;
                for (int c = 0; c < cp.inputChannel; ++c) {
                    for (int kh = 0; kh < cp.kernelSize; ++kh) {
                        for (int kw = 0; kw < cp.kernelSize; ++kw) {
                            int in_h = out_h * cp.stride + kh;
                            int in_w = out_w * cp.stride + kw;
                            if (in_h >= 0 && in_h < cp.H && in_w >= 0 && in_w < cp.W) {
                                val += image[c][in_h][in_w] * kernel[m][c][kh][kw];
                            }
                        }
                    }
                }
                output[m][out_h][out_w] = val;
            }
        }
    }
}


void extract_avgpool_intermediate(
    const std::vector<double>& product,
    std::vector<double>& output,
    int H, int W,
    int C,
    int k, int stride
) {
    output.clear();
    output.reserve(C * ((H - k) / stride + 1) * ((W - k) / stride + 1));

    int outH = (H - k) / stride + 1;
    int outW = (W - k) / stride + 1;

    int channelStride = H * W; // 하나의 채널이 차지하는 슬롯 수

    for (int c = 0; c < C; ++c) {

        int channelOffset = c * channelStride;  // 해당 채널 시작점

        for (int oy = 0; oy < outH; oy++) {
            for (int ox = 0; ox < outW; ox++) {

                int idx = channelOffset + (oy * stride) * W + (ox * stride);

                if (idx < (int)product.size())
                    output.push_back(product[idx]);
                else
                    output.push_back(0.0);
            }
        }
    }
}


void cheetah_encode_fc_weight(
    int inDim,               // 입력 차원 (D)
    int outDim,              // 출력 뉴런 수 (M)
    int CKKS_N,
    const std::vector<std::vector<int>>& weight, // [outDim][inDim] = W[m][j]
    std::vector<double>& encoded                    // 한 poly에 모든 weight encode
) {
    encoded.assign(CKKS_N, 0.0);

    // O = D*M - 1  (CHEETAH conv의 O와 동일한 역할)
    int O = inDim * outDim - 1;

    for (int m = 0; m < outDim; ++m) {
        for (int j = 0; j < inDim; ++j) {

            int poly_idx = O - m * inDim - j;

            // cyclic conv로 돌리려면 N으로 modulo
            poly_idx %= CKKS_N;
            if (poly_idx < 0)
                poly_idx += CKKS_N;

            encoded[poly_idx] = weight[m][j];
        }
    }
}

void cheetah_encode_fc_input(
    int inDim, int CKKS_N,
    const std::vector<double>& x,   // 길이 inDim
    std::vector<double>& encoded
) {
    encoded.assign(CKKS_N, 0.0);

    for (int j = 0; j < inDim && j < CKKS_N; ++j) {
        encoded[j] = x[j];
    }
}


void cheetah_decode_fc_output(
    const std::vector<double>& product,
    int inDim, int outDim, int CKKS_N,
    std::vector<double>& output
) {
    output.assign(outDim, 0.0);

    // O = D*M - 1  (same as encoder)
    int O = inDim * outDim - 1;

    for (int m = 0; m < outDim; ++m) {

        int idx = O - m * inDim;

        // modulo CKKS ring size
        idx %= CKKS_N;
        if (idx < 0) idx += CKKS_N;

        if (idx < (int)product.size())
            output[m] = product[idx];
        else
            output[m] = 0.0; // fail-safe
    }
}


bool file_exists(const std::string &filename) {
    std::ifstream file(filename);
    return file.good();
}

