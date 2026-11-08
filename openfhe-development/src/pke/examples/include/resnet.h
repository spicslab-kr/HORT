struct ConvParam {
    int H, W;
    int inputChannel, outputChannel;
    int kernelSize;
    int stride;
    int padding;
};

inline void calculate_output_dimensions_pad(const ConvParam& cp, int& H_out, int& W_out) {
    const int H = cp.H, W = cp.W, K = cp.kernelSize, S = cp.stride, P = cp.padding;
    H_out = (H + 2*P - K) / S + 1;
    W_out = (W + 2*P - K) / S + 1;
}