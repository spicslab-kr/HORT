#include "binfhe-base-scheme.h"


Ciphertext<DCRTPoly> cheetah_repack_for_conv (
    CryptoContext<DCRTPoly> cc,
    const ConvParam& cp,
    int CKKS_N,
    Ciphertext<DCRTPoly> ctIn
) {
    if (!ctIn) {
        OPENFHE_THROW("ctIn is null");
    }

    const uint32_t H = cp.H;
    const uint32_t W = cp.W;
    const uint32_t C = cp.inputChannel;

    const uint32_t total = C * H * W;

    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();

    // ciphertext 복사본 생성
    auto ctOut = ctIn->Clone();

    auto elems = ctOut->GetElements();  // vector<DCRTPoly>, 보통 [c0, c1]
    if (elems.empty()) {
        OPENFHE_THROW("Ciphertext has no elements");
    }

    // ring dimension 확인
    const uint32_t ringDim = elems[0].GetRingDimension();
 
    const uint32_t used = std::min(total, ringDim);

    // 각 component polynomial(c0, c1, ...)에 대해 동일한 계수 재배치 수행
    for (auto& poly : elems) {
        // COEFFICIENT 포맷으로 변환 (표현만 바뀜, 복호화 아님)
        poly.SetFormat(Format::COEFFICIENT);

        // DCRTPoly는 여러 tower(NativePoly)로 구성됨
        const uint32_t numTowers = poly.GetNumOfElements();
        NativePoly tower(towerParams[0], Format::EVALUATION, true);

        for (uint32_t t = 0; t < numTowers; ++t) {
            NativePoly tower = poly.GetElementAtIndex(t);

            const auto& vals = tower.GetValues();
            auto mod = tower.GetModulus();

            NativeVector newVals(vals.GetLength(), mod);
            newVals.SetModulus(mod);

            for (uint32_t c = 0; c < C; ++c) {
                for (uint32_t h = 0; h < H; ++h) {
                    for (uint32_t w = 0; w < W; ++w) {
                        uint32_t idx_flat = c * H * W + h * W + w;
                        uint32_t dst = idx_flat;
                        uint32_t src = idx_flat; 

                        if (dst < used && src < used) {
                            newVals[dst] = vals[src];
                        }
                    }
                }
            }

           
            tower.SetValues(newVals, Format::COEFFICIENT);
            poly.SetElementAtIndex(t, tower);     
        }


        // 다시 EVALUATION 포맷으로 돌려놓기 (이 상태가 대부분의 연산 포맷)
        poly.SetFormat(Format::EVALUATION);
    }

    ctOut->SetElements(elems);
    return ctOut;
}


Ciphertext<DCRTPoly> cheetah_extract_conv (
    CryptoContext<DCRTPoly> cc,
    const ConvParam& cp,
    int CKKS_N,
    Ciphertext<DCRTPoly> ctIn
) {
    if (!ctIn) {
        OPENFHE_THROW("ctIn is null");
    }

    const uint32_t H = cp.H;
    const uint32_t W = cp.W;
    const uint32_t C = cp.inputChannel;
    int H_out, W_out;
    calculate_output_dimensions(cp, H_out, W_out);

    const uint32_t total = C * H * W;

    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();

    // ciphertext 복사본 생성
    auto ctOut = ctIn->Clone();

    auto elems = ctOut->GetElements();  // vector<DCRTPoly>, 보통 [c0, c1]
    if (elems.empty()) {
        OPENFHE_THROW("Ciphertext has no elements");
    }

    // ring dimension 확인
    const uint32_t ringDim = elems[0].GetRingDimension();
 
    const uint32_t used = std::min(total, ringDim);

    // 각 component polynomial(c0, c1, ...)에 대해 동일한 계수 재배치 수행
    for (auto& poly : elems) {
        // COEFFICIENT 포맷으로 변환 (표현만 바뀜, 복호화 아님)
        poly.SetFormat(Format::COEFFICIENT);

        // DCRTPoly는 여러 tower(NativePoly)로 구성됨
        const uint32_t numTowers = poly.GetNumOfElements();
        NativePoly tower(towerParams[0], Format::EVALUATION, true);

        for (uint32_t t = 0; t < numTowers; ++t) {
            NativePoly tower = poly.GetElementAtIndex(t);

            const auto& vals = tower.GetValues();
            auto mod = tower.GetModulus();

            NativeVector newVals(vals.GetLength(), mod);
            newVals.SetModulus(mod);


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
                        newVals[m * H_out * W_out + out_h * W_out + out_w] = vals[poly_idx];
                    }
                }
            }

           
            tower.SetValues(newVals, Format::COEFFICIENT);
            poly.SetElementAtIndex(t, tower);     
        }


        // 다시 EVALUATION 포맷으로 돌려놓기 (이 상태가 대부분의 연산 포맷)
        poly.SetFormat(Format::EVALUATION);
    }

    ctOut->SetElements(elems);
    return ctOut;
}

Ciphertext<DCRTPoly> cheetah_extract_avgpool (
    CryptoContext<DCRTPoly> cc,
    const ConvParam& cp,
    int CKKS_N,
    Ciphertext<DCRTPoly> ctIn,
    int H, int W,
    int C,
    int k, int stride
) {
    if (!ctIn) {
        OPENFHE_THROW("ctIn is null");
    }

    const uint32_t total = H * C * W;

    int outH = (H - k) / stride + 1;
    int outW = (W - k) / stride + 1;

    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();

    // ciphertext 복사본 생성
    auto ctOut = ctIn->Clone();

    auto elems = ctOut->GetElements();  // vector<DCRTPoly>, 보통 [c0, c1]
    if (elems.empty()) {
        OPENFHE_THROW("Ciphertext has no elements");
    }

    // ring dimension 확인
    const uint32_t ringDim = elems[0].GetRingDimension();
 
    const uint32_t used = std::min(total, ringDim);

    // 각 component polynomial(c0, c1, ...)에 대해 동일한 계수 재배치 수행
    for (auto& poly : elems) {
        // COEFFICIENT 포맷으로 변환 (표현만 바뀜, 복호화 아님)
        poly.SetFormat(Format::COEFFICIENT);

        // DCRTPoly는 여러 tower(NativePoly)로 구성됨
        const uint32_t numTowers = poly.GetNumOfElements();
        NativePoly tower(towerParams[0], Format::EVALUATION, true);

        for (uint32_t t = 0; t < numTowers; ++t) {
            NativePoly tower = poly.GetElementAtIndex(t);

            const auto& vals = tower.GetValues();
            auto mod = tower.GetModulus();

            NativeVector newVals(vals.GetLength(), mod);
            newVals.SetModulus(mod);
            int nv_idx = 0;


            int channelStride = H * W; // 하나의 채널이 차지하는 슬롯 수

            for (int c = 0; c < C; ++c) {

                int channelOffset = c * channelStride;  // 해당 채널 시작점

                for (int oy = 0; oy < outH; oy++) {
                    for (int ox = 0; ox < outW; ox++) {

                        int idx = channelOffset + (oy * stride) * W + (ox * stride);

                        if (idx < (int)vals.GetLength())
                            newVals[nv_idx++]=vals[idx];
                        else
                            nv_idx++;
                    }
                }
            }

           
            tower.SetValues(newVals, Format::COEFFICIENT);
            poly.SetElementAtIndex(t, tower);     
        }


        // 다시 EVALUATION 포맷으로 돌려놓기 (이 상태가 대부분의 연산 포맷)
        poly.SetFormat(Format::EVALUATION);
    }

    ctOut->SetElements(elems);
    return ctOut;
}

uint32_t checkInputFunction(const std::vector<NativeInteger>& lut, NativeInteger mod) {
        size_t mid{lut.size() / 2};
        if (lut[0] == (mod - lut[mid])) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != (mod - lut[mid + i]))
                    return 2;
            return 0;
        }
        if (lut[0] == lut[mid]) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != lut[mid + i])
                    return 2;
            return 1;
        }
        return 2;
    }


