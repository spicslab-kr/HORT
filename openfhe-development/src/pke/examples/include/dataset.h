#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

struct CIFARImage {
    uint8_t label; 
    std::vector<uint8_t> pixels;
    std::vector<std::vector<std::vector<uint8_t>>> img;

    CIFARImage() {
        img.resize(3, std::vector<std::vector<uint8_t>>(32, std::vector<uint8_t>(32, 0)));
    }
} ;

struct MNISTImage {
    uint8_t label;
    std::vector<uint8_t> pixels;
    std::vector<double> pixels_double;
    std::vector<std::vector<std::vector<uint8_t>>> img; 

    MNISTImage(int rows = 28, int cols = 28) {
        pixels.resize(rows * cols);
        img.resize(3, std::vector<std::vector<uint8_t>>(28, std::vector<uint8_t>(28, 0)));
    }
};