#include <iostream>
#include <iomanip>
#include "converters.hpp"

void print(const std::string& str, const std::string& val) {
    std::cout << std::setw(12) << std::left << str << val << std::endl;
}

int main(int, char**)
{
    std::string s;
    cvt::Converter_HEX hex;
    cvt::Converter_WIF wif;
    cvt::Converter_WIF wifc;
    cvt::Converter_P2PKH p2p;
    cvt::Converter_P2PKH p2pc;
    cvt::Converter_P2SH p2s;
    cvt::Converter_BECH32 bech;

    for (;;) {
        std::cout << "Enter the string: ";
        std::getline(std::cin, s);
        std::cout << std::endl;

        print("INPUT: ", s);
        print("HEX: ", hex.convert(s));
        print("WIF(c): ", wif.convert(hex.data(), cvt::compressed));
        print("WIF(u): ", wif.convert(hex.data()));
        print("P2PKH(c): ", p2p.convert(hex.data(), cvt::compressed));
        print("P2PKH(u): ", p2p.convert(hex.data()));
        print("P2SH(u): ", p2s.convert(hex.data()));
        print("BECH32(u): ", bech.convert(hex.data()));
        std::cout << std::endl;
        std::cout << std::endl;
    }
    
}