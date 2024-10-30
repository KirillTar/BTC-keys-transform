#include <iomanip>
#include <algorithm>
#include <sstream>
#include "SSLmem.hpp"
#include "converters.hpp"

namespace cvt {

    // *****************   base functional    ****************** 

    std::string Converter::sha256(const std::string& unhashed) {

        EVP_MD_CTX_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new());

        std::string hashed;

        if (context.get() == NULL) {
            return "";
        }

        if (!EVP_DigestInit_ex(context.get(), EVP_sha256(), NULL)) {
            return "";
        }

        if (!EVP_DigestUpdate(context.get(), unhashed.c_str(), unhashed.length())) {
            return "";
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int lengthOfHash = 0;

        if (!EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash)) {
            return "";
        }

        std::stringstream ss;

        for (unsigned int i = 0; i < lengthOfHash; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        return hashed = ss.str();
    }

    std::string Converter::ripemd160(const std::string& unhashed) {

        EVP_MD_CTX_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new());

        std::string hashed;

        if (!context.get()) {
            return "";
        }

        if (!EVP_DigestInit_ex(context.get(), EVP_ripemd160(), NULL)) {
            return "";
        }

        if (!EVP_DigestUpdate(context.get(), unhashed.c_str(), unhashed.length())) {
            return "";
        }

        unsigned char hash[32];
        unsigned int lengthOfHash = 0;

        if (!EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash)) {
            return "";
        }

        std::stringstream ss;
        for (unsigned int i = 0; i < lengthOfHash; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        return hashed = ss.str();
    }


    std::string Converter::base58encode(const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> digits((data.size() * 138 / 100) + 1);
        size_t digitslen = 1;

        for (size_t i = 0; i < data.size(); i++)
        {
            uint32_t carry = static_cast<uint32_t>(data[i]);
            for (size_t j = 0; j < digitslen; j++)
            {
                carry = carry + static_cast<uint32_t>(digits[j] << 8);
                digits[j] = static_cast<uint8_t>(carry % 58);
                carry /= 58;
            }
            for (; carry; carry /= 58)
                digits[digitslen++] = static_cast<uint8_t>(carry % 58);
        }

        std::string result;

        for (size_t i = 0; i < (data.size() - 1) && !data[i]; i++)
            result.push_back(base58chars[0]);
        for (size_t i = 0; i < digitslen; i++)
            result.push_back(base58chars[digits[digitslen - 1 - i]]);
        return result;
    }

#pragma warning(disable : 4996)

    std::string Converter::to_public_key(const std::string& hexPrivateKey, bool compressed) {

        EC_KEY_ptr<EC_KEY> eckey(EC_KEY_new_by_curve_name(NID_secp256k1));

        if (!eckey) {
            return "";
        }

        BN_ptr<BIGNUM> privKeyBN(BN_new());

        if (!privKeyBN.get()) {
            return "";
        }

        auto tmp = privKeyBN.release();
        if (BN_hex2bn(&tmp, hexPrivateKey.c_str()) == 0) {
            return "";
        }

        privKeyBN.reset(tmp);

        if (EC_KEY_set_private_key(eckey.get(), privKeyBN.get()) != 1) {
            return "";
        }

        EC_POINT_ptr<EC_POINT> pubKeyPoint(EC_POINT_new(EC_KEY_get0_group(eckey.get())));
        if (EC_POINT_mul(EC_KEY_get0_group(eckey.get()), pubKeyPoint.get(), privKeyBN.get(), nullptr, nullptr, nullptr) != 1) {
            return "";
        }

        char* pubKeyHexUncompressed = EC_POINT_point2hex(EC_KEY_get0_group(eckey.get()), pubKeyPoint.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr);
        std::string publicKeyHexUncompressed(pubKeyHexUncompressed);

        char* pubKeyHexCompressed = EC_POINT_point2hex(EC_KEY_get0_group(eckey.get()), pubKeyPoint.get(), POINT_CONVERSION_COMPRESSED, nullptr);
        std::string publicKeyHexCompressed(pubKeyHexCompressed);

        OPENSSL_free(pubKeyHexUncompressed);
        OPENSSL_free(pubKeyHexCompressed);

        if (compressed)
        {
            return publicKeyHexCompressed;
        }
        else {
            return publicKeyHexUncompressed;
        }

    }

    std::vector<uint8_t> Converter::unhexify_to_vec(std::string const& s) {
        std::vector<uint8_t> v;
        for (size_t i = 0; i < s.size(); i += 2) {
            auto substr = s.substr(i, 2);
            auto chr_int = std::stoi(substr, nullptr, 16);
            v.push_back(static_cast<uint8_t>(chr_int));
        }
        return v;
    }

    std::string Converter::unhexify_to_str(std::string const& s) {
        std::string str = "";
        for (size_t i = 0; i < s.size(); i += 2) {
            auto substr = s.substr(i, 2);
            auto chr_int = std::stoi(substr, nullptr, 16);
            str.push_back(chr_int);
        }
        return str;
    }

    //***************   base functional end ***************

    
    //*********	simple HEX	**********
    std::string Converter_HEX::convert(std::string& unhashed, bool compressed) noexcept {
        m_str = sha256(unhashed);
        return m_str;
    }

    std::string& Converter_HEX::data() noexcept {
        return m_str;
    }


    //*********	HEX to WIF	**********
    std::string Converter_WIF::convert(std::string& hex, bool compressed) noexcept {

        m_str = "80" + hex;

        if (compressed) {
            m_str += "01";
        }

        std::string checksum = sha256(unhexify_to_str(m_str));
        checksum = sha256(unhexify_to_str(checksum));
        m_str += checksum.substr(0, 8);

        m_str = base58encode(unhexify_to_vec(m_str));
        return m_str;
    }

    std::string& Converter_WIF::data() noexcept {
        return m_str;
    }


    //*********  HEX to P2PKH	**********
    std::string Converter_P2PKH::convert(std::string& hex, bool compressed) noexcept {

        m_str = to_public_key(hex, compressed);

        m_str = sha256(unhexify_to_str(m_str));
        m_str = ripemd160(unhexify_to_str(m_str));
        m_str = "00" + m_str;

        std::string checksum = sha256(unhexify_to_str(m_str));
        checksum = sha256(unhexify_to_str(checksum));
        m_str += checksum.substr(0, 8);

        m_str = base58encode(unhexify_to_vec(m_str));

        return m_str;
    }

    std::string& Converter_P2PKH::data() noexcept {
        return m_str;
    }


    //*********	HEX to P2SH	**********
    std::string Converter_P2SH::convert(std::string& hex, bool compressed) noexcept {

        m_str = to_public_key(hex, cvt::compressed);
        m_str = sha256(unhexify_to_str(m_str));
        m_str = ripemd160(unhexify_to_str(m_str));
        m_str = "0014" + m_str;
        m_str = sha256(unhexify_to_str(m_str));
        m_str = ripemd160(unhexify_to_str(m_str));
        m_str = "05" + m_str;

        std::string checksum = sha256(unhexify_to_str(m_str));
        checksum = sha256(unhexify_to_str(checksum));
        checksum = checksum.substr(0, 8);
        m_str += checksum;

        m_str = base58encode(unhexify_to_vec(m_str));
        return m_str;
    }

    std::string& Converter_P2SH::data() noexcept {
        return m_str;
    }


    //*********	HEX to BECH32 implementation	**********
    uint32_t Converter_BECH32::polymod(const std::vector<uint8_t>& values)
    {
        uint32_t c = 1;
        for (const auto v_i : values) {
            uint8_t c0 = c >> 25;

            c = ((c & 0x1ffffff) << 5) ^ v_i;

            if (c0 & 1)  c ^= 0x3b6a57b2; //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
            if (c0 & 2)  c ^= 0x26508e6d; //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 +  {3}x^2 + {19}x + {13}
            if (c0 & 4)  c ^= 0x1ea119fa; //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 +  {6}x^2 + {15}x + {26}
            if (c0 & 8)  c ^= 0x3d4233dd; //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 + {12}x^2 + {30}x + {29}
            if (c0 & 16) c ^= 0x2a1462b3; // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 + {24}x^2 + {21}x + {19}
        }
        return c;
    }

    std::vector<uint8_t> Converter_BECH32::expand_hrp(const std::string& hrp) {
        std::vector<uint8_t> ret;
        ret.reserve(hrp.size() + 90);
        ret.resize(hrp.size() * 2 + 1);
        for (size_t i = 0; i < hrp.size(); ++i) {
            unsigned char c = hrp[i];
            ret[i] = c >> 5;
            ret[i + hrp.size() + 1] = c & 0x1f;
        }
        ret[hrp.size()] = 0;
        return ret;
    }

    std::vector<uint8_t> Converter_BECH32::create_checksum(const std::string& hrp, const std::vector<uint8_t>& values) {
        std::vector<uint8_t> enc = expand_hrp(hrp);
        enc.insert(enc.end(), values.begin(), values.end());
        enc.resize(enc.size() + 6);
        uint32_t mod = polymod(enc) ^ 1;
        std::vector<uint8_t> ret;
        ret.resize(6);
        for (size_t i = 0; i < 6; ++i) {
            // Convert the 5-bit groups in mod to checksum values.
            ret[i] = (mod >> (5 * (5 - i))) & 31;
        }
        return ret;
    }

    // not the most effective way, can be replaced with original implementation in btc
    std::vector<uint8_t> Converter_BECH32::to_5_bit(const std::vector<uint8_t>& hash) {

        std::vector<uint8_t> five_bit_view;
        std::vector<std::string> nums;
        std::string res = "", tmp = "";

        for (int i = 0; i < hash.size(); ++i) {
            uint8_t byte = hash[i];
            for (int j = 0; j < 8; j++) {

                if (byte & 1)
                    tmp.push_back('1');

                if (!(byte & 1))
                    tmp.push_back('0');
                byte >>= 1;
            }

            std::reverse(tmp.begin(), tmp.end());
            res += tmp;
            tmp.clear();
        }

        std::stringstream ss;

        for (int i = 0; i < res.size(); i++) {

            if (i == res.size() - 1) {
                ss << res[i];
                nums.push_back(ss.str());
            }

            if (i > 0 && i % 5 == 0)
            {
                nums.push_back(ss.str());
                ss.str("");
            }

            ss << res[i];
        }

        int num = 0;
        for (int i = 0; i < nums.size(); i++) {

            for (int j = 0; j < 5; j++) {

                if (nums[i][j] == '1') {
                    num += 1;
                }

                num <<= 1;
            }

            five_bit_view.push_back(num >>= 1);
            num = 0;
        }

        return five_bit_view;
    }


    //*********	HEX to BECH32 main convert	**********
    std::string Converter_BECH32::convert(std::string& hex, bool compressed) noexcept {

        m_str = to_public_key(hex, cvt::compressed);
        m_str = sha256(unhexify_to_str(m_str));
        m_str = ripemd160(unhexify_to_str(m_str));

        std::vector<uint8_t> data = to_5_bit(unhexify_to_vec(m_str));
       
        data.insert(data.begin(), 0x00);
        std::vector<uint8_t> checksum = create_checksum("bc", data);

        data.insert(data.end(), checksum.begin(), checksum.end());

        m_str.clear();
        m_str = "bc1";
        m_str.reserve(m_str.size() + data.size());

        for (const auto c : data) {
            m_str += CHARSET[c];
        }

        return m_str;
    }

    std::string& Converter_BECH32::data() noexcept {
        return m_str;
    }

}   //namespace cvt