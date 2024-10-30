#pragma once
#include <string>
#include <vector>

namespace cvt {

	class Converter {
	public:
		virtual ~Converter() = default;
		virtual std::string convert(std::string&, bool compressed = false) noexcept = 0;
		virtual std::string& data() noexcept = 0;

	protected:
		std::string sha256(const std::string& unhashed);
		std::string ripemd160(const std::string& unhashed);
		std::string base58encode(const std::vector<uint8_t>&);
		std::string to_public_key(const std::string& privateKeyHex, bool compressed = false);
		std::vector<uint8_t> unhexify_to_vec(std::string const& s);
		std::string unhexify_to_str(std::string const& s);

	protected:
		static constexpr const uint8_t base58chars[] = {
		'1', '2', '3', '4', '5', '6', '7', '8',
		'9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
		'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
		'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z' };
	};


	//*********	simple HEX	**********
	class Converter_HEX : public Converter {
	public:
		virtual ~Converter_HEX() = default;
		std::string convert(std::string&, bool = false) noexcept override;
		std::string& data() noexcept override;
	private:
		std::string m_str;
	};


	//*********	HEX to WIF	**********
	class Converter_WIF : public Converter {
	public:
		virtual ~Converter_WIF() = default;
		std::string convert(std::string&, bool = false) noexcept override;
		std::string& data() noexcept override;
	private:
		std::string m_str;
	};


	//*********  HEX to P2PKH	**********
	class Converter_P2PKH : public Converter {
	public:
		virtual ~Converter_P2PKH() = default;
		std::string convert(std::string&, bool = false) noexcept override;
		std::string& data() noexcept override;
	private:
		std::string m_str;
	};


	//*********	HEX to P2SH	**********
	class Converter_P2SH : public Converter {
	public:
		virtual ~Converter_P2SH() = default;
		std::string convert(std::string&, bool = true) noexcept override;
		std::string& data() noexcept override;
	private:
		std::string m_str;
	};


	//*********	HEX to BECH32	**********
	class Converter_BECH32 : public Converter {

	public:
		virtual ~Converter_BECH32() = default;
		std::string convert(std::string&, bool = true) noexcept override;
		std::string& data() noexcept override;

	private:
		std::vector<uint8_t> to_5_bit(const std::vector<uint8_t>& hash);
		uint32_t polymod(const std::vector<uint8_t>& values);
		std::vector<uint8_t> expand_hrp(const std::string& hrp);
		std::vector<uint8_t> create_checksum(const std::string& hrp, const std::vector<uint8_t>& values);

	private:
		std::string m_str;
		static constexpr char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

	};

	constexpr bool compressed = true;
	constexpr bool uncompressed = false;
}
