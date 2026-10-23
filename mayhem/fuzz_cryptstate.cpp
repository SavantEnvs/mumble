// Fuzzes the OCB2 CryptState: authenticated decrypt of arbitrary packets, and raw OCB decrypt / round trip.
#include "SSL.h"
#include "crypto/CryptStateOCB2.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>


extern "C" int LLVMFuzzerInitialize(int *, char ***) {
	MumbleSSL::initialize();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 3 * AES_BLOCK_SIZE + 1) {
		return -1;
	}

	FuzzedDataProvider provider(data, size);
	const std::string key = provider.ConsumeBytesAsString(AES_KEY_SIZE_BYTES);
	const std::string eiv = provider.ConsumeBytesAsString(AES_BLOCK_SIZE);
	const std::string div = provider.ConsumeBytesAsString(AES_BLOCK_SIZE);
	const bool rawMode    = provider.ConsumeBool();

	CryptStateOCB2 state;
	if (!state.setKey(key, eiv, div)) {
		return -1;
	}

	if (rawMode) {
		// OCB core with an arbitrary nonce and length
		std::vector< uint8_t > payload = provider.ConsumeRemainingBytes< uint8_t >();
		if (payload.size() > 4096) {
			payload.resize(4096);
		}
		payload.reserve(payload.size() + 1); // keep data() non-null for empty payloads
		unsigned char nonce[AES_BLOCK_SIZE];
		std::memcpy(nonce, eiv.data(), AES_BLOCK_SIZE);
		unsigned char tag[AES_BLOCK_SIZE];
		std::vector< uint8_t > plain(payload.size() + 1);
		state.ocb_decrypt(payload.data(), plain.data(), static_cast< unsigned int >(payload.size()), nonce, tag);

		std::vector< uint8_t > crypted(payload.size() + 1);
		std::vector< uint8_t > roundtrip(payload.size() + 1);
		unsigned char tag2[AES_BLOCK_SIZE];
		unsigned char tag3[AES_BLOCK_SIZE];
		std::vector< uint8_t > src = payload;
		src.reserve(src.size() + 1);
		if (state.ocb_encrypt(src.data(), crypted.data(), static_cast< unsigned int >(src.size()), nonce, tag2, false)) {
			state.ocb_decrypt(crypted.data(), roundtrip.data(), static_cast< unsigned int >(src.size()), nonce, tag3);
			if (std::memcmp(roundtrip.data(), payload.data(), payload.size()) != 0
				|| std::memcmp(tag2, tag3, AES_BLOCK_SIZE) != 0) {
				abort();
			}
		}
		return 0;
	}

	// Packet stream through the stateful decrypt (IV resync, replay history, tag check)
	for (int i = 0; i < 64 && provider.remaining_bytes() > 0; ++i) {
		const size_t len                   = provider.ConsumeIntegralInRange< size_t >(0, 255);
		std::vector< uint8_t > packet = provider.ConsumeBytes< uint8_t >(len);
		packet.reserve(packet.size() + 1);
		std::vector< uint8_t > out(packet.size() + 1);
		state.decrypt(packet.data(), out.data(), static_cast< unsigned int >(packet.size()));
	}

	return 0;
}
