// Fuzzes Mumble's UDP packet decoder (legacy + protobuf formats, client and server role).
#include "MumbleProtocol.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace Mumble::Protocol;

template< Role role > static void run(Version::full_t version, bool pingOnly, const uint8_t *data, size_t size) {
	UDPDecoder< role > decoder(version);

	// Decode from the decoder's own receive buffer, exactly as the client and server do.
	std::span< byte > buffer = decoder.getBuffer();
	std::memcpy(buffer.data(), data, size);
	std::span< const byte > packet(buffer.data(), size);

	if (!decoder.decode(packet, pingOnly)) {
		return;
	}

	if (decoder.getMessageType() == UDPMessageType::Audio) {
		AudioData audio = decoder.getAudioData();
		volatile std::size_t sum = audio.payload.size();
		for (byte b : audio.payload) {
			sum = sum + b;
		}
		(void) sum;
	} else {
		PingData ping = decoder.getPingData();
		(void) ping;
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// byte 0 selects role / protocol version / ping-only; the rest is the packet
	if (size < 2 || size - 1 > MAX_UDP_PACKET_SIZE) {
		return -1;
	}

	const uint8_t selector = data[0];
	data++;
	size--;

	static const Version::full_t versions[] = { Version::UNKNOWN, Version::fromComponents(1, 4, 0),
												Version::fromComponents(1, 5, 0), Version::fromComponents(1, 6, 0) };
	const Version::full_t version = versions[(selector >> 2) & 0x3];
	const bool pingOnly           = (selector & 0x2) != 0;

	if (selector & 0x1) {
		run< Role::Client >(version, pingOnly, data, size);
	} else {
		run< Role::Server >(version, pingOnly, data, size);
	}

	return 0;
}
