// Fuzzes parsing of every Mumble TCP control message (the server's and client's main network input).
#include "MumbleProtocol.h"
#include "Mumble.pb.h"
#include "ProtoUtils.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

template< typename Message > static bool roundTrip(const uint8_t *data, size_t size, Message &msg) {
	if (!msg.ParseFromArray(data, static_cast< int >(size))) {
		return false;
	}
	std::string wire;
	if (!msg.SerializeToString(&wire)) {
		abort();
	}
	Message again;
	if (!again.ParseFromString(wire)) {
		abort();
	}
	return true;
}

struct Extra {
	void operator()(const MumbleProto::Version &msg) const { (void) MumbleProto::getVersion(msg); }
	void operator()(const MumbleProto::SuggestConfig &msg) const { (void) MumbleProto::getSuggestedVersion(msg); }
	template< typename T > void operator()(const T &) const {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1 || size > 0x7FFFFF) {
		return -1;
	}

	const Extra extra;
	const uint8_t type = data[0];
	data++;
	size--;

#define PROCESS_MUMBLE_TCP_MESSAGE(name, value)                 \
	case value: {                                               \
		MumbleProto::name msg;                                  \
		if (!roundTrip(data, size, msg)) {                      \
			return -1;                                          \
		}                                                       \
		extra(msg);                                             \
		return 0;                                               \
	}

	switch (type) {
		MUMBLE_ALL_TCP_MESSAGES
		default:
			return -1;
	}
#undef PROCESS_MUMBLE_TCP_MESSAGE
}
