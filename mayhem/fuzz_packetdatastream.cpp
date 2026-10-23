// Fuzzes the PacketDataStream varint / blob / string reader and checks the varint round trip.
#include "PacketDataStream.h"

#include <QByteArray>
#include <QList>
#include <QString>

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	FuzzedDataProvider provider(data, size);

	if (size < 2) {
		return -1;
	}

	const unsigned opCount = provider.ConsumeIntegralInRange< unsigned >(1, 24);
	std::vector< uint8_t > ops;
	for (unsigned i = 0; i < opCount; ++i) {
		ops.push_back(provider.ConsumeIntegral< uint8_t >() % 9);
	}

	// Round trip: encode a value, decode it, require the same value (and no overrun).
	const quint64 value = provider.ConsumeIntegral< quint64 >();
	{
		unsigned char buf[16] = {};
		PacketDataStream out(buf, sizeof(buf));
		out << value;
		if (!out.isValid()) {
			abort();
		}
		PacketDataStream in(buf, sizeof(buf));
		quint64 decoded = 0;
		in >> decoded;
		if (!in.isValid() || decoded != value || in.size() != out.size()) {
			abort();
		}
	}

	std::vector< uint8_t > bytes = provider.ConsumeRemainingBytes< uint8_t >();
	if (bytes.empty()) {
		return 0;
	}
	PacketDataStream stream(bytes.data(), static_cast< unsigned int >(bytes.size()));

	for (uint8_t op : ops) {
		switch (op) {
			case 0: {
				quint64 v;
				stream >> v;
				break;
			}
			case 1: {
				quint32 v;
				stream >> v;
				break;
			}
			case 2: {
				int v;
				stream >> v;
				break;
			}
			case 3: {
				QByteArray v;
				stream >> v;
				break;
			}
			case 4: {
				QString v;
				stream >> v;
				break;
			}
			case 5: {
				float v;
				stream >> v;
				break;
			}
			case 6: {
				double v;
				stream >> v;
				break;
			}
			case 7: {
				bool v;
				stream >> v;
				break;
			}
			case 8: {
				QList< int > v;
				stream >> v;
				break;
			}
		}
		if (!stream.isValid()) {
			break;
		}
	}

	return 0;
}
