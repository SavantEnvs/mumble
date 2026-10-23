// Fuzzes HostAddress construction/formatting/matching and the Ban/ServerAddress helpers built on it.
#include "Ban.h"
#include "HostAddress.h"
#include "ServerAddress.h"

#include <QHostAddress>
#include <QString>

#include <fuzzer/FuzzedDataProvider.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 2) {
		return -1;
	}

	FuzzedDataProvider provider(data, size);
	const uint8_t mode = provider.ConsumeIntegral< uint8_t >() % 4;

	HostAddress host;
	switch (mode) {
		case 0: {
			// textual IPv4/IPv6 address
			const std::string text = provider.ConsumeRemainingBytesAsString();
			host                   = HostAddress(QHostAddress(QString::fromUtf8(text.data(), static_cast< qsizetype >(text.size()))));
			break;
		}
		case 1: {
			host = HostAddress(provider.ConsumeBytesAsString(16));
			break;
		}
		case 2: {
			const std::string raw = provider.ConsumeBytesAsString(16);
			host                  = HostAddress(QByteArray(raw.data(), static_cast< qsizetype >(raw.size())));
			break;
		}
		case 3: {
			struct sockaddr_storage storage;
			std::memset(&storage, 0, sizeof(storage));
			if (provider.ConsumeBool()) {
				struct sockaddr_in *in = reinterpret_cast< struct sockaddr_in * >(&storage);
				in->sin_family         = AF_INET;
				in->sin_addr.s_addr    = provider.ConsumeIntegral< uint32_t >();
				in->sin_port           = provider.ConsumeIntegral< uint16_t >();
			} else {
				struct sockaddr_in6 *in6 = reinterpret_cast< struct sockaddr_in6 * >(&storage);
				in6->sin6_family         = AF_INET6;
				const std::string raw    = provider.ConsumeBytesAsString(16);
				std::memcpy(&in6->sin6_addr, raw.data(), raw.size());
				in6->sin6_port = provider.ConsumeIntegral< uint16_t >();
			}
			host = HostAddress(storage);
			break;
		}
	}

	const unsigned int bits = provider.ConsumeIntegralInRange< unsigned int >(0, 128);
	HostAddress other;
	other.fromIPv4(provider.ConsumeIntegral< uint32_t >());

	(void) host.isValid();
	(void) host.isV6();
	(void) host.toString();
	(void) host.toString(false);
	(void) host.toStdString();
	(void) host.toByteArray();
	(void) host.toAddress();
	(void) host.match(other, bits);
	(void) (host < other);
	(void) (host == other);
	if (!host.isV6()) {
		(void) host.toIPv4();
	}
	struct sockaddr_storage out;
	host.toSockaddr(&out);

	Ban ban;
	ban.haAddress = host;
	ban.iMask     = static_cast< int >(bits);
	ban.iDuration = provider.ConsumeIntegral< unsigned int >();
	ban.qsHash    = QString::fromLatin1(provider.ConsumeRandomLengthString(8).c_str());
	(void) ban.isValid();
	(void) ban.toString();
	(void) ban.toKey();
	(void) qHash(ban);

	ServerAddress server(host, provider.ConsumeIntegral< unsigned short >());
	(void) server.isValid();
	(void) qHash(server);

	return 0;
}
