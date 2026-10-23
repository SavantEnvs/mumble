// Known-answer probe built with the project's normal flags; test.sh compares its stdout to golden values.
#include "HostAddress.h"
#include "MumbleProtocol.h"
#include "PacketDataStream.h"
#include "SSL.h"
#include "Version.h"
#include "crypto/CryptStateOCB2.h"

#include <QByteArray>
#include <QString>

#include <cstdio>
#include <cstring>
#include <string>

using namespace Mumble::Protocol;

static void hex(const char *label, const unsigned char *p, size_t n) {
	std::printf("%s=", label);
	for (size_t i = 0; i < n; ++i) {
		std::printf("%02x", p[i]);
	}
	std::printf("\n");
}

int main() {
	MumbleSSL::initialize();

	// PacketDataStream varint encoding: 0x1234 -> 2 bytes (14 bit form), -2 -> single byte, 2^40 -> 64 bit form
	{
		unsigned char buf[32] = {};
		PacketDataStream s(buf, sizeof(buf));
		s << static_cast< quint64 >(0x1234) << static_cast< qint64 >(-2) << static_cast< quint64 >(1ULL << 40);
		hex("varint", buf, s.size());
		PacketDataStream r(buf, s.size());
		quint64 a, c;
		qint64 b;
		r >> a >> b >> c;
		std::printf("varint_decoded=%llu,%lld,%llu\n", static_cast< unsigned long long >(a),
					static_cast< long long >(b), static_cast< unsigned long long >(c));
	}

	// Version parsing and packing
	{
		const Version::full_t v = Version::fromString(QString::fromLatin1("1.5.634"));
		std::printf("version=%llu legacy=%u str=%s\n", static_cast< unsigned long long >(v),
					static_cast< unsigned >(Version::toLegacyVersion(v)),
					Version::toString(v).toStdString().c_str());
	}

	// Protobuf UDP ping round trip
	{
		UDPPingEncoder< Role::Client > enc(Version::fromComponents(1, 5, 0));
		PingData ping;
		ping.timestamp = 0x0102030405ULL;
		std::span< const byte > encoded = enc.encodePingPacket(ping);
		hex("ping", encoded.data(), encoded.size());

		UDPDecoder< Role::Server > dec(Version::fromComponents(1, 5, 0));
		std::memcpy(dec.getBuffer().data(), encoded.data(), encoded.size());
		const bool ok = dec.decode(std::span< const byte >(dec.getBuffer().data(), encoded.size()));
		std::printf("ping_decoded=%d,%llu\n", ok ? 1 : 0, static_cast< unsigned long long >(dec.getPingData().timestamp));
	}

	// OCB2 known-answer: all-zero key/nonce, 16 zero bytes -> fixed ciphertext and tag
	{
		CryptStateOCB2 cs;
		unsigned char key[16] = {}, nonce[16] = {}, plain[16] = {}, crypt[16] = {}, tag[16] = {};
		cs.setKey(std::string(reinterpret_cast< char * >(key), 16), std::string(reinterpret_cast< char * >(nonce), 16),
				  std::string(reinterpret_cast< char * >(nonce), 16));
		cs.ocb_encrypt(plain, crypt, sizeof(plain), nonce, tag);
		hex("ocb_crypt", crypt, sizeof(crypt));
		hex("ocb_tag", tag, sizeof(tag));
	}

	// HostAddress formatting
	{
		HostAddress h;
		h.fromIPv4(0xC0A80101, false);
		std::printf("host=%s\n", h.toString(false).toStdString().c_str());
	}

	return 0;
}
