// Fuzzes HTMLFilter::filter, which turns chat/comment HTML into plain text.
#include "HTMLFilter.h"

#include <QString>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size > 64 * 1024) {
		return -1;
	}

	const QString in = QString::fromUtf8(reinterpret_cast< const char * >(data), static_cast< qsizetype >(size));
	QString out;
	HTMLFilter::filter(in, out);

	return 0;
}
