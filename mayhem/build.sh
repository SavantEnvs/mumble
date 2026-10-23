#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses (sanitized + instrumented), their -standalone reproducers,
# and the upstream Qt unit tests (normal flags) for mumble's `shared` library.
#
# The upstream CMake build needs 3rdparty git submodules that a fork checkout does not contain, so the
# `shared` library (src/CMakeLists.txt SHARED_SOURCES) is compiled directly, twice: once sanitized for the
# harnesses, once with normal flags for the tests. All dependencies are apt packages baked into the image.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC"
B="$SRC/build/mayhem"            # build/ is gitignored upstream, so `git clean -ffdX` removes it
GEN="$B/gen"
mkdir -p "$GEN" "$B/san/obj" "$B/clean/obj" "$B/tests" "$B/moc"

PKGS="Qt6Core Qt6Network Qt6Xml Qt6Test protobuf openssl spdlog"
pkg-config --exists $PKGS || { echo "missing build dependency; need: $PKGS" >&2; exit 1; }
read -r -a PKG_CFLAGS <<<"$(pkg-config --cflags $PKGS)"
read -r -a PKG_LIBS <<<"$(pkg-config --libs $PKGS)"
MOC="$(pkg-config --variable=libexecdir Qt6Core)/moc"
[ -x "$MOC" ] || MOC="$(command -v moc)"

# ---- generated sources (what src/CMakeLists.txt generates) ----
protoc --cpp_out="$GEN" -I "$SRC/src" "$SRC/src/Mumble.proto" "$SRC/src/MumbleUDP.proto"
python3 "$SRC/scripts/generate-ffdhe.py" --output "$GEN/FFDHETable.h"
python3 "$SRC/scripts/generate_license_header.py" --dep-file "$SRC/dependencies.json" \
	--mumble-license-file "$SRC/LICENSE" --output "$GEN/licenses.h"
"$MOC" -I"$SRC/src" -I"$GEN" "${PKG_CFLAGS[@]}" "$SRC/src/ServerResolver.h" -o "$GEN/moc_ServerResolver.cpp"
"$MOC" -I"$SRC/src" -I"$GEN" "${PKG_CFLAGS[@]}" "$SRC/src/ServerResolver.cpp" -o "$GEN/ServerResolver.moc"

COMMON_DEFS=(-DMUMBLE_VERSION=1.7.0 -DMUMBLE_VERSION_MAJOR=1 -DMUMBLE_VERSION_MINOR=7 -DMUMBLE_VERSION_PATCH=0
	-DQT_RESTRICTED_CAST_FROM_ASCII -DUSE_QSSLDIFFIEHELLMANPARAMETERS -DMUMBLE_BUILD_YEAR=now -D_USE_MATH_DEFINES
	'-DMUMBLE_TARGET_ARCH="x86_64"' '-DMUMBLE_TARGET_OS="Linux"' -DQT_USE_FAST_CONCATENATION -DQT_USE_FAST_OPERATOR_PLUS)
COMMON_INC=(-I"$SRC/src" -I"$GEN" -I"$SRC/3rdparty/arc4random")
CXXSTD=(-std=c++20 -fPIC)

SHARED_SOURCES=(
	Ban EnvUtils ExceptionUtils FFDHE HostAddress HTMLFilter License Logger MumbleProtocol OSInfo PasswordGenerator
	PlatformCheck QtUtils ProcessResolver ProtoUtils SelfSignedCertificate ServerAddress ServerResolver
	ServerResolverRecord SSL SSLLocks Timer UnresolvedServerAddress Version VolumeAdjustment
	crypto/CryptographicHash crypto/CryptographicRandom crypto/CryptState crypto/CryptStateOCB2
)

# Upstream UB that fires on every valid input and would halt the fuzzer before it reaches new code.
# Suppressed per file with -fno-sanitize= (not -fsanitize-ignorelist=, whose file ccache does not hash).
# Only the sanitized build sets UBSAN_SUPPRESS=1; every other UBSan check stays active in these files.
ubsan_suppress_flags() {
	[ "${UBSAN_SUPPRESS:-0}" = 1 ] || return 0
	case "$1" in
	# CryptStateOCB2: AESencrypt/AESdecrypt macros compute `(dst) + outlen` on a keyblock (unsigned long long[2])
	# with outlen=16 (array-bounds); XOR/S2/S3 load uint64_t blocks straight from byte offsets of the packet
	# buffer (alignment).
	*/src/crypto/CryptStateOCB2.cpp) echo -fno-sanitize=array-bounds,alignment ;;
	# MumbleProtocol: legacy extended ping decode loads a uint64_t through a misaligned reinterpret_cast.
	*/src/MumbleProtocol.cpp) echo -fno-sanitize=alignment ;;
	esac
}

# build_shared <dir> <compiler flags...> : compile the shared library into <dir>/libshared.a
build_shared() {
	local dir="$1"; shift
	local pids=() srcs=() objs=() s i rc=0
	for s in "${SHARED_SOURCES[@]}"; do
		srcs+=("$SRC/src/$s.cpp"); objs+=("$dir/obj/$(basename "$s").o")
	done
	srcs+=("$GEN/Mumble.pb.cc" "$GEN/MumbleUDP.pb.cc" "$GEN/moc_ServerResolver.cpp" "$SRC/3rdparty/arc4random/arc4random_uniform.cpp")
	objs+=("$dir/obj/Mumble.pb.o" "$dir/obj/MumbleUDP.pb.o" "$dir/obj/moc_ServerResolver.o" "$dir/obj/arc4random_uniform.o")
	for i in "${!srcs[@]}"; do
		while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n || true; done
		# shellcheck disable=SC2046
		"$CXX" "$@" $(ubsan_suppress_flags "${srcs[$i]}") -c "${srcs[$i]}" -o "${objs[$i]}" &
		pids+=($!)
	done
	for i in "${pids[@]}"; do wait "$i" || rc=1; done
	[ "$rc" -eq 0 ] || { echo "shared library compile failed in $dir" >&2; exit 1; }
	rm -f "$dir/libshared.a"
	ar rcs "$dir/libshared.a" "$dir"/obj/*.o
}

# ---- 1) sanitized + coverage-instrumented library for the fuzz harnesses ----
# shellcheck disable=SC2086
UBSAN_SUPPRESS=1 build_shared "$B/san" "${CXXSTD[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" "${PKG_CFLAGS[@]}" \
	$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1

# ---- 2) harnesses (fuzzer + standalone reproducer) ----
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "${CXXSTD[@]}" -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"

HARNESSES=(fuzz_udp_decoder fuzz_packetdatastream fuzz_cryptstate fuzz_htmlfilter fuzz_tcp_messages fuzz_network_types)
for h in "${HARNESSES[@]}"; do
	HFLAGS=("${CXXSTD[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" "${PKG_CFLAGS[@]}")
	# shellcheck disable=SC2086
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link "${HFLAGS[@]}" -c "$SRC/mayhem/$h.cpp" -o "$B/$h.o"
	# shellcheck disable=SC2086
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "$B/lsan_off.o" "$B/san/libshared.a" \
		"${PKG_LIBS[@]}" -o "$OUT/$h"
	# shellcheck disable=SC2086
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$h.o" "$B/standalone_main.o" "$B/lsan_off.o" "$B/san/libshared.a" \
		"${PKG_LIBS[@]}" -o "$OUT/$h-standalone"
done

# ---- 3) upstream unit tests + KAT probe, normal flags ----
# shellcheck disable=SC2086
build_shared "$B/clean" "${CXXSTD[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" "${PKG_CFLAGS[@]}" -O2 $COVERAGE_FLAGS

TESTS=(TestCaseInsensitiveQString TestCrypt TestCryptographicHash TestCryptographicRandom TestFFDHE
	TestMumbleProtocol TestPacketDataStream TestPasswordGenerator TestSelfSignedCertificate TestServerAddress
	TestSSLCiphers TestSSLLocks TestStdAbs TestUnresolvedServerAddress TestVersion)
for t in "${TESTS[@]}"; do
	tsrc="$SRC/src/tests/$t/$t.cpp"
	"$MOC" -I"$SRC/src" -I"$GEN" "${PKG_CFLAGS[@]}" "${COMMON_DEFS[@]}" "$tsrc" -o "$B/moc/$t.moc"
	$CXX "${CXXSTD[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" "${PKG_CFLAGS[@]}" -I"$B/moc" -O2 $COVERAGE_FLAGS \
		"$tsrc" "$B/clean/libshared.a" "${PKG_LIBS[@]}" $COVERAGE_FLAGS -o "$B/tests/$t"
done
$CXX "${CXXSTD[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" "${PKG_CFLAGS[@]}" -O2 $COVERAGE_FLAGS \
	"$SRC/mayhem/kat_probe.cpp" "$B/clean/libshared.a" "${PKG_LIBS[@]}" $COVERAGE_FLAGS -o "$B/tests/kat_probe"
