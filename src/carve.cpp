#include "carve.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <cwctype>

namespace {

constexpr size_t kMaxFlows = 256;
constexpr size_t kMaxFiles = 20000;

constexpr size_t kMaxFile = 512ull << 20;
constexpr size_t kMaxTotal = 1024ull << 20;
constexpr size_t kMaxFlowBuffer = 64ull << 20;

constexpr size_t kMaxDiskFlowBuffer = kMaxFile + (16ull << 20);

enum Sig {
    SIG_JPEG, SIG_PNG, SIG_GIF, SIG_BMP, SIG_TIFF, SIG_WEBP, SIG_ICO, SIG_PSD, SIG_DDS, SIG_JP2,
    SIG_PDF, SIG_ZIP, SIG_RAR, SIG_7Z, SIG_GZIP, SIG_CAB,
    SIG_MP4, SIG_AVI, SIG_MKV, SIG_FLV, SIG_MPEG, SIG_ASF, SIG_OGG,
    SIG_MP3, SIG_WAV, SIG_FLAC, SIG_AIFF, SIG_AMR, SIG_MIDI,
    SIG_PE, SIG_ELF, SIG_BATCH,
    SIG_COUNT
};

struct SigInfo {
    const wchar_t* type;
    const wchar_t* ext;
    size_t minSize;
};

const SigInfo kSigInfo[SIG_COUNT] = {
    {L"JPEG image",       L".jpg",  100},
    {L"PNG image",        L".png",  60},
    {L"GIF image",        L".gif",  20},
    {L"BMP image",        L".bmp",  26},
    {L"TIFF image",       L".tif",  100},
    {L"WebP image",       L".webp", 30},
    {L"ICO icon",         L".ico",  40},
    {L"Photoshop image",  L".psd",  40},
    {L"DirectDraw image", L".dds",  128},
    {L"JPEG 2000 image",  L".jp2",  40},
    {L"PDF document",     L".pdf",  60},
    {L"ZIP archive",      L".zip",  100},
    {L"RAR archive",      L".rar",  20},
    {L"7-Zip archive",    L".7z",   20},
    {L"GZip archive",     L".gz",   20},
    {L"Cabinet archive",  L".cab",  36},
    {L"MP4 video",        L".mp4",  100},
    {L"AVI video",        L".avi",  100},
    {L"Matroska video",   L".mkv",  100},
    {L"Flash video",      L".flv",  20},
    {L"MPEG video",       L".mpg",  100},
    {L"ASF media",        L".wmv",  100},
    {L"Ogg media",        L".ogg",  100},
    {L"MP3 audio",        L".mp3",  100},
    {L"WAV audio",        L".wav",  44},
    {L"FLAC audio",       L".flac", 40},
    {L"AIFF audio",       L".aiff", 40},
    {L"AMR audio",        L".amr",  20},
    {L"MIDI audio",       L".mid",  20},
    {L"PE executable",    L".exe",  64},
    {L"ELF executable",   L".elf",  64},
    {L"Batch script",     L".bat",  16},
};

const unsigned char kPngMagic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
const unsigned char kTiffLe[]   = {0x49, 0x49, 0x2A, 0x00};
const unsigned char kTiffBe[]   = {0x4D, 0x4D, 0x00, 0x2A};
const unsigned char kRarMagic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
const unsigned char k7zMagic[]  = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
const unsigned char kMkvMagic[] = {0x1A, 0x45, 0xDF, 0xA3};
const unsigned char kJp2Magic[] = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20,
                                   0x0D, 0x0A, 0x87, 0x0A};
const unsigned char kAsfGuid[]  = {0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
                                   0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C};
const unsigned char kElfMagic[] = {0x7F, 0x45, 0x4C, 0x46};

inline uint16_t Le16(const std::vector<BYTE>& b, size_t p) {
    return static_cast<uint16_t>(b[p] | (b[p + 1] << 8));
}
inline uint32_t Le32(const std::vector<BYTE>& b, size_t p) {
    return static_cast<uint32_t>(b[p]) | (static_cast<uint32_t>(b[p + 1]) << 8) |
           (static_cast<uint32_t>(b[p + 2]) << 16) | (static_cast<uint32_t>(b[p + 3]) << 24);
}
inline uint32_t Be32(const std::vector<BYTE>& b, size_t p) {
    return (static_cast<uint32_t>(b[p]) << 24) | (static_cast<uint32_t>(b[p + 1]) << 16) |
           (static_cast<uint32_t>(b[p + 2]) << 8) | static_cast<uint32_t>(b[p + 3]);
}
inline uint64_t Be64(const std::vector<BYTE>& b, size_t p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[p + i];
    return v;
}
inline uint16_t Be16(const std::vector<BYTE>& b, size_t p) {
    return static_cast<uint16_t>((b[p] << 8) | b[p + 1]);
}
inline uint64_t Le64(const std::vector<BYTE>& b, size_t p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | b[p + i];
    return v;
}

bool LooksLikeBmp(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 34 > n) return false;
    const uint32_t fileSize = Le32(b, i + 2);
    if (Le16(b, i + 6) != 0 || Le16(b, i + 8) != 0) return false;
    const uint32_t pixelOffset = Le32(b, i + 10);
    const uint32_t dibSize = Le32(b, i + 14);
    if (dibSize != 40 && dibSize != 52 && dibSize != 56 && dibSize != 64 && dibSize != 108 &&
        dibSize != 124) {
        return false;
    }
    if (fileSize < 26 || fileSize > kMaxFile) return false;
    if (pixelOffset < 14 + dibSize || pixelOffset >= fileSize) return false;

    const int32_t width = static_cast<int32_t>(Le32(b, i + 18));
    const int32_t height = static_cast<int32_t>(Le32(b, i + 22));
    if (width <= 0 || width > 65535) return false;
    if (height == 0 || height > 65535 || height < -65535) return false;

    if (Le16(b, i + 26) != 1) return false;
    const uint16_t bits = Le16(b, i + 28);
    if (bits != 1 && bits != 4 && bits != 8 && bits != 16 && bits != 24 && bits != 32) return false;
    if (Le32(b, i + 30) > 6) return false;
    return true;
}

bool JpegMarkerValid(BYTE marker) {
    return (marker >= 0xE0 && marker <= 0xEF) ||
           marker == 0xDB || marker == 0xC4 || marker == 0xDD || marker == 0xFE ||
           (marker >= 0xC0 && marker <= 0xCF);
}

bool LooksLikeIco(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 6 + 16 > n) return false;
    if (b[i] != 0 || b[i + 1] != 0 || (b[i + 2] != 1 && b[i + 2] != 2) || b[i + 3] != 0) return false;
    const uint16_t count = Le16(b, i + 4);
    if (count == 0 || count > 255) return false;
    const size_t dir = i + 6;
    if (dir + static_cast<size_t>(count) * 16 > n) return false;
    for (uint16_t e = 0; e < count; ++e) {
        const size_t p = dir + static_cast<size_t>(e) * 16;
        const uint16_t planes = Le16(b, p + 4);
        const uint16_t bits = Le16(b, p + 6);
        const uint32_t bytes = Le32(b, p + 8);
        const uint32_t offset = Le32(b, p + 12);
        if (b[i + 2] == 1 && (planes != 1 || bits > 32)) return false;
        if (bytes == 0 || offset < dir + static_cast<size_t>(count) * 16) return false;
    }
    return true;
}

bool LooksLikePsd(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 26 > n) return false;
    if (std::memcmp(&b[i], "8BPS", 4) != 0) return false;
    if (Be16(b, i + 4) != 1) return false;
    for (int k = 6; k < 12; ++k) {
        if (b[i + k] != 0) return false;
    }
    const uint16_t channels = Be16(b, i + 12);
    const uint32_t height = Be32(b, i + 14);
    const uint32_t width = Be32(b, i + 18);
    const uint16_t depth = Be16(b, i + 22);
    const uint16_t mode = Be16(b, i + 24);
    if (channels < 1 || channels > 56) return false;
    if (width == 0 || height == 0 || width > 300000 || height > 300000) return false;
    if (depth != 1 && depth != 8 && depth != 16 && depth != 32) return false;
    return mode <= 9;
}

bool LooksLikeDds(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 128 > n) return false;
    if (std::memcmp(&b[i], "DDS ", 4) != 0) return false;
    if (Le32(b, i + 4) != 124) return false;
    const uint32_t height = Le32(b, i + 12);
    const uint32_t width = Le32(b, i + 16);
    return height > 0 && width > 0 && height <= 65536 && width <= 65536;
}

size_t Mp3FrameLength(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 4 > n) return 0;
    if (b[i] != 0xFF || (b[i + 1] & 0xE0) != 0xE0) return 0;
    const int version = (b[i + 1] >> 3) & 3;
    const int layer = (b[i + 1] >> 1) & 3;
    if (version == 1 || layer != 1) return 0;
    const int bitrateIndex = (b[i + 2] >> 4) & 0xF;
    const int sampleIndex = (b[i + 2] >> 2) & 3;
    if (bitrateIndex == 0 || bitrateIndex == 15 || sampleIndex == 3) return 0;
    static const int kBitrateV1[16] = {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0};
    static const int kBitrateV2[16] = {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0};
    static const int kSampleV1[4] = {44100, 48000, 32000, 0};
    static const int kSampleV2[4] = {22050, 24000, 16000, 0};
    static const int kSampleV25[4] = {11025, 12000, 8000, 0};
    const int bitrate = (version == 3) ? kBitrateV1[bitrateIndex] : kBitrateV2[bitrateIndex];
    const int sample = (version == 3) ? kSampleV1[sampleIndex]
                                      : (version == 2 ? kSampleV2[sampleIndex] : kSampleV25[sampleIndex]);
    if (bitrate == 0 || sample == 0) return 0;
    const int pad = (b[i + 2] >> 1) & 1;
    const int length = ((version == 3) ? 144 : 72) * bitrate * 1000 / sample + pad;
    return length > 4 ? static_cast<size_t>(length) : 0;
}

bool LooksLikeMp3(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 10 <= n && std::memcmp(&b[i], "ID3", 3) == 0) {
        return b[i + 3] < 0xFF && b[i + 4] < 0xFF && (b[i + 5] & 0x0F) == 0;
    }
    const size_t first = Mp3FrameLength(b, i);
    if (first == 0) return false;
    const size_t next = i + first;
    if (next + 4 > n) return false;
    return Mp3FrameLength(b, next) != 0;
}

bool LooksLikeMpeg(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 14 > n) return false;
    if (b[i] != 0 || b[i + 1] != 0 || b[i + 2] != 1) return false;
    if (b[i + 3] == 0xBA) {

        if ((b[i + 4] & 0xC0) != 0x40) return false;
        if ((b[i + 4] & 0x04) == 0) return false;
        if ((b[i + 6] & 0x04) == 0) return false;
        if ((b[i + 8] & 0x04) == 0) return false;
        if ((b[i + 9] & 0x01) == 0) return false;
        if ((b[i + 12] & 0x03) != 0x03) return false;

        const size_t limit = std::min(n, i + 4096);
        for (size_t p = i + 14; p + 3 < limit; ++p) {
            if (b[p] != 0 || b[p + 1] != 0 || b[p + 2] != 1) continue;
            const BYTE code = b[p + 3];
            if (code == 0xBA || code == 0xBB || code == 0xB9 || code == 0xBD ||
                (code >= 0xC0 && code <= 0xEF)) {
                return true;
            }
        }
        return false;
    }
    if (b[i + 3] == 0xB3) {
        const uint32_t width = (static_cast<uint32_t>(b[i + 4]) << 4) | (b[i + 5] >> 4);
        const uint32_t height = ((static_cast<uint32_t>(b[i + 5]) & 0x0F) << 8) | b[i + 6];
        const uint8_t aspect = b[i + 7] >> 4;
        const uint8_t rate = b[i + 7] & 0x0F;
        if (width < 16 || width > 8192 || height < 16 || height > 8192) return false;
        if (aspect == 0) return false;
        return rate != 0 && rate != 15;
    }
    return false;
}

bool LooksLikeOgg(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 27 > n) return false;
    if (std::memcmp(&b[i], "OggS", 4) != 0) return false;
    if (b[i + 4] != 0) return false;
    if (b[i + 5] & 0xF8) return false;
    return b[i + 26] != 0;
}

bool LooksLikeFlac(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 8 > n) return false;
    if (std::memcmp(&b[i], "fLaC", 4) != 0) return false;

    return b[i + 4] == 0x00 && b[i + 5] == 0x00 && b[i + 6] == 0x00 && b[i + 7] == 0x22;
}

bool LooksLikeMidi(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 14 > n) return false;
    if (std::memcmp(&b[i], "MThd", 4) != 0) return false;
    if (Be32(b, i + 4) != 6) return false;
    if (Be16(b, i + 8) > 2) return false;
    if (Be16(b, i + 10) == 0) return false;
    return Be16(b, i + 12) != 0;
}

bool LooksLikeCab(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 36 > n) return false;
    if (std::memcmp(&b[i], "MSCF", 4) != 0) return false;
    const uint32_t size = Le32(b, i + 8);
    return size >= 36 && size <= kMaxFile;
}

bool LooksLikePe(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 0x40 > n) return false;
    if (b[i] != 'M' || b[i + 1] != 'Z') return false;
    const uint32_t lfanew = Le32(b, i + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x1000) return false;
    const size_t pe = i + lfanew;
    if (pe + 24 > n) return false;
    if (std::memcmp(&b[pe], "PE\0\0", 4) != 0) return false;
    const uint16_t machine = Le16(b, pe + 4);
    const uint16_t sections = Le16(b, pe + 6);
    const uint16_t optSize = Le16(b, pe + 20);
    if (sections == 0 || sections > 96 || optSize < 60) return false;
    const uint16_t magic = Le16(b, pe + 24);
    if (magic != 0x10B && magic != 0x20B) return false;
    switch (machine) {
    case 0x014C: case 0x8664: case 0x01C0: case 0x01C4: case 0xAA64: case 0x0200:
        return true;
    default:
        return false;
    }
}

bool LooksLikeElf(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 20 > n) return false;
    if (std::memcmp(&b[i], kElfMagic, 4) != 0) return false;
    if (b[i + 4] != 1 && b[i + 4] != 2) return false;
    if (b[i + 5] != 1 && b[i + 5] != 2) return false;
    if (b[i + 6] != 1) return false;
    const uint16_t type = b[i + 5] == 1 ? Le16(b, i + 16) : Be16(b, i + 16);
    return type >= 1 && type <= 4;
}

bool LooksLikeBatch(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();
    if (i + 9 > n) return false;
    if (i > 0) {

        const BYTE previous = b[i - 1];
        const bool boundary = previous == '\n' || previous == '\r' || previous == 0 ||
                              previous == 0xFF || previous == 0xCC;
        if (!boundary) return false;
    }
    static const char tag[] = "@echo off";
    for (int k = 0; k < 9; ++k) {
        if (std::tolower(static_cast<unsigned char>(b[i + k])) != tag[k]) return false;
    }
    const size_t limit = std::min(n, i + 256);
    size_t printable = 0;
    for (size_t p = i; p < limit; ++p) {
        const BYTE c = b[p];
        if (c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F)) ++printable;
    }
    return limit > i && printable * 100 >= (limit - i) * 95;
}

int MatchAt(const std::vector<BYTE>& b, size_t i) {
    const size_t n = b.size();

    if (i + 4 <= n && b[i] == 0xFF && b[i + 1] == 0xD8 && b[i + 2] == 0xFF &&
        JpegMarkerValid(b[i + 3])) {
        return SIG_JPEG;
    }
    if (i + 8 <= n && std::memcmp(&b[i], kPngMagic, 8) == 0) return SIG_PNG;
    if (i + 6 <= n && (std::memcmp(&b[i], "GIF87a", 6) == 0 ||
                        std::memcmp(&b[i], "GIF89a", 6) == 0)) {
        return SIG_GIF;
    }
    if (i + 4 <= n && (std::memcmp(&b[i], kTiffLe, 4) == 0 || std::memcmp(&b[i], kTiffBe, 4) == 0))
        return SIG_TIFF;
    if (i + 12 <= n && std::memcmp(&b[i], kJp2Magic, 12) == 0) return SIG_JP2;
    if (i + 4 <= n && std::memcmp(&b[i], "8BPS", 4) == 0 && LooksLikePsd(b, i)) return SIG_PSD;
    if (i + 4 <= n && std::memcmp(&b[i], "DDS ", 4) == 0 && LooksLikeDds(b, i)) return SIG_DDS;
    if (i + 4 <= n && b[i] == 0 && b[i + 1] == 0 && (b[i + 2] == 1 || b[i + 2] == 2) &&
        b[i + 3] == 0 && LooksLikeIco(b, i)) {
        return SIG_ICO;
    }
    if (i + 5 <= n && std::memcmp(&b[i], "%PDF-", 5) == 0) return SIG_PDF;
    if (i + 4 <= n && b[i] == 'P' && b[i + 1] == 'K' && b[i + 2] == 0x03 && b[i + 3] == 0x04)
        return SIG_ZIP;
    if (i + 6 <= n && std::memcmp(&b[i], kRarMagic, 6) == 0) return SIG_RAR;
    if (i + 6 <= n && std::memcmp(&b[i], k7zMagic, 6) == 0) return SIG_7Z;
    if (i + 3 <= n && b[i] == 0x1F && b[i + 1] == 0x8B && b[i + 2] == 0x08) return SIG_GZIP;
    if (i + 4 <= n && std::memcmp(&b[i], "MSCF", 4) == 0 && LooksLikeCab(b, i)) return SIG_CAB;
    if (i + 4 <= n && std::memcmp(&b[i], kMkvMagic, 4) == 0) return SIG_MKV;
    if (i + 4 <= n && b[i] == 'F' && b[i + 1] == 'L' && b[i + 2] == 'V' && b[i + 3] == 0x01)
        return SIG_FLV;
    if (i + 16 <= n && std::memcmp(&b[i], kAsfGuid, 16) == 0) return SIG_ASF;
    if (i + 4 <= n && std::memcmp(&b[i], "OggS", 4) == 0 && LooksLikeOgg(b, i)) return SIG_OGG;
    if (i + 4 <= n && std::memcmp(&b[i], "fLaC", 4) == 0 && LooksLikeFlac(b, i)) return SIG_FLAC;
    if (i + 4 <= n && std::memcmp(&b[i], "MThd", 4) == 0 && LooksLikeMidi(b, i)) return SIG_MIDI;
    if (i + 6 <= n && std::memcmp(&b[i], "#!AMR", 5) == 0 &&
        (b[i + 5] == '\n' || b[i + 5] == '\r')) {
        return SIG_AMR;
    }
    if (i + 14 <= n && b[i] == 'B' && b[i + 1] == 'M' && LooksLikeBmp(b, i)) return SIG_BMP;
    if (i + 12 <= n && std::memcmp(&b[i], "RIFF", 4) == 0) {
        if (std::memcmp(&b[i + 8], "WEBP", 4) == 0) return SIG_WEBP;
        if (std::memcmp(&b[i + 8], "AVI ", 4) == 0) return SIG_AVI;
        if (std::memcmp(&b[i + 8], "WAVE", 4) == 0) return SIG_WAV;
    }
    if (i + 12 <= n && std::memcmp(&b[i], "FORM", 4) == 0 &&
        (std::memcmp(&b[i + 8], "AIFF", 4) == 0 || std::memcmp(&b[i + 8], "AIFC", 4) == 0)) {
        return SIG_AIFF;
    }
    if (i + 0x40 <= n && b[i] == 'M' && b[i + 1] == 'Z' && LooksLikePe(b, i)) return SIG_PE;
    if (i + 20 <= n && b[i] == 0x7F && LooksLikeElf(b, i)) return SIG_ELF;

    if (i + 4 <= n && LooksLikeMp3(b, i)) return SIG_MP3;
    if (i + 12 <= n && LooksLikeMpeg(b, i)) return SIG_MPEG;
    if (i + 9 <= n && b[i] == '@' && LooksLikeBatch(b, i)) return SIG_BATCH;
    if (i + 8 <= n && std::memcmp(&b[i + 4], "ftyp", 4) == 0) {
        uint32_t sz = Be32(b, i);
        if (sz >= 8 && sz <= (64u << 20)) return SIG_MP4;
    }
    return -1;
}

bool GifEnd(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    size_t p = off + 6;
    if (p + 7 > b.size()) return false;
    const BYTE packed = b[p + 4];
    p += 7;
    if (packed & 0x80) p += static_cast<size_t>(3) << ((packed & 7) + 1);
    while (p < b.size()) {
        const BYTE block = b[p];
        if (block == 0x3B) { end = p + 1; complete = true; return true; }
        if (block == 0x2C) {
            if (p + 10 > b.size()) return false;
            const BYTE flags = b[p + 9];
            p += 10;
            if (flags & 0x80) p += static_cast<size_t>(3) << ((flags & 7) + 1);
            if (p >= b.size()) return false;
            ++p;
        } else if (block == 0x21) {
            if (p + 2 > b.size()) return false;
            p += 2;
        } else {
            return false;
        }
        for (;;) {
            if (p >= b.size()) return false;
            const BYTE length = b[p++];
            if (length == 0) break;
            if (p + length > b.size()) return false;
            p += length;
        }
    }
    return false;
}

bool Mp3End(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    const size_t n = b.size();
    size_t p = off;
    if (p + 10 <= n && std::memcmp(&b[p], "ID3", 3) == 0) {
        const size_t tag = 10 + ((static_cast<size_t>(b[p + 6] & 0x7F) << 21) |
                                 (static_cast<size_t>(b[p + 7] & 0x7F) << 14) |
                                 (static_cast<size_t>(b[p + 8] & 0x7F) << 7) |
                                 static_cast<size_t>(b[p + 9] & 0x7F));
        if (tag > n - p) return false;
        p += tag;
    }
    size_t last = p;
    int frames = 0;
    while (p + 4 <= n) {
        const size_t length = Mp3FrameLength(b, p);
        if (length == 0) break;
        if (p + length > n) { end = p; complete = false; return frames > 0; }
        p += length;
        last = p;
        ++frames;
    }
    if (frames == 0) return false;
    end = last;
    complete = true;
    return true;
}

bool JpegEnd(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    const size_t n = b.size();
    size_t p = off + 2;
    bool sawScan = false;
    while (p + 1 < n) {
        if (b[p] != 0xFF) {

            if (sawScan && p - off >= kSigInfo[SIG_JPEG].minSize) {
                end = p;
                complete = false;
                return true;
            }
            return false;
        }
        size_t q = p + 1;
        while (q < n && b[q] == 0xFF) ++q;
        if (q >= n) return false;
        const BYTE marker = b[q];
        if (marker == 0xD9) {
            end = q + 1;
            complete = true;
            return true;
        }
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            p = q + 1;
            continue;
        }
        if (q + 2 >= n) return false;
        const size_t length = (static_cast<size_t>(b[q + 1]) << 8) | b[q + 2];
        if (length < 2) return false;
        p = q + 1 + length;
        if (p > n) {
            end = n;
            complete = false;
            return true;
        }
        if (marker != 0xDA) continue;
        sawScan = true;
        while (p + 1 < n) {
            if (b[p] != 0xFF) { ++p; continue; }
            const BYTE next = b[p + 1];
            if (next == 0x00 || (next >= 0xD0 && next <= 0xD7)) {
                p += 2;
                continue;
            }
            break;
        }
    }
    return false;
}

bool IcoEnd(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 6 > b.size()) return false;
    const uint16_t count = Le16(b, off + 4);
    const size_t dir = off + 6;
    if (dir + static_cast<size_t>(count) * 16 > b.size()) return false;
    size_t total = dir + static_cast<size_t>(count) * 16;
    for (uint16_t e = 0; e < count; ++e) {
        const size_t p = dir + static_cast<size_t>(e) * 16;
        const uint32_t bytes = Le32(b, p + 8);
        const uint32_t offset = Le32(b, p + 12);
        const size_t candidate = off + static_cast<size_t>(offset) + bytes;
        if (candidate > total) total = candidate;
    }
    end = total;
    complete = end <= b.size();
    return complete;
}

bool RiffSize(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 8 > b.size()) return false;
    const uint32_t sz = Le32(b, off + 4);
    if (sz < 4 || sz > kMaxFile) return false;
    end = off + 8 + static_cast<size_t>(sz);
    complete = end <= b.size();
    return complete;
}

bool FormSize(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 8 > b.size()) return false;
    const uint32_t sz = Be32(b, off + 4);
    if (sz < 4 || sz > kMaxFile) return false;
    end = off + 8 + static_cast<size_t>(sz);
    complete = end <= b.size();
    return complete;
}

bool PeSize(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 0x40 > b.size()) return false;
    const uint32_t lfanew = Le32(b, off + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x1000) return false;
    const size_t pe = off + lfanew;
    if (pe + 24 > b.size()) return false;
    const uint16_t sections = Le16(b, pe + 6);
    const uint16_t optSize = Le16(b, pe + 20);
    const size_t opt = pe + 24;
    if (opt + 60 > b.size()) return false;
    const uint32_t sizeOfHeaders = Le32(b, opt + 60);
    const size_t secTable = opt + optSize;
    if (secTable + static_cast<size_t>(sections) * 40 > b.size()) return false;
    size_t total = sizeOfHeaders;
    for (uint16_t s = 0; s < sections; ++s) {
        const size_t sh = secTable + static_cast<size_t>(s) * 40;
        const uint32_t rawSize = Le32(b, sh + 16);
        const uint32_t rawPtr = Le32(b, sh + 20);
        if (rawSize && rawPtr) {
            const size_t candidate = static_cast<size_t>(rawPtr) + rawSize;
            if (candidate > total) total = candidate;
        }
    }
    if (total < 64 || total > kMaxFile) return false;
    end = off + total;
    complete = end <= b.size();
    return complete;
}

bool ElfSize(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 52 > b.size()) return false;
    const bool is64 = b[off + 4] == 2;
    if (b[off + 5] != 1) return false;
    size_t shoff = 0, shentsize = 0, shnum = 0;
    if (is64) {
        if (off + 64 > b.size()) return false;
        shoff = static_cast<size_t>(Le64(b, off + 0x28));
        shentsize = Le16(b, off + 0x3A);
        shnum = Le16(b, off + 0x3C);
    } else {
        shoff = Le32(b, off + 0x20);
        shentsize = Le16(b, off + 0x2E);
        shnum = Le16(b, off + 0x30);
    }
    if (shoff == 0 || shnum == 0 || shentsize < (is64 ? 64u : 40u)) return false;
    if (shoff + shnum * shentsize > b.size()) return false;
    size_t total = 0;
    for (size_t s = 0; s < shnum; ++s) {
        const size_t sh = off + shoff + s * shentsize;
        const size_t shOffset = is64 ? static_cast<size_t>(Le64(b, sh + 0x18)) : Le32(b, sh + 0x10);
        const size_t shSize = is64 ? static_cast<size_t>(Le64(b, sh + 0x20)) : Le32(b, sh + 0x14);
        if (shOffset && shSize) {
            const size_t candidate = shOffset + shSize;
            if (candidate > total) total = candidate;
        }
    }
    if (total < 64 || total > kMaxFile) return false;
    end = off + total;
    complete = end <= b.size();
    return complete;
}

bool BoxWalkEnd(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    size_t p = off;
    size_t last = off;
    bool broke = false;
    while (p + 8 <= b.size()) {
        const uint32_t boxSize = Be32(b, p);
        if (boxSize == 0) {

            bool typed = true;
            for (size_t k = 4; k < 8; ++k) {
                if (b[p + k] < 0x20 || b[p + k] > 0x7E) { typed = false; break; }
            }
            if (!typed) { broke = true; break; }
            end = b.size(); complete = false; return true;
        }
        if (boxSize == 1) {
            if (p + 16 > b.size()) { broke = true; break; }
            const uint64_t big = Be64(b, p + 8);
            if (big < 16 || big > kMaxFile || p + big > b.size()) { broke = true; break; }
            p += static_cast<size_t>(big);
        } else {
            if (boxSize < 8 || boxSize > kMaxFile || p + boxSize > b.size()) { broke = true; break; }
            p += boxSize;
        }
        last = p;
    }
    if (last == off) return false;
    end = last;
    complete = !broke;
    return true;
}

bool MidiEnd(const std::vector<BYTE>& b, size_t off, size_t& end, bool& complete) {
    if (off + 14 > b.size()) return false;
    const uint32_t headerLen = Be32(b, off + 4);
    size_t p = off + 8 + headerLen;
    size_t last = p;
    while (p + 8 <= b.size()) {
        const uint32_t len = Be32(b, p + 4);
        if (len > kMaxFile || p + 8 + len > b.size()) break;
        p += 8 + len;
        last = p;
    }
    end = last;
    complete = last > off + 8 && p + 8 > b.size();
    return complete;
}

bool DetermineEnd(const std::vector<BYTE>& b, size_t off, int sig, size_t& end, bool& complete) {
    complete = false;
    switch (sig) {
    case SIG_JPEG:
        return JpegEnd(b, off, end, complete);
    case SIG_PNG:
        for (size_t p = off + 8; p + 4 <= b.size(); ++p) {
            if (b[p] == 'I' && b[p + 1] == 'E' && b[p + 2] == 'N' && b[p + 3] == 'D') {
                end = p + 8; complete = true; return true;
            }
        }
        return false;
    case SIG_GIF:
        return GifEnd(b, off, end, complete);
    case SIG_BMP: {
        if (off + 6 > b.size()) return false;
        uint32_t sz = Le32(b, off + 2);
        if (sz < 26 || sz > kMaxFile) return false;
        end = off + sz;
        complete = end <= b.size();
        return complete;
    }
    case SIG_ICO:
        return IcoEnd(b, off, end, complete);
    case SIG_WEBP:
    case SIG_AVI:
    case SIG_WAV:
        return RiffSize(b, off, end, complete);
    case SIG_AIFF:
        return FormSize(b, off, end, complete);
    case SIG_PDF:
        for (size_t p = off + 5; p + 5 <= b.size(); ++p) {
            if (b[p] == '%' && b[p + 1] == '%' && b[p + 2] == 'E' && b[p + 3] == 'O' && b[p + 4] == 'F') {
                end = p + 5; complete = true; return true;
            }
        }
        return false;
    case SIG_ZIP: {

        size_t foundEnd = 0;
        bool found = false;
        bool foundComplete = false;
        for (size_t p = off + 22; p + 22 <= b.size(); ++p) {
            if (b[p] != 'P' || b[p + 1] != 'K' || b[p + 2] != 0x05 || b[p + 3] != 0x06) continue;
            const uint16_t disk = Le16(b, p + 4);
            const uint16_t cdDisk = Le16(b, p + 6);
            const uint16_t comment = Le16(b, p + 20);
            const uint32_t cdSize = Le32(b, p + 12);
            const uint32_t cdOffset = Le32(b, p + 16);
            const size_t relative = p - off;
            if (disk != 0 || cdDisk != 0) continue;
            if (cdOffset > relative || cdSize > relative) continue;
            if (static_cast<size_t>(cdOffset) + cdSize > relative) continue;
            found = true;
            foundEnd = p + 22 + comment;
            foundComplete = foundEnd <= b.size();
        }
        if (!found) return false;
        end = foundEnd;
        complete = foundComplete;
        return complete;
    }
    case SIG_MP4:
    case SIG_JP2:
        return BoxWalkEnd(b, off, end, complete);
    case SIG_MIDI:
        return MidiEnd(b, off, end, complete);
    case SIG_PE:
        return PeSize(b, off, end, complete);
    case SIG_ELF:
        return ElfSize(b, off, end, complete);
    case SIG_CAB: {
        if (off + 12 > b.size()) return false;
        const uint32_t sz = Le32(b, off + 8);
        if (sz < 36 || sz > kMaxFile) return false;
        end = off + sz;
        complete = end <= b.size();
        return complete;
    }
    case SIG_ASF: {

        if (off + 24 > b.size()) return false;
        const uint64_t sz = Le64(b, off + 16);
        if (sz < 24 || sz > kMaxFile) return false;
        end = off + static_cast<size_t>(sz);
        complete = end <= b.size();
        return complete;
    }
    case SIG_TIFF:
    case SIG_RAR:
    case SIG_7Z:
    case SIG_MKV:
    case SIG_FLV:
    case SIG_PSD:
    case SIG_MP3:
        return Mp3End(b, off, end, complete);
    case SIG_DDS:
    case SIG_GZIP:
    case SIG_OGG:
    case SIG_MPEG:
    case SIG_FLAC:
    case SIG_AMR:

        end = b.size();
        complete = false;
        return true;
    case SIG_BATCH: {

        size_t p = off;
        while (p < b.size()) {
            const BYTE c = b[p];
            const bool text = c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F);
            if (!text) break;
            ++p;
        }
        if (p - off < 16) return false;
        end = p;
        complete = true;
        return true;
    }
    default:
        return false;
    }
}

std::wstring SanitizeName(std::wstring name) {
    std::wstring out;
    for (wchar_t c : name) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' ||
            c == L'<' || c == L'>' || c == L'|' || c < 32) {
            continue;
        }
        out.push_back(c);
    }
    while (!out.empty() && (out.front() == L' ' || out.front() == L'.')) out.erase(out.begin());
    while (!out.empty() && out.back() == L' ') out.pop_back();
    if (out.size() > 120) out = out.substr(0, 120);
    return out;
}

bool HasKnownExtension(const std::string& lowerToken) {
    static const char* exts[] = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".psd",
        ".dds", ".jp2", ".heic", ".heif", ".avif",
        ".mp4", ".m4v", ".mov", ".avi", ".mkv", ".webm", ".flv", ".wmv", ".asf", ".mpg",
        ".mpeg", ".3gp", ".m4a", ".mp3", ".wav", ".flac", ".ogg", ".oga", ".opus", ".aiff",
        ".aif", ".amr", ".mid", ".midi",
        ".exe", ".dll", ".sys", ".scr", ".com", ".elf", ".msi", ".cab",
        ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".pdf", ".zip", ".rar", ".7z", ".gz",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"};
    for (const char* e : exts) {
        size_t el = std::strlen(e);
        if (lowerToken.size() > el &&
            lowerToken.compare(lowerToken.size() - el, el, e) == 0) {
            return true;
        }
    }
    return false;
}

std::wstring ExtractName(const std::vector<BYTE>& b, size_t off) {
    const size_t start = off > 8192 ? off - 8192 : 0;
    const size_t stop = std::min(b.size(), off + 2048);
    if (stop <= start) return L"";
    std::string win(reinterpret_cast<const char*>(b.data() + start), stop - start);

    std::string lower = win;
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    size_t pos = 0;
    while ((pos = lower.find("filename=", pos)) != std::string::npos) {
        size_t v = pos + 9;
        bool quoted = false;
        if (v < win.size() && (win[v] == '"' || win[v] == '\'')) { quoted = true; ++v; }
        size_t e = v;
        while (e < win.size() && e - v < 200) {
            unsigned char c = static_cast<unsigned char>(win[e]);
            if (quoted && (c == '"' || c == '\'')) break;
            if (!quoted && (c == '\r' || c == '\n' || c == ';' || c == ' ')) break;
            if (c < 32) break;
            ++e;
        }
        if (e > v) {
            std::wstring name = SanitizeName(Utf8ToWide(win.substr(v, e - v)));
            if (!name.empty()) return name;
        }
        pos = v;
    }

    std::wstring best;
    size_t i = 0;
    while (i < win.size()) {
        unsigned char c = static_cast<unsigned char>(win[i]);
        if (std::isalnum(c) || c == '.' || c == '-' || c == '_' || c == '(' || c == ')' ||
            c == ' ' || c == '~') {
            size_t s = i;
            while (i < win.size()) {
                unsigned char d = static_cast<unsigned char>(win[i]);
                if (!(std::isalnum(d) || d == '.' || d == '-' || d == '_' || d == '(' ||
                      d == ')' || d == ' ' || d == '~')) {
                    break;
                }
                ++i;
            }
            std::string token = win.substr(s, i - s);
            std::string lowToken = token;
            for (char& ch : lowToken) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (HasKnownExtension(lowToken)) {
                std::wstring candidate = SanitizeName(Utf8ToWide(token));
                if (!candidate.empty()) best = candidate;
            }
        } else {
            ++i;
        }
    }
    return best;
}

std::wstring NowText() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return Format(L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
}

bool LooksLikeHttpRequest(const BYTE* data, size_t length) {
    static const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE "};
    if (length < 16) return false;
    for (const char* method : methods) {
        const size_t len = std::strlen(method);
        if (length > len && std::memcmp(data, method, len) == 0) return true;
    }
    return false;
}

std::wstring HttpRequestText(const BYTE* data, size_t length) {
    std::string text(reinterpret_cast<const char*>(data), std::min<size_t>(length, 2048));
    std::string line = text.substr(0, text.find("\r\n"));
    const size_t version = line.find(" HTTP/");
    if (version != std::string::npos) line.erase(version);

    std::string host;
    const size_t hostAt = text.find("\r\nHost:");
    if (hostAt != std::string::npos) {
        const size_t value = hostAt + 7;
        const size_t end = text.find("\r\n", value);
        host = text.substr(value, (end == std::string::npos ? text.size() : end) - value);
        while (!host.empty() && (host.front() == ' ' || host.front() == '\t')) host.erase(host.begin());
    }

    std::wstring result = Utf8ToWide(line);
    if (!host.empty()) result += L"  \u00B7  host " + Utf8ToWide(host);
    return result;
}

std::mutex g_mutex;
std::vector<CarvedFile> g_files;
std::set<uint64_t> g_hashes;
size_t g_total = 0;
unsigned g_counter = 0;

uint64_t HashPrefix(const BYTE* p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h ^ (static_cast<uint64_t>(n) * 2654435761ull);
}

void RefineType(int sig, const std::vector<BYTE>& b, size_t off,
                std::wstring& type, std::wstring& ext) {
    if (sig == SIG_PE) {
        if (off + 0x40 > b.size()) return;
        const uint32_t lfanew = Le32(b, off + 0x3C);
        if (lfanew < 0x40 || off + lfanew + 70 > b.size()) return;
        const size_t pe = off + lfanew;
        const uint16_t characteristics = Le16(b, pe + 22);
        const size_t opt = pe + 24;
        const uint16_t subsystem = Le16(b, opt + 68);
        if (characteristics & 0x2000) {
            type = L"PE dynamic library";
            ext = L".dll";
        } else if (subsystem == 1) {
            type = L"PE driver";
            ext = L".sys";
        } else {
            type = L"PE executable";
            ext = L".exe";
        }
    } else if (sig == SIG_MP4) {
        if (off + 12 > b.size()) return;
        char brand[4];
        std::memcpy(brand, &b[off + 8], 4);
        auto is = [&](const char* s) { return std::memcmp(brand, s, 4) == 0; };
        if (is("heic") || is("heix") || is("hevc") || is("hevx") || is("mif1") || is("msf1")) {
            type = L"HEIF image";
            ext = L".heic";
        } else if (is("avif") || is("avis")) {
            type = L"AVIF image";
            ext = L".avif";
        } else if (is("M4A ") || is("M4B ")) {
            type = L"M4A audio";
            ext = L".m4a";
        } else if (is("qt  ")) {
            type = L"QuickTime movie";
            ext = L".mov";
        } else if (is("3gp4") || is("3gp5") || is("3g2a")) {
            type = L"3GP video";
            ext = L".3gp";
        }
    }
}

void AddCarved(const std::vector<BYTE>& b, size_t off, size_t end, int sig,
               const std::wstring& source, const std::wstring& origin,
               const std::wstring& captured, bool complete) {

    size_t len = end - off;
    if (len > kMaxFile) {
        len = kMaxFile;
        complete = false;
    }
    if (len < kSigInfo[sig].minSize) return;

    const uint64_t hash = HashPrefix(b.data() + off, std::min<size_t>(len, 256)) ^
                          (static_cast<uint64_t>(len) << 1);

    CarvedFile file;
    file.type = kSigInfo[sig].type;
    file.ext = kSigInfo[sig].ext;
    RefineType(sig, b, off, file.type, file.ext);
    file.size = len;
    file.complete = complete;
    file.source = source;
    file.origin = origin;
    file.captured = captured;

    std::wstring name = ExtractName(b, off);
    if (name.empty()) {
        name = Format(L"capture_%u%s", ++g_counter, file.ext.c_str());
    } else if (name.find(L'.') == std::wstring::npos) {
        name += file.ext;
    }
    file.name = name;
    file.data.assign(b.begin() + off, b.begin() + off + len);
    file.hasData = true;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_files.size() >= kMaxFiles) return;
    if (g_total + file.size > kMaxTotal) return;
    if (!g_hashes.insert(hash).second) return;
    g_total += file.size;
    g_files.push_back(std::move(file));
}

}

std::vector<CarvedFile> CarvedSnapshot() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_files;
}

size_t CarvedCount() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_files.size();
}

std::vector<std::wstring> CarvedNames() {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<std::wstring> names;
    names.reserve(g_files.size());
    for (const CarvedFile& file : g_files) names.push_back(file.name);
    return names;
}

bool CarvedCopy(const std::wstring& name, CarvedFile& out) {
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const CarvedFile& file : g_files) {
        if (file.name == name) {
            out = file;
            return true;
        }
    }
    return false;
}

void CarvedClear() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_files.clear();
    g_hashes.clear();
    g_total = 0;
    g_counter = 0;
}

namespace {

std::wstring ExtensionOf(const std::wstring& name) {
    const size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos || dot + 1 >= name.size()) return L"";
    std::wstring ext = ToLower(name.substr(dot));
    if (ext.size() > 8) return L"";
    for (wchar_t c : ext) {
        if (!iswalnum(c) && c != L'.') return L"";
    }
    return ext;
}

const struct {
    const wchar_t* ext;
    const wchar_t* type;
} kExtraTypes[] = {
    {L".txt",  L"Text document"},     {L".log",  L"Log file"},
    {L".csv",  L"CSV document"},      {L".json", L"JSON document"},
    {L".xml",  L"XML document"},      {L".html", L"HTML document"},
    {L".htm",  L"HTML document"},     {L".ini",  L"Configuration file"},
    {L".cfg",  L"Configuration file"}, {L".dat",  L"Data file"},
    {L".doc",  L"Word document"},     {L".docx", L"Word document"},
    {L".xls",  L"Excel workbook"},    {L".xlsx", L"Excel workbook"},
    {L".ppt",  L"PowerPoint deck"},   {L".pptx", L"PowerPoint deck"},
    {L".rtf",  L"Rich text document"}, {L".lnk", L"Shell shortcut"},
    {L".db",   L"Database"},          {L".sqlite", L"SQLite database"},
    {L".dll",  L"PE dynamic library"}, {L".sys", L"PE driver"},
    {L".msi",  L"Windows installer"},  {L".reg", L"Registry export"},
    {L".ps1",  L"PowerShell script"},  {L".py",  L"Python script"},
    {L".js",   L"JavaScript file"},    {L".vbs", L"VBScript file"},
    {L".iso",  L"Disc image"},        {L".img", L"Disk image"},
    {L".dd",   L"Disk image"},        {L".vhd", L"Virtual disk"},
    {L".vhdx", L"Virtual disk"},      {L".eml", L"E-mail message"},
    {L".msg",  L"Outlook message"},   {L".pst", L"Outlook data file"},
    {L".zipx", L"ZIP archive"},       {L".tar", L"TAR archive"},
};

void DescribeByName(const std::wstring& name, const std::vector<BYTE>& data, std::wstring& type,
                    std::wstring& ext) {
    ext = ExtensionOf(name);
    for (int i = 0; i < SIG_COUNT; ++i) {
        if (ext == kSigInfo[i].ext) {
            type = kSigInfo[i].type;
            return;
        }
    }
    for (const auto& entry : kExtraTypes) {
        if (ext == entry.ext) {
            type = entry.type;
            return;
        }
    }

    if (!data.empty()) {
        std::vector<BYTE> head(data.begin(),
                               data.begin() + std::min<size_t>(data.size(), 4096));
        const int sig = MatchAt(head, 0);
        if (sig >= 0) {
            type = kSigInfo[sig].type;
            ext = kSigInfo[sig].ext;
            return;
        }
    }
    type = ext.empty() ? L"File" : ToLower(ext.substr(1)) + L" file";
}

}

bool CarvedAddEntry(const std::wstring& name, const std::wstring& type,
                    const std::wstring& source, const std::wstring& state,
                    const std::wstring& created, const std::wstring& modified,
                    uint64_t logicalSize, std::vector<BYTE> data, bool complete) {
    if (name.empty()) return false;

    CarvedFile file;
    file.name = name;
    file.source = source;
    file.state = state;
    file.created = created;
    file.modified = modified;
    file.complete = complete;
    if (type.empty()) {
        DescribeByName(name, data, file.type, file.ext);
    } else {
        file.type = type;
        file.ext = ExtensionOf(name);
    }

    if (data.size() > kMaxFile) {
        data.resize(kMaxFile);
        file.complete = false;
    }

    if (type.empty() && data.size() >= 16) {
        std::vector<BYTE> head(data.begin(),
                               data.begin() + std::min<size_t>(data.size(), 4096));
        const int sig = MatchAt(head, 0);
        int claimedSig = -1;
        for (int i = 0; i < SIG_COUNT; ++i) {
            if (file.ext == kSigInfo[i].ext) { claimedSig = i; break; }
        }
        if (sig >= 0 && claimedSig >= 0 && sig != claimedSig) {
            file.type = kSigInfo[sig].type;
            file.ext = kSigInfo[sig].ext;
            RefineType(sig, data, 0, file.type, file.ext);
        } else if (sig < 0 && claimedSig >= 0 && file.ext != L".bat" && file.ext != L".cmd") {
            return false;
        }
    }

    file.size = data.empty() ? static_cast<size_t>(std::min<uint64_t>(logicalSize, SIZE_MAX))
                             : data.size();

    uint64_t hash = 0;
    if (!data.empty()) {
        hash = HashPrefix(data.data(), std::min<size_t>(data.size(), 256)) ^
               (static_cast<uint64_t>(data.size()) << 1);
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_files.size() >= kMaxFiles) return false;
    if (!data.empty()) {
        if (g_total + data.size() <= kMaxTotal && g_hashes.insert(hash).second) {
            g_total += data.size();
            file.data = std::move(data);
            file.hasData = true;
        } else {
            file.complete = false;
        }
    }
    g_files.push_back(std::move(file));
    return true;
}

bool CarvedHasRoom(size_t size) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_files.size() >= kMaxFiles) return false;
    if (g_total + size > kMaxTotal) return false;
    return true;
}

size_t CarvedMaxFile() {
    return kMaxFile;
}

size_t CarvedMaxFiles() {
    return kMaxFiles;
}

void Carver::Reset() {
    flows_.clear();
    requests_.clear();
}

void Carver::ResetFlow(const std::string& flowKey) {
    flows_.erase(flowKey);
}

void Carver::Append(Flow& flow, uint32_t seq, const BYTE* data, size_t length) {
    if (!flow.haveSeq) { flow.nextSeq = seq; flow.haveSeq = true; }
    if (seq == flow.nextSeq) {
        flow.buffer.insert(flow.buffer.end(), data, data + length);
        flow.nextSeq = seq + static_cast<uint32_t>(length);
    } else if (static_cast<int32_t>(seq - flow.nextSeq) < 0) {
        uint32_t skip = flow.nextSeq - seq;
        if (skip >= length) return;
        flow.buffer.insert(flow.buffer.end(), data + skip, data + length);
        flow.nextSeq = seq + static_cast<uint32_t>(length);
    } else {

        flow.buffer.insert(flow.buffer.end(), data, data + length);
        flow.nextSeq = seq + static_cast<uint32_t>(length);
    }
}

void Carver::Scan(Flow& flow) {
    std::vector<BYTE>& b = flow.buffer;
    if (b.size() < 16) return;

    for (auto it = flow.pending.begin(); it != flow.pending.end();) {
        size_t off = it->first;
        int sig = it->second;
        if (off + 4 > b.size()) { ++it; continue; }
        size_t end = 0;
        bool complete = false;
        if (DetermineEnd(b, off, sig, end, complete) && complete && end > off &&
            end <= b.size() && end - off >= kSigInfo[sig].minSize) {
            AddCarved(b, off, end, sig, flow.source, flow.origin, flow.captured, true);
            flow.carved.insert(off);
            it = flow.pending.erase(it);
        } else {
            ++it;
        }
    }

    for (size_t i = flow.scanFrom; i + 8 <= b.size(); ++i) {
        int sig = MatchAt(b, i);
        if (sig < 0) continue;
        if (flow.carved.count(i) || flow.pending.count(i)) continue;
        size_t end = 0;
        bool complete = false;
        if (DetermineEnd(b, i, sig, end, complete)) {
            if (complete && end > i && end <= b.size() && end - i >= kSigInfo[sig].minSize) {
                AddCarved(b, i, end, sig, flow.source, flow.origin, flow.captured, true);
                flow.carved.insert(i);
            } else {
                flow.pending[i] = sig;
            }
        } else {
            flow.pending[i] = sig;
        }
    }
    flow.scanFrom = b.size() > 64 ? b.size() - 64 : 0;
}

void Carver::FeedTcp(const std::string& flowKey, uint32_t seq, const BYTE* data, size_t length,
                     const std::wstring& source, const std::wstring& destination) {
    if (!data || length == 0) return;
    if (LooksLikeHttpRequest(data, length)) {
        if (requests_.size() >= 256) requests_.clear();
        requests_[WideToUtf8(source)] = HttpRequestText(data, length);
    }
    if (flows_.size() >= kMaxFlows && flows_.find(flowKey) == flows_.end()) {

        flows_.erase(flows_.begin());
    }
    Flow& flow = flows_[flowKey];
    if (flow.source.empty()) {
        flow.source = source + L" \u2192 " + destination;
        flow.captured = NowText();
    }
    if (flow.origin.empty()) {

        auto known = requests_.find(WideToUtf8(destination));
        if (known != requests_.end()) flow.origin = known->second;
    }
    Append(flow, seq, data, length);

    if (flow.buffer.size() > kMaxFlowBuffer) {
        size_t drop = flow.buffer.size() / 2;
        flow.buffer.erase(flow.buffer.begin(), flow.buffer.begin() + drop);
        flow.scanFrom = 0;
        flow.carved.clear();
        flow.pending.clear();
    }
    Scan(flow);
}

void Carver::FeedDatagram(const std::string& , const BYTE* data, size_t length,
                          const std::wstring& source, const std::wstring& destination) {
    if (!data || length < 16) return;
    Flow flow;
    flow.source = source + L" \u2192 " + destination;
    flow.captured = NowText();
    flow.buffer.assign(data, data + length);
    Scan(flow);
}

namespace {

size_t TruncatedEnd(const std::vector<BYTE>& b, size_t off, int sig) {
    const size_t limit = std::min(b.size(), off + kMaxFile);
    for (size_t p = off + kSigInfo[sig].minSize; p + 8 <= limit; ++p) {
        if (MatchAt(b, p) >= 0) return p;
    }
    return limit;
}

bool EmitPending(const std::vector<BYTE>& b, size_t off, int sig, const std::wstring& source,
                 const std::wstring& origin, const std::wstring& captured) {
    size_t end = 0;
    bool complete = false;
    if (!DetermineEnd(b, off, sig, end, complete) || end <= off || end > b.size()) {
        end = TruncatedEnd(b, off, sig);
    }
    if (end <= off || end - off < kSigInfo[sig].minSize) return false;
    AddCarved(b, off, end, sig, source, origin, captured, false);
    return true;
}
}

void Carver::FeedDisk(const std::string& flowKey, uint32_t seq, const BYTE* data, size_t length,
                      const std::wstring& label) {
    if (!data || length == 0) return;
    Flow& flow = flows_[flowKey];
    if (flow.source.empty()) {
        flow.source = label;
        flow.captured = NowText();
    }
    Append(flow, seq, data, length);
    if (flow.buffer.size() > kMaxDiskFlowBuffer) {

        const size_t drop = flow.buffer.size() / 2;
        for (auto it = flow.pending.begin(); it != flow.pending.end();) {
            const size_t off = it->first;
            const int sig = it->second;
            if (EmitPending(flow.buffer, off, sig, flow.source, flow.origin, flow.captured)) {
                flow.carved.insert(off);
            }
            it = flow.pending.erase(it);
        }
        flow.buffer.erase(flow.buffer.begin(), flow.buffer.begin() + drop);
        flow.scanFrom = 0;
        std::set<size_t> carved;
        for (size_t c : flow.carved) {
            if (c >= drop) carved.insert(c - drop);
        }
        flow.carved.swap(carved);
        std::map<size_t, int> pending;
        for (const auto& item : flow.pending) {
            if (item.first >= drop) pending[item.first - drop] = item.second;
        }
        flow.pending.swap(pending);
    }
    Scan(flow);
}

bool WorthPartial(int sig) {
    switch (sig) {
    case SIG_GZIP:
    case SIG_MP3:
    case SIG_BATCH:
        return false;
    default:
        return true;
    }
}

void Carver::Finalize() {
    for (auto& entry : flows_) {
        Flow& flow = entry.second;
        std::vector<BYTE>& b = flow.buffer;
        if (b.size() < 16) continue;
        for (size_t i = 0; i + 8 <= b.size(); ++i) {
            const int sig = MatchAt(b, i);
            if (sig < 0 || flow.carved.count(i) || !WorthPartial(sig)) continue;
            if (EmitPending(b, i, sig, flow.source, flow.origin, flow.captured)) {
                flow.carved.insert(i);
            }
        }
    }
}

namespace {

bool FeedHandle(HANDLE handle, const std::wstring& label, const std::string& key,
                Carver& carver, const Sink& sink, std::atomic<bool>& stop,
                uint64_t limitBytes, uint64_t& total) {
    std::vector<BYTE> chunk(8ull << 20);
    uint32_t seq = 1;
    auto last = std::chrono::steady_clock::now();
    while (!stop.load()) {
        DWORD got = 0;
        if (!ReadFile(handle, chunk.data(), static_cast<DWORD>(chunk.size()), &got, nullptr) ||
            got == 0) {
            return true;
        }
        carver.FeedDisk(key, seq, chunk.data(), got, label);
        seq += got;
        total += got;
        if (limitBytes && total >= limitBytes) return true;
        const auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() >= 400) {
            sink.Status(Format(L"Scanning %s \u00B7 %s read \u00B7 %s recovered",
                               label.c_str(), SizeText(total).c_str(),
                               CommaNumber(CarvedCount()).c_str()), -1);
            last = now;
        }
    }
    return false;
}

}

std::vector<Row> CarvedRows() {
    const std::vector<CarvedFile> files = CarvedSnapshot();
    std::vector<Row> rows;
    rows.reserve(files.size());
    for (const CarvedFile& file : files) {
        Row row;
        row.push_back(file.name);
        row.push_back(file.type);
        row.push_back(file.type == L"Folder" ? std::wstring(L"\u2014") : SizeText(file.size));
        row.push_back(file.source);
        std::wstring state = !file.state.empty()
                                 ? file.state
                                 : (file.complete ? L"complete" : L"partial");
        if (!file.hasData && file.type != L"Folder") state += L" \u00B7 metadata only";
        row.push_back(std::move(state));
        row.push_back(file.modified);
        row.push_back(file.created);
        rows.push_back(std::move(row));
    }
    return rows;
}

std::vector<std::wstring> CarvedDetails() {
    const std::vector<CarvedFile> files = CarvedSnapshot();
    std::vector<std::wstring> details;
    details.reserve(files.size());
    for (const CarvedFile& file : files) {
        std::wstring text;
        text += L"Name        : " + file.name + L"\r\n";
        text += L"Type        : " + file.type + L"\r\n";
        if (!file.ext.empty()) text += L"Extension   : " + file.ext + L"\r\n";
        text += L"Size        : " +
                (file.type == L"Folder" ? std::wstring(L"-") : SizeText(file.size)) + L"\r\n";
        text += L"Source      : " + file.source + L"\r\n";
        if (!file.origin.empty()) text += L"Origin      : " + file.origin + L"\r\n";
        if (!file.captured.empty()) text += L"Captured    : " + file.captured + L"\r\n";
        std::wstring state = !file.state.empty()
                                 ? file.state
                                 : (file.complete ? L"complete" : L"partial");
        text += L"State       : " + state + L"\r\n";
        text += L"Data stored : " +
                std::wstring(file.hasData ? L"yes" : L"no (metadata only)") + L"\r\n";
        if (!file.created.empty()) text += L"Created     : " + file.created + L"\r\n";
        if (!file.modified.empty()) text += L"Modified    : " + file.modified + L"\r\n";
        if (!file.data.empty()) {
            std::wstring hex;
            size_t shown = file.data.size() < 160 ? file.data.size() : 160;
            for (size_t i = 0; i < shown; ++i) {
                if (i) hex += L' ';
                hex += Format(L"%02X", file.data[i]);
            }
            if (file.data.size() > shown) hex += L" \u2026";
            text += L"\r\n--- first bytes ---\r\n" + hex + L"\r\n";
        }
        details.push_back(std::move(text));
    }
    return details;
}

size_t CarveIntoStore(const Sink& sink, std::atomic<bool>& stop, const CarveConfig& config,
                      uint64_t& total, bool& stopped) {
    Carver carver;
    total = 0;
    stopped = false;

    for (const CarveSource& src : config.sources) {
        if (stop.load()) { stopped = true; break; }
        HANDLE handle = CreateFileW(src.path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            sink.Status(Format(L"Cannot open %s (error %lu). Run as Administrator for raw volumes.",
                               src.label.c_str(), GetLastError()), -1);
            continue;
        }
        const std::string key = "disk:" + WideToUtf8(src.label);
        const bool more = FeedHandle(handle, src.label, key, carver, sink, stop,
                                     config.limitBytes, total);
        CloseHandle(handle);
        if (!more) { stopped = true; break; }
        if (config.limitBytes && total >= config.limitBytes) break;
    }
    carver.Finalize();
    return CarvedCount();
}

void RunDiskCarve(const Sink& sink, std::atomic<bool>& stop, CarveConfig config) {
    CarvedClear();
    uint64_t total = 0;
    bool stopped = false;
    CarveIntoStore(sink, stop, config, total, stopped);

    std::vector<Row> rows = CarvedRows();
    const std::wstring where = config.sources.size() == 1 ? config.sources.front().label
                                                          : L"multiple sources";
    std::wstring summary = Format(L"%s file(s) recovered from %s \u00B7 %s scanned%s",
                                  CommaNumber(rows.size()).c_str(), where.c_str(),
                                  SizeText(total).c_str(), stopped ? L" \u00B7 stopped" : L"");
    if (rows.empty()) summary += L" \u00B7 check the volume selection";
    sink.Detailed(std::move(rows), CarvedDetails(), true, summary, 100);
    sink.Done(summary);
}
