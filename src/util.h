#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// ---- text ---------------------------------------------------------------
std::wstring widen(std::string_view s);
std::string narrow(std::wstring_view s);
std::wstring toLower(std::wstring_view s);
std::string trim(std::string_view s);
std::wstring trimW(std::wstring_view s);
bool containsCI(std::wstring_view haystack, std::wstring_view needle);

// Console cell width of one Unicode code point (0, 1 or 2).
int codepointWidth(uint32_t cp);
int textWidth(std::wstring_view s);
std::wstring truncateToWidth(std::wstring_view s, int maxWidth, bool ellipsis = true);
std::wstring padRight(std::wstring_view s, int width);
std::vector<std::wstring> wrapTextLines(std::wstring_view text, int width);

// ---- numbers ------------------------------------------------------------
std::string formatBytes(uint64_t bytes);
std::wstring formatBytesW(uint64_t bytes);
std::string formatRate(double bytesPerSecond);
std::wstring formatRateW(double bytesPerSecond);
std::string formatLocalTime(int64_t unixSeconds);

int64_t nowUnix();
