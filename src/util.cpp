#include "util.h"

#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <ctime>

namespace {

bool isCombining(uint32_t cp) {
  return (cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
         (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) ||
         (cp >= 0xFE20 && cp <= 0xFE2F) || cp == 0x200B || cp == 0xFEFF;
}

// Decode one UTF-16 unit (handling surrogate pairs) starting at `i`.
uint32_t nextCodepoint(std::wstring_view s, size_t& i) {
  wchar_t c = s[i++];
  if (c >= 0xD800 && c <= 0xDBFF && i < s.size()) {
    wchar_t lo = s[i];
    if (lo >= 0xDC00 && lo <= 0xDFFF) {
      ++i;
      return 0x10000u + ((static_cast<uint32_t>(c) - 0xD800u) << 10) +
             (static_cast<uint32_t>(lo) - 0xDC00u);
    }
  }
  return static_cast<uint32_t>(c);
}

}  // namespace

std::wstring widen(std::string_view s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                              nullptr, 0);
  if (n <= 0) return {};
  std::wstring out(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                      out.data(), n);
  return out;
}

std::string narrow(std::wstring_view s) {
  if (s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                              nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                      out.data(), n, nullptr, nullptr);
  return out;
}

std::wstring toLower(std::wstring_view s) {
  std::wstring out(s);
  for (wchar_t& c : out) c = static_cast<wchar_t>(std::towlower(c));
  return out;
}

std::string trim(std::string_view s) {
  size_t b = 0;
  while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' ||
                          s[b] == '\n'))
    ++b;
  size_t e = s.size();
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' ||
                   s[e - 1] == '\n'))
    --e;
  return std::string(s.substr(b, e - b));
}

std::wstring trimW(std::wstring_view s) {
  size_t b = 0;
  while (b < s.size() && (s[b] == L' ' || s[b] == L'\t' || s[b] == L'\r' ||
                          s[b] == L'\n'))
    ++b;
  size_t e = s.size();
  while (e > b && (s[e - 1] == L' ' || s[e - 1] == L'\t' || s[e - 1] == L'\r' ||
                   s[e - 1] == L'\n'))
    --e;
  return std::wstring(s.substr(b, e - b));
}

bool containsCI(std::wstring_view haystack, std::wstring_view needle) {
  if (needle.empty()) return true;
  if (haystack.size() < needle.size()) return false;
  std::wstring h = toLower(haystack);
  std::wstring n = toLower(needle);
  return h.find(n) != std::wstring::npos;
}

int codepointWidth(uint32_t cp) {
  if (cp == 0) return 0;
  if (cp < 32 || (cp >= 0x7F && cp < 0xA0)) return 0;
  if (isCombining(cp)) return 0;
  // East Asian wide / full-width ranges, plus emoji.
  if (cp >= 0x1100 &&
      (cp <= 0x115F || cp == 0x2329 || cp == 0x232A ||
       (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
       (cp >= 0xAC00 && cp <= 0xD7A3) ||
       (cp >= 0xF900 && cp <= 0xFAFF) ||
       (cp >= 0xFE10 && cp <= 0xFE19) ||
       (cp >= 0xFE30 && cp <= 0xFE6F) ||
       (cp >= 0xFF00 && cp <= 0xFF60) ||
       (cp >= 0xFFE0 && cp <= 0xFFE6) ||
       (cp >= 0x1F300 && cp <= 0x1FAFF) ||
       (cp >= 0x20000 && cp <= 0x3FFFD))) {
    return 2;
  }
  return 1;
}

int textWidth(std::wstring_view s) {
  int width = 0;
  size_t i = 0;
  while (i < s.size()) width += codepointWidth(nextCodepoint(s, i));
  return width;
}

std::wstring truncateToWidth(std::wstring_view s, int maxWidth, bool ellipsis) {
  if (maxWidth <= 0) return {};
  if (textWidth(s) <= maxWidth) return std::wstring(s);
  const int ellipsisWidth = ellipsis ? 1 : 0;
  if (maxWidth <= ellipsisWidth) return ellipsis ? L"\u2026" : L"";

  std::wstring out;
  int width = 0;
  size_t i = 0;
  const int limit = maxWidth - ellipsisWidth;
  while (i < s.size()) {
    size_t start = i;
    uint32_t cp = nextCodepoint(s, i);
    int w = codepointWidth(cp);
    if (w == 0) continue;
    if (width + w > limit) break;
    out.append(s.substr(start, i - start));
    width += w;
  }
  if (ellipsis) out += L"\u2026";
  return out;
}

std::wstring padRight(std::wstring_view s, int width) {
  std::wstring out(s);
  int w = textWidth(out);
  if (w < width) out.append(static_cast<size_t>(width - w), L' ');
  return out;
}

std::vector<std::wstring> wrapTextLines(std::wstring_view text, int width) {
  width = std::max(4, width);
  std::vector<std::wstring> lines;
  std::wstring line;

  auto flush = [&]() {
    if (!line.empty()) {
      lines.push_back(line);
      line.clear();
    }
  };

  size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && text[i] == L' ') ++i;
    if (i >= text.size()) break;

    const size_t start = i;
    while (i < text.size() && text[i] != L' ') ++i;
    std::wstring word(text.substr(start, i - start));

    while (textWidth(word) > width) {
      std::wstring part = truncateToWidth(word, width, false);
      if (part.empty()) break;
      flush();
      lines.push_back(part);
      word = word.substr(part.size());
    }
    if (word.empty()) continue;

    if (line.empty()) {
      line = word;
    } else if (textWidth(line) + 1 + textWidth(word) <= width) {
      line += L' ';
      line += word;
    } else {
      flush();
      line = word;
    }
  }
  flush();
  if (lines.empty()) lines.push_back(L"");
  return lines;
}

std::string formatBytes(uint64_t bytes) {
  char buf[64];
  if (bytes < 1000ULL) {
    std::snprintf(buf, sizeof(buf), "%llu B",
                  static_cast<unsigned long long>(bytes));
  } else if (bytes < 1000ULL * 1000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1000.0);
  } else if (bytes < 1000ULL * 1000ULL * 1000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1f MB", bytes / 1e6);
  } else {
    std::snprintf(buf, sizeof(buf), "%.2f GB", bytes / 1e9);
  }
  return buf;
}

std::wstring formatBytesW(uint64_t bytes) { return widen(formatBytes(bytes)); }

std::string formatRate(double bytesPerSecond) {
  if (bytesPerSecond < 0.0 || bytesPerSecond < 1.0) return "0 B/s";
  char buf[64];
  if (bytesPerSecond < 1000.0) {
    std::snprintf(buf, sizeof(buf), "%.0f B/s", bytesPerSecond);
  } else if (bytesPerSecond < 1e6) {
    std::snprintf(buf, sizeof(buf), "%.1f KB/s", bytesPerSecond / 1e3);
  } else if (bytesPerSecond < 1e9) {
    std::snprintf(buf, sizeof(buf), "%.2f MB/s", bytesPerSecond / 1e6);
  } else {
    std::snprintf(buf, sizeof(buf), "%.2f GB/s", bytesPerSecond / 1e9);
  }
  return buf;
}

std::wstring formatRateW(double bytesPerSecond) {
  return widen(formatRate(bytesPerSecond));
}

std::string formatLocalTime(int64_t unixSeconds) {
  time_t t = static_cast<time_t>(unixSeconds);
  tm local{};
  localtime_s(&local, &t);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
  return buf;
}

int64_t nowUnix() {
  return static_cast<int64_t>(std::time(nullptr));
}
