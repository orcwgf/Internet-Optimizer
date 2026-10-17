#include "screen.h"

#include <algorithm>
#include <cwchar>

#include "util.h"

namespace {

// Returns the code point and the number of UTF-16 units consumed.
uint32_t decode(const std::wstring_view s, size_t& i) {
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

void appendStyle(std::wstring& out, const Style& style) {
  out += L"\x1b[0m";
  bool any = false;
  if (style.bold) {
    out += L"\x1b[1m";
    any = true;
  }
  if (style.dim) {
    out += L"\x1b[2m";
    any = true;
  }
  if (style.fg >= 0) {
    out += L"\x1b[38;5;";
    out += std::to_wstring(style.fg);
    out += L"m";
    any = true;
  }
  if (style.bg >= 0) {
    out += L"\x1b[48;5;";
    out += std::to_wstring(style.bg);
    out += L"m";
    any = true;
  }
  (void)any;
}

}  // namespace

Screen::Screen(int width, int height)
    : w_(std::max(1, width)), h_(std::max(1, height)),
      cells_(static_cast<size_t>(w_) * h_) {}

void Screen::applyStyle(Cell& cell, Style style) {
  cell.fg = static_cast<int16_t>(style.fg);
  cell.bg = static_cast<int16_t>(style.bg);
  cell.flags = static_cast<uint8_t>((style.bold ? 1 : 0) | (style.dim ? 2 : 0) |
                                    (cell.flags & 4));
}

void Screen::clear(Style style) {
  for (int y = 0; y < h_; ++y) {
    for (int x = 0; x < w_; ++x) {
      Cell& c = at(x, y);
      c.a = L' ';
      c.b = 0;
      c.flags = 0;
      applyStyle(c, style);
    }
  }
}

void Screen::put(int x, int y, std::wstring_view text, Style style) {
  if (y < 0 || y >= h_) return;
  int cx = x;
  size_t i = 0;
  while (i < text.size()) {
    const uint32_t cp = decode(text, i);
    if (cp == L'\n' || cp == L'\r') break;
    const int w = codepointWidth(cp);
    if (w == 0) continue;
    if (cx >= 0 && cx < w_ && cx + w <= w_) {
      // If we are overwriting half of an existing wide character, blank the
      // rest of that character so columns stay aligned.
      if (at(cx, y).flags & 4) {
        if (cx > 0) {
          Cell& lead = at(cx - 1, y);
          lead.a = L' ';
          lead.b = 0;
          lead.flags = static_cast<uint8_t>(lead.flags & 3);
        }
      }
      if (cx + 1 < w_ && (at(cx + 1, y).flags & 4)) {
        Cell& cont = at(cx + 1, y);
        cont.a = L' ';
        cont.b = 0;
        cont.flags = 0;
        cont.fg = -1;
        cont.bg = -1;
      }
      Cell& cell = at(cx, y);
      cell.a = static_cast<wchar_t>(cp);
      cell.b = 0;
      if (cp > 0xFFFF) {
        cell.a = static_cast<wchar_t>(0xD800 + ((cp - 0x10000) >> 10));
        cell.b = static_cast<wchar_t>(0xDC00 + ((cp - 0x10000) & 0x3FF));
      }
      cell.flags = static_cast<uint8_t>(cell.flags & ~4);
      applyStyle(cell, style);
      if (w == 2) {
        Cell& cont = at(cx + 1, y);
        cont.a = L' ';
        cont.b = 0;
        cont.flags = static_cast<uint8_t>((cell.flags & 3) | 4);
        cont.fg = cell.fg;
        cont.bg = cell.bg;
      }
    }
    cx += w;
  }
}

void Screen::putRight(int x, int y, int width, std::wstring_view text,
                      Style style) {
  std::wstring t = truncateToWidth(text, width, false);
  int used = textWidth(t);
  put(x + std::max(0, width - used), y, t, style);
}

void Screen::fill(int x, int y, int width, int height, wchar_t ch,
                  Style style) {
  const int x0 = std::max(0, x);
  const int y0 = std::max(0, y);
  const int x1 = std::min(w_, x + width);
  const int y1 = std::min(h_, y + height);
  for (int yy = y0; yy < y1; ++yy) {
    for (int xx = x0; xx < x1; ++xx) {
      Cell& c = at(xx, yy);
      c.a = ch;
      c.b = 0;
      c.flags = 0;
      applyStyle(c, style);
    }
  }
}

void Screen::box(int x, int y, int width, int height, Style border,
                 std::wstring_view title, Style titleStyle) {
  if (width < 2 || height < 2) return;
  const int x1 = x + width - 1;
  const int y1 = y + height - 1;

  put(x, y, L"\u250C", border);
  put(x1, y, L"\u2510", border);
  put(x, y1, L"\u2514", border);
  put(x1, y1, L"\u2518", border);
  for (int i = x + 1; i < x1; ++i) {
    put(i, y, L"\u2500", border);
    put(i, y1, L"\u2500", border);
  }
  for (int j = y + 1; j < y1; ++j) {
    put(x, j, L"\u2502", border);
    put(x1, j, L"\u2502", border);
  }

  if (!title.empty()) {
    std::wstring t = L" " + std::wstring(title) + L" ";
    t = truncateToWidth(t, std::max(1, width - 4));
    put(x + 2, y, t, titleStyle);
  }
}

void Screen::dimAll() {
  for (Cell& cell : cells_) cell.flags = static_cast<uint8_t>(cell.flags | 2);
}

void Screen::hline(int x, int y, int width, wchar_t left, wchar_t mid,
                   wchar_t right, Style style, int midAt) {
  if (width <= 0 || y < 0 || y >= h_) return;
  put(x, y, std::wstring(1, left), style);
  for (int i = 1; i < width - 1; ++i) {
    put(x + i, y, std::wstring(1, i == midAt ? mid : L'\u2500'), style);
  }
  if (width > 1) put(x + width - 1, y, std::wstring(1, right), style);
}

std::wstring Screen::render() const {
  std::wstring out;
  out.reserve(static_cast<size_t>(w_) * h_ * 2 + 4096);

  for (int y = 0; y < h_; ++y) {
    out += L"\x1b[" + std::to_wstring(y + 1) + L";1H";
    Style current;
    bool haveStyle = false;
    for (int x = 0; x < w_; ++x) {
      const Cell& c = at(x, y);
      if (c.flags & 4) continue;
      Style s;
      s.fg = c.fg;
      s.bg = c.bg;
      s.bold = (c.flags & 1) != 0;
      s.dim = (c.flags & 2) != 0;
      if (!haveStyle || s != current) {
        appendStyle(out, s);
        current = s;
        haveStyle = true;
      }
      out += c.a;
      if (c.b) out += c.b;
    }
    appendStyle(out, Style{});
  }
  out += L"\x1b[0m";
  return out;
}

std::wstring Screen::plain() const {
  std::wstring out;
  out.reserve(static_cast<size_t>(w_) * h_);
  for (int y = 0; y < h_; ++y) {
    for (int x = 0; x < w_; ++x) {
      const Cell& c = at(x, y);
      if (c.flags & 4) continue;
      out += c.a;
      if (c.b) out += c.b;
    }
    if (y + 1 < h_) out += L'\n';
  }
  return out;
}
