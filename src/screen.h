#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

struct Style {
  int fg = -1;  // 256-color index, -1 = terminal default
  int bg = -1;
  bool bold = false;
  bool dim = false;

  bool operator==(const Style& o) const {
    return fg == o.fg && bg == o.bg && bold == o.bold && dim == o.dim;
  }
  bool operator!=(const Style& o) const { return !(*this == o); }
};

// A fixed-size cell grid. Handles wide characters and East Asian widths so
// columns stay aligned, then serializes to VT escape sequences in one frame.
class Screen {
 public:
  Screen(int width, int height);

  int width() const { return w_; }
  int height() const { return h_; }

  void clear(Style style = {});
  void put(int x, int y, std::wstring_view text, Style style = {});
  void putRight(int x, int y, int width, std::wstring_view text,
                Style style = {});
  void fill(int x, int y, int width, int height, wchar_t ch, Style style = {});
  void box(int x, int y, int width, int height, Style border,
           std::wstring_view title = {}, Style titleStyle = {});
  void dimAll();
  void hline(int x, int y, int width, wchar_t left, wchar_t mid, wchar_t right,
             Style style, int midAt = -1);

  std::wstring render() const;  // full frame with cursor positioning + colors
  std::wstring plain() const;   // newline-separated text, for tests/debug

 private:
  struct Cell {
    wchar_t a = L' ';
    wchar_t b = 0;  // low surrogate for astral characters
    int16_t fg = -1;
    int16_t bg = -1;
    uint8_t flags = 0;  // 1=bold, 2=dim, 4=continuation cell
  };

  Cell& at(int x, int y) { return cells_[static_cast<size_t>(y) * w_ + x]; }
  const Cell& at(int x, int y) const {
    return cells_[static_cast<size_t>(y) * w_ + x];
  }
  void applyStyle(Cell& cell, Style style);

  int w_;
  int h_;
  std::vector<Cell> cells_;
};

namespace sty {
// 256-color palette choices that read well on dark and light terminals.
inline const Style text{252, -1, false, false};
inline const Style dim{244, -1, false, false};
inline const Style accent{81, -1, true, false};
inline const Style green{114, -1, false, false};
inline const Style yellow{221, -1, false, false};
inline const Style red{210, -1, true, false};
inline const Style titleText{231, 24, true, false};
inline const Style titleSub{117, 24, false, false};
inline const Style border{240, -1, false, false};
inline const Style borderFocus{81, -1, false, false};
inline const Style header{250, 236, true, false};
inline const Style selected{255, 238, true, false};
inline const Style marked{226, -1, true, false};
inline const Style barEmpty{239, 236, false, false};
inline const Style modalBg{252, 235, false, false};
inline const Style modalBorder{81, -1, false, false};
inline const Style modalTitle{231, 24, true, false};
inline const Style ok{114, -1, false, false};
inline const Style warn{221, -1, false, false};
inline const Style error{210, -1, true, false};
}  // namespace sty
