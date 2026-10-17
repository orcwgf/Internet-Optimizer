#pragma once

#include <deque>
#include <string>

class Screen;

enum class Key {
  None,
  Char,
  Up,
  Down,
  Left,
  Right,
  Home,
  End,
  PageUp,
  PageDown,
  Escape,
  Enter,
  Backspace,
  Delete,
  Tab,
  F5,
  Resize,
};

struct InputEvent {
  Key key = Key::None;
  wchar_t ch = 0;
};

// Owns the console mode, alternate screen buffer and raw keyboard input.
class Console {
 public:
  Console() = default;
  ~Console();
  Console(const Console&) = delete;
  Console& operator=(const Console&) = delete;

  bool init();
  void shutdown();

  int width() const;
  int height() const;

  void draw(const Screen& screen);
  InputEvent poll(int timeoutMs);

  bool interrupted() const;

 private:
  void writeRaw(const std::wstring& text);
  void writeConsole(const std::wstring& text);

  std::deque<InputEvent> pending_;
  void* out_ = nullptr;
  void* in_ = nullptr;
  unsigned long outMode_ = 0;
  unsigned long inMode_ = 0;
  bool active_ = false;
};
