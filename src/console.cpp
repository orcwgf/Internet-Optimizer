#include "console.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <vector>

#include "screen.h"

namespace {

std::atomic<bool> g_interrupted{false};

BOOL WINAPI ctrlHandler(DWORD type) {
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
      type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT ||
      type == CTRL_SHUTDOWN_EVENT) {
    g_interrupted.store(true);
    return TRUE;
  }
  return FALSE;
}

}  // namespace

Console::~Console() { shutdown(); }

bool Console::init() {
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  if (out == INVALID_HANDLE_VALUE || in == INVALID_HANDLE_VALUE) return false;

  DWORD outMode = 0;
  DWORD inMode = 0;
  if (!GetConsoleMode(out, &outMode) || !GetConsoleMode(in, &inMode)) {
    return false;
  }

  out_ = out;
  in_ = in;
  outMode_ = outMode;
  inMode_ = inMode;

  DWORD newOut = outMode | ENABLE_PROCESSED_OUTPUT |
                 ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  SetConsoleMode(out, newOut);

  DWORD newIn = inMode | ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT;
  newIn &= ~(ENABLE_QUICK_EDIT_MODE | ENABLE_MOUSE_INPUT |
             ENABLE_PROCESSED_INPUT);
  SetConsoleMode(in, newIn);

  SetConsoleCtrlHandler(ctrlHandler, TRUE);
  g_interrupted.store(false);

  writeRaw(L"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
  active_ = true;
  return true;
}

void Console::shutdown() {
  if (!active_) return;
  writeRaw(L"\x1b[0m\x1b[?25h\x1b[?1049l");
  if (out_) SetConsoleMode(static_cast<HANDLE>(out_), outMode_);
  if (in_) SetConsoleMode(static_cast<HANDLE>(in_), inMode_);
  SetConsoleCtrlHandler(ctrlHandler, FALSE);
  active_ = false;
}

int Console::width() const {
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (out_ && GetConsoleScreenBufferInfo(static_cast<HANDLE>(out_), &info)) {
    return std::max(20, static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1));
  }
  return 80;
}

int Console::height() const {
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (out_ && GetConsoleScreenBufferInfo(static_cast<HANDLE>(out_), &info)) {
    return std::max(10, static_cast<int>(info.srWindow.Bottom - info.srWindow.Top + 1));
  }
  return 24;
}

void Console::writeConsole(const std::wstring& text) {
  if (!out_) {
    return;
  }
  HANDLE h = static_cast<HANDLE>(out_);
  size_t offset = 0;
  while (offset < text.size()) {
    DWORD chunk = static_cast<DWORD>(
        std::min<size_t>(text.size() - offset, 8192));
    DWORD written = 0;
    if (!WriteConsoleW(h, text.data() + offset, chunk, &written, nullptr)) {
      // Fall back to UTF-8 stdout when the console handle is redirected.
      return;
    }
    if (written == 0) return;
    offset += written;
  }
}

void Console::writeRaw(const std::wstring& text) { writeConsole(text); }

void Console::draw(const Screen& screen) {
  std::wstring frame = L"\x1b[H";
  frame += screen.render();
  writeConsole(frame);
}

InputEvent Console::poll(int timeoutMs) {
  if (!pending_.empty()) {
    InputEvent event = pending_.front();
    pending_.pop_front();
    return event;
  }

  InputEvent empty;
  if (!in_ || g_interrupted.load()) return empty;

  HANDLE h = static_cast<HANDLE>(in_);
  DWORD wait = WaitForSingleObject(h, static_cast<DWORD>(std::max(0, timeoutMs)));
  if (wait != WAIT_OBJECT_0) return empty;

  INPUT_RECORD records[32];
  DWORD count = 0;
  if (!ReadConsoleInputW(h, records, 32, &count)) return empty;

  auto push = [&](InputEvent event) {
    if (event.key != Key::None) pending_.push_back(event);
  };

  for (DWORD i = 0; i < count; ++i) {
    const INPUT_RECORD& r = records[i];
    if (r.EventType == WINDOW_BUFFER_SIZE_EVENT) {
      InputEvent event;
      event.key = Key::Resize;
      push(event);
      continue;
    }
    if (r.EventType != KEY_EVENT) continue;
    const KEY_EVENT_RECORD& k = r.Event.KeyEvent;
    if (!k.bKeyDown) continue;

    InputEvent event;
    switch (k.wVirtualKeyCode) {
      case VK_UP:
        event.key = Key::Up;
        break;
      case VK_DOWN:
        event.key = Key::Down;
        break;
      case VK_LEFT:
        event.key = Key::Left;
        break;
      case VK_RIGHT:
        event.key = Key::Right;
        break;
      case VK_HOME:
        event.key = Key::Home;
        break;
      case VK_END:
        event.key = Key::End;
        break;
      case VK_PRIOR:
        event.key = Key::PageUp;
        break;
      case VK_NEXT:
        event.key = Key::PageDown;
        break;
      case VK_ESCAPE:
        event.key = Key::Escape;
        break;
      case VK_RETURN:
        event.key = Key::Enter;
        break;
      case VK_BACK:
        event.key = Key::Backspace;
        break;
      case VK_DELETE:
        event.key = Key::Delete;
        break;
      case VK_TAB:
        event.key = Key::Tab;
        break;
      case VK_F5:
        event.key = Key::F5;
        break;
      default:
        if (k.uChar.UnicodeChar != 0) {
          event.key = Key::Char;
          event.ch = k.uChar.UnicodeChar;
        }
        break;
    }
    push(event);
  }

  if (!pending_.empty()) {
    InputEvent event = pending_.front();
    pending_.pop_front();
    return event;
  }
  return empty;
}

bool Console::interrupted() const { return g_interrupted.load(); }
