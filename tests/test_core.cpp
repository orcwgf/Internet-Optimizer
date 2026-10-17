#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "config.h"
#include "filter.h"
#include "risk.h"
#include "screen.h"
#include "util.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void checkImpl(bool condition, const char* expression, int line) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::printf("FAIL line %d: %s\n", line, expression);
  }
}

#define CHECK(expr) checkImpl((expr), #expr, __LINE__)

void testFormatting() {
  CHECK(formatBytes(999) == "999 B");
  CHECK(formatBytes(10'000'000'000ULL) == "10.00 GB");
  CHECK(formatBytes(1'500'000ULL) == "1.5 MB");
  CHECK(formatRate(600'000.0) == "600.0 KB/s");
  CHECK(formatRate(1'500.0) == "1.5 KB/s");
  CHECK(formatRate(0.0) == "0 B/s");
  CHECK(formatRate(-5.0) == "0 B/s");
  CHECK(formatRate(2'500'000.0) == "2.50 MB/s");

  CHECK(textWidth(L"abc") == 3);
  CHECK(textWidth(L"\u3042") == 2);          // hiragana A
  CHECK(textWidth(L"a\u3042b") == 4);
  CHECK(textWidth(truncateToWidth(L"\u3042\u3044\u3046", 4)) <= 4);
  CHECK(padRight(L"ab", 4) == L"ab  ");
  CHECK(containsCI(L"OneDrive.exe", L"onedrive"));

  // Wrapping must consume runs of spaces without looping forever.
  auto spaced = wrapTextLines(L"a   b", 10);
  CHECK(spaced.size() == 1 && spaced[0] == L"a b");
  auto leading = wrapTextLines(L"   alpha beta", 20);
  CHECK(!leading.empty() && leading[0] == L"alpha beta");
  auto wrapped = wrapTextLines(
      L"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe extra words here", 14);
  CHECK(wrapped.size() > 2);
  for (const auto& line : wrapped) CHECK(textWidth(line) <= 14);
}

void testRisk() {
  ProcessInfo svchost;
  svchost.pid = 1234;
  svchost.name = L"svchost.exe";
  svchost.sessionId = 1;
  svchost.microsoft = true;
  assessRisk(svchost, 99);
  CHECK(svchost.risk == Risk::Critical);
  CHECK(!svchost.riskReason.empty());

  ProcessInfo sessionZero;
  sessionZero.pid = 4321;
  sessionZero.name = L"SomeAgent.exe";
  sessionZero.sessionId = 0;
  assessRisk(sessionZero, 99);
  CHECK(sessionZero.risk == Risk::Important);

  ProcessInfo normal;
  normal.pid = 5555;
  normal.name = L"notepad.exe";
  normal.sessionId = 2;
  normal.path = L"C:\\Tools\\notepad.exe";
  assessRisk(normal, 99);
  CHECK(normal.risk == Risk::Normal);
  CHECK(normal.riskReason.empty());

  ProcessInfo oneDrive;
  oneDrive.pid = 7777;
  oneDrive.name = L"OneDrive.exe";
  oneDrive.sessionId = 1;
  oneDrive.microsoft = true;
  assessRisk(oneDrive, 99);
  CHECK(oneDrive.risk == Risk::Important);

  ProcessInfo self = normal;
  self.pid = 99;
  assessRisk(self, 99);
  CHECK(self.risk == Risk::Critical);

  CHECK(!dataHeavyHint(L"OneDrive.exe").empty());
  CHECK(dataHeavyHint(L"notepad.exe").empty());
}

void testFilters() {
  std::vector<ProcessInfo> procs;
  {
    ProcessInfo p;
    p.pid = 1;
    p.name = L"OneDrive.exe";
    p.activeTcp = 3;
    p.sessionId = 1;
    p.downBps = 120'000.0;
    procs.push_back(p);
  }
  {
    ProcessInfo p;
    p.pid = 2;
    p.name = L"svchost.exe";
    p.activeTcp = 1;
    p.sessionId = 0;
    p.systemUser = true;
    p.risk = Risk::Critical;
    procs.push_back(p);
  }
  {
    ProcessInfo p;
    p.pid = 3;
    p.name = L"Spooler.exe";
    p.listenTcp = 2;
    p.sessionId = 0;
    procs.push_back(p);
  }
  {
    ProcessInfo p;
    p.pid = 4;
    p.name = L"Spotify.exe";
    p.activeTcp = 1;
    p.udpCount = 2;
    p.sessionId = 1;
    p.upBps = 5'000.0;
    procs.push_back(p);
  }

  auto visible = buildVisible(procs, false, true, L"", SortMode::Traffic);
  CHECK(visible.size() == 3);            // listener-only hidden
  CHECK(visible[0] == 0);                // 120 KB/s download
  CHECK(visible[1] == 3);                // 5 KB/s upload
  CHECK(visible[2] == 1);                // idle but has a socket

  auto hiddenSystem = buildVisible(procs, true, true, L"", SortMode::Traffic);
  CHECK(hiddenSystem.size() == 2);
  for (size_t i : hiddenSystem) CHECK(procs[i].sessionId != 0);

  auto search = buildVisible(procs, false, true, L"one", SortMode::Traffic);
  CHECK(search.size() == 1 && search[0] == 0);

  auto showListeners = buildVisible(procs, false, false, L"", SortMode::Name);
  CHECK(showListeners.size() == 4);
  CHECK(procs[showListeners[0]].name == L"OneDrive.exe");

  CHECK(std::wstring(sortName(SortMode::Traffic)) == L"speed");
  CHECK(nextSort(SortMode::Traffic) == SortMode::Name);
}

void testConfig() {
  Config saved;
  saved.hideSystem = true;
  saved.hideListenOnly = false;
  saved.sortMode = 3;

  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / L"netpilot_test_config.ini";
  std::filesystem::remove(path);

  CHECK(saveConfig(path.wstring(), saved));
  Config loaded;
  CHECK(loadConfig(path.wstring(), loaded));
  CHECK(loaded.fileExisted);
  CHECK(loaded.hideSystem == saved.hideSystem);
  CHECK(loaded.hideListenOnly == saved.hideListenOnly);
  CHECK(loaded.sortMode == saved.sortMode);

  // A missing file is not an error, just "no preferences yet".
  Config missing;
  CHECK(!loadConfig((path.wstring() + L".missing").c_str(), missing));
  CHECK(!missing.fileExisted);
  std::filesystem::remove(path);
}

void testScreen() {
  Screen screen(30, 8);
  screen.clear();
  screen.box(0, 0, 30, 8, sty::border, L"Test");
  screen.put(2, 2, L"hello", sty::text);
  screen.put(2, 3, L"\u3042wide", sty::accent);

  const std::wstring plain = screen.plain();
  CHECK(plain.find(L"Test") != std::wstring::npos);
  CHECK(plain.find(L"hello") != std::wstring::npos);
  CHECK(plain.find(L"\u3042wide") != std::wstring::npos);
  CHECK(plain.find(L'\u250C') != std::wstring::npos);

  const std::wstring rendered = screen.render();
  CHECK(rendered.find(L"\x1b[") != std::wstring::npos);
  CHECK(rendered.find(L"\x1b[0m") != std::wstring::npos);

  // Overwrite half of a wide glyph; must not leave stray continuation cells.
  screen.put(2, 3, L"x", sty::text);
  const std::wstring after = screen.plain();
  CHECK(after.find(L"x wide") != std::wstring::npos);

  Screen tiny(5, 2);
  tiny.put(0, 0, L"abcdefghij", sty::text);
  CHECK(textWidth(tiny.plain().substr(0, 5)) <= 5);
}

}  // namespace

int main() {
  SetConsoleOutputCP(CP_UTF8);
  testFormatting();
  testRisk();
  testFilters();
  testConfig();
  testScreen();

  std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
