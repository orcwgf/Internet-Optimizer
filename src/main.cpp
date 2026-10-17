#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "app.h"
#include "config.h"
#include "console.h"
#include "filter.h"
#include "risk.h"
#include "sysinfo.h"
#include "util.h"

namespace {

constexpr const wchar_t* kVersion = L"1.1.0";

struct Cli {
  std::wstring configPath;
  bool allowCritical = false;
  bool dump = false;
  bool all = false;
  bool noElevate = false;
  bool help = false;
  bool version = false;
};

void printHelp() {
  const char* text =
      "NetPilot 1.1.0 - find the processes using your network and stop them\n"
      "\n"
      "Usage: netpilot [options]\n"
      "\n"
      "  --allow-critical    allow stopping critical Windows processes\n"
      "                      (still requires typing KILL in the warning dialog)\n"
      "  --dump              print one sampled snapshot and exit (no UI)\n"
      "  --all               with --dump: show system and listening-only rows\n"
      "  --no-elevate        do not ask for administrator rights on startup\n"
      "  --config <path>     use a custom config file\n"
      "  -h, --help          show this help\n"
      "  --version           show the version\n"
      "\n"
      "Keys: Up/Down move, Space mark, K stop, S suspend/resume, D details,\n"
      "      / search, H system processes, L listeners, O sort, ? help, Q quit.\n"
      "\n"
      "NetPilot asks for administrator rights so it can measure per-app speeds\n"
      "and control background services. Press N at the UAC prompt to continue\n"
      "without them (the list still works, speeds show n/a).\n";
  std::fwrite(text, 1, std::strlen(text), stdout);
}

void printVersion() {
  const char* text = "NetPilot 1.1.0\n";
  std::fwrite(text, 1, std::strlen(text), stdout);
}

bool parseArgs(int argc, wchar_t** argv, Cli& cli, std::wstring& error) {
  for (int i = 1; i < argc; ++i) {
    const std::wstring arg = argv[i];
    if (arg == L"--help" || arg == L"-h") {
      cli.help = true;
    } else if (arg == L"--version") {
      cli.version = true;
    } else if (arg == L"--dump") {
      cli.dump = true;
    } else if (arg == L"--all") {
      cli.all = true;
    } else if (arg == L"--no-elevate") {
      cli.noElevate = true;
    } else if (arg == L"--allow-critical") {
      cli.allowCritical = true;
    } else if (arg == L"--config") {
      if (i + 1 >= argc) {
        error = L"Missing value for --config";
        return false;
      }
      cli.configPath = argv[++i];
    } else {
      error = L"Unknown option: " + arg;
      return false;
    }
  }
  return true;
}

std::wstring quoteArg(const std::wstring& arg) {
  std::wstring out = L"\"";
  for (wchar_t c : arg) {
    if (c == L'"') out += L'\\';
    out += c;
  }
  out += L'"';
  return out;
}

// Relaunch through the UAC prompt. Returns true when a new elevated instance
// was started, false when the user cancelled or elevation is unavailable.
bool relaunchElevated(int argc, wchar_t** argv) {
  wchar_t exe[MAX_PATH * 2] = {};
  const DWORD len = GetModuleFileNameW(nullptr, exe,
                                       static_cast<DWORD>(std::size(exe)));
  if (len == 0 || len >= std::size(exe)) return false;

  std::wstring params;
  for (int i = 1; i < argc; ++i) {
    if (!params.empty()) params += L' ';
    params += quoteArg(argv[i]);
  }

  SHELLEXECUTEINFOW sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  sei.lpVerb = L"runas";
  sei.lpFile = exe;
  sei.lpParameters = params.empty() ? nullptr : params.c_str();
  sei.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&sei)) return false;
  if (sei.hProcess) CloseHandle(sei.hProcess);
  return true;
}

std::wstring padLeft(const std::wstring& text, int width) {
  const int used = textWidth(text);
  if (used >= width) return text;
  return std::wstring(static_cast<size_t>(width - used), L' ') + text;
}

void printDump(Config& cfg, const Cli& cli, const std::wstring& configPath) {
  SetConsoleOutputCP(CP_UTF8);

  NetScanner scanner;
  const int64_t now = nowUnix();

  const AdapterTotals before = scanner.adapterTotals();
  scanner.scan();  // primes per-connection counters
  Sleep(1100);
  std::vector<ProcessInfo> processes = scanner.scan();
  const AdapterTotals after = scanner.adapterTotals();

  double downBps = 0.0;
  double upBps = 0.0;
  if (before.ok && after.ok && after.in >= before.in &&
      after.out >= before.out) {
    downBps = static_cast<double>(after.in - before.in) / 1.1;
    upBps = static_cast<double>(after.out - before.out) / 1.1;
  }

  for (ProcessInfo& p : processes) assessRisk(p, GetCurrentProcessId());

  const bool hideSystem = cli.all ? false : cfg.hideSystem;
  const bool hideListen = cli.all ? false : cfg.hideListenOnly;
  const std::vector<size_t> visible = buildVisible(
      processes, hideSystem, hideListen, L"",
      static_cast<SortMode>(std::clamp(cfg.sortMode, 0, 4)));

  std::string out;
  out += "NetPilot " + narrow(kVersion) + " - network snapshot\n";
  out += "Time:     " + formatLocalTime(now) + "\n";
  out += std::string("Mode:     ") +
         (NetScanner::isElevated() ? "administrator" : "standard user") + "\n";
  if (!configPath.empty()) out += "Config:   " + narrow(configPath) + "\n";
  out += "Live:     down " + formatRate(downBps) + ", up " +
         formatRate(upBps) + " (1.1s sample)\n";

  if (after.ok) {
    out += "Adapters: " + formatBytes(after.in) + " received / " +
           formatBytes(after.out) + " sent since boot\n";
  } else {
    out += "Adapters: counters unavailable\n";
  }
  if (!NetScanner::isElevated()) {
    out += "Note:     per-app rates need administrator rights\n";
  }

  out += "\n";
  out += "   PID        DOWN          UP  TCP UDP LISTEN SESS RISK  PROCESS\n";
  out += "  ------------------------------------------------------------------\n";

  for (size_t idx : visible) {
    const ProcessInfo& p = processes[idx];
    const std::string down =
        p.statsLive ? formatRate(p.downBps) : (NetScanner::isElevated() ? "-" : "n/a");
    const std::string up =
        p.statsLive ? formatRate(p.upBps) : (NetScanner::isElevated() ? "-" : "n/a");
    std::wstring row;
    row += L"  " + padLeft(std::to_wstring(p.pid), 5) + L"  ";
    row += padRight(widen(down), 11) + L" ";
    row += padLeft(widen(up), 12) + L"  ";
    row += padLeft(std::to_wstring(p.activeTcp), 3) + L" ";
    row += padLeft(std::to_wstring(p.udpCount), 3) + L" ";
    row += padLeft(std::to_wstring(p.listenTcp), 6) + L" ";
    row += padLeft(std::to_wstring(p.sessionId), 4) + L" ";
    row += padRight(riskBadge(p), 5) + L" ";
    row += p.name;
    if (p.suspended) row += L" (paused)";
    if (!p.company.empty()) row += L"  [" + p.company + L"]";
    out += narrow(row) + "\n";
  }

  if (visible.empty()) {
    out += "  (no processes with network sockets)\n";
  }
  out += "\n";
  out += std::to_string(visible.size()) + " of " +
         std::to_string(processes.size()) + " socket-owning processes shown.\n";
  if (!NetScanner::isElevated()) {
    out += "Tip: run as administrator to see per-app speeds and control "
           "system processes.\n";
  } else {
    out += "Tip: DOWN/UP are per-app TCP rates; Windows exposes no per-app "
           "UDP byte counter.\n";
  }

  std::fwrite(out.data(), 1, out.size(), stdout);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  Cli cli;
  std::wstring error;
  if (!parseArgs(argc, argv, cli, error)) {
    const std::string message = narrow(error);
    std::fwrite(message.data(), 1, message.size(), stderr);
    const char* hint = "\nUse --help for usage.\n";
    std::fwrite(hint, 1, std::strlen(hint), stderr);
    return 2;
  }
  if (cli.help) {
    printHelp();
    return 0;
  }
  if (cli.version) {
    printVersion();
    return 0;
  }

  std::wstring configPath =
      cli.configPath.empty() ? defaultConfigPath() : cli.configPath;
  Config cfg;
  loadConfig(configPath, cfg);

  if (cli.dump) {
    printDump(cfg, cli, configPath);
    return 0;
  }

  wchar_t noElevate[8] = {};
  const bool envNoElevate =
      GetEnvironmentVariableW(L"NETPILOT_NO_ELEVATE", noElevate,
                              static_cast<DWORD>(std::size(noElevate))) > 0;
  if (!cli.noElevate && !envNoElevate && !NetScanner::isElevated()) {
    if (relaunchElevated(argc, argv)) return 0;
    // UAC was cancelled; keep going with the permissions we have.
  }

  Console console;
  if (!console.init()) {
    const char* message =
        "NetPilot needs an interactive Windows console for its UI.\n"
        "Run it from Windows Terminal / conhost, or use --dump for a\n"
        "one-shot text report.\n";
    std::fwrite(message, 1, std::strlen(message), stderr);
    return 2;
  }

  App::Options options;
  options.allowCritical = cli.allowCritical;

  App app(cfg, configPath, options);
  if (!app.init()) {
    console.shutdown();
    const char* message = "NetPilot failed to start.\n";
    std::fwrite(message, 1, std::strlen(message), stderr);
    return 1;
  }
  app.run(console);
  console.shutdown();
  return 0;
}
