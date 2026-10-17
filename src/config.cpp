#include "config.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string_view>

#include "util.h"

std::wstring defaultConfigPath() {
  wchar_t buffer[MAX_PATH * 2] = {};
  DWORD n = GetEnvironmentVariableW(L"APPDATA", buffer,
                                   static_cast<DWORD>(std::size(buffer)));
  std::wstring base;
  if (n > 0 && n < std::size(buffer)) {
    base.assign(buffer, n);
  } else {
    wchar_t exe[MAX_PATH * 2] = {};
    DWORD len = GetModuleFileNameW(nullptr, exe,
                                   static_cast<DWORD>(std::size(exe)));
    if (len > 0) {
      base = std::filesystem::path(std::wstring(exe, len)).parent_path().wstring();
    } else {
      base = L".";
    }
  }
  return (std::filesystem::path(base) / L"NetPilot" / L"config.ini").wstring();
}

namespace {

bool readFile(const std::wstring& path, std::string& out) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return false;
  std::fseek(f, 0, SEEK_END);
  long size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (size < 0) {
    std::fclose(f);
    return false;
  }
  out.resize(static_cast<size_t>(size));
  size_t read = size > 0 ? std::fread(out.data(), 1, out.size(), f) : 0;
  std::fclose(f);
  out.resize(read);
  return true;
}

bool parseInt64(const std::string& s, int64_t& out) {
  if (s.empty()) return false;
  errno = 0;
  char* end = nullptr;
  long long v = std::strtoll(s.c_str(), &end, 10);
  if (end == s.c_str() || errno != 0) return false;
  while (*end == ' ' || *end == '\t') ++end;
  if (*end != '\0') return false;
  out = static_cast<int64_t>(v);
  return true;
}

}  // namespace

bool loadConfig(const std::wstring& path, Config& cfg) {
  std::string data;
  if (!readFile(path, data)) return false;
  cfg.fileExisted = true;

  size_t pos = 0;
  if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xEF &&
      static_cast<unsigned char>(data[1]) == 0xBB &&
      static_cast<unsigned char>(data[2]) == 0xBF) {
    pos = 3;
  }

  while (pos <= data.size()) {
    size_t end = data.find('\n', pos);
    if (end == std::string::npos) end = data.size();
    std::string line = trim(std::string_view(data).substr(pos, end - pos));
    pos = end + 1;

    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = trim(std::string_view(line).substr(0, eq));
    std::string value = trim(std::string_view(line).substr(eq + 1));

    if (key == "hide_system") {
      cfg.hideSystem = value == "1" || value == "true";
    } else if (key == "hide_listen_only") {
      cfg.hideListenOnly = value == "1" || value == "true";
    } else if (key == "sort_mode") {
      int64_t v = 0;
      if (parseInt64(value, v) && v >= 0 && v <= 4) cfg.sortMode = static_cast<int>(v);
    }
  }
  return true;
}

bool saveConfig(const std::wstring& path, const Config& cfg) {
  std::error_code ec;
  std::filesystem::path p(path);
  if (p.has_parent_path()) {
    std::filesystem::create_directories(p.parent_path(), ec);
  }

  std::string out;
  out += "# NetPilot configuration\n";
  out += std::string("hide_system=") + (cfg.hideSystem ? "1" : "0") + "\n";
  out += std::string("hide_listen_only=") + (cfg.hideListenOnly ? "1" : "0") + "\n";
  out += "sort_mode=" + std::to_string(cfg.sortMode) + "\n";

  std::filesystem::path tmp = p;
  tmp += L".tmp";
  FILE* f = nullptr;
  if (_wfopen_s(&f, tmp.c_str(), L"wb") != 0 || !f) return false;
  bool ok = std::fwrite(out.data(), 1, out.size(), f) == out.size();
  ok = (std::fclose(f) == 0) && ok;
  if (!ok) {
    _wremove(tmp.c_str());
    return false;
  }
  return MoveFileExW(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}
