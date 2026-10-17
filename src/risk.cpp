#include "risk.h"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <vector>

#include "util.h"

namespace {

const wchar_t* const kCriticalNames[] = {
    L"system",
    L"system idle process",
    L"registry",
    L"memory compression",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"services.exe",
    L"lsass.exe",
    L"lsaiso.exe",
    L"svchost.exe",
    L"fontdrvhost.exe",
    L"dwm.exe",
    L"audiodg.exe",
    L"msmpeng.exe",
    L"nissrv.exe",
    L"securityhealthservice.exe",
    L"smartscreen.exe",
    L"wudfhost.exe",
};

const wchar_t* const kDataHeavyNames[] = {
    L"onedrive.exe",      L"dropbox.exe",        L"googledrivefs.exe",
    L"backup and sync",   L"steam.exe",          L"steamwebhelper.exe",
    L"epicgameslauncher.exe", L"battle.net.exe",  L"agent.exe",
    L"spotify.exe",       L"discord.exe",        L"teams.exe",
    L"ms-teams.exe",      L"zoom.exe",           L"slack.exe",
    L"telegram.exe",      L"whatsapp.exe",       L"qbittorrent.exe",
    L"utorrent.exe",      L"transmission.exe",   L"deluge.exe",
    L"adobe creative cloud.exe", L"creative cloud.exe", L"photoshop.exe",
    L"primevideo.exe",    L"netflix.exe",        L"vlc.exe",
    L"thunder.exe",       L"idman.exe",          L"aria2c.exe",
    L"winget.exe",        L"curl.exe",           L"wget.exe",
};

bool matchesAny(const std::wstring& lower,
                const wchar_t* const* names, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (lower == names[i]) return true;
  }
  return false;
}

bool startsWithCI(const std::wstring& text, const std::wstring& prefix) {
  if (prefix.empty() || text.size() < prefix.size()) return false;
  for (size_t i = 0; i < prefix.size(); ++i) {
    if (std::towlower(text[i]) != std::towlower(prefix[i])) return false;
  }
  return true;
}

const std::wstring& windowsDirLower() {
  static const std::wstring dir = [] {
    wchar_t buf[MAX_PATH + 1] = {};
    UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
    return toLower(n > 0 ? std::wstring(buf, n) : std::wstring(L"C:\\Windows"));
  }();
  return dir;
}

}  // namespace

void assessRisk(ProcessInfo& info, uint32_t selfPid) {
  const std::wstring lower = toLower(info.name);
  std::vector<std::wstring> reasons;
  Risk risk = Risk::Normal;

  auto elevate = [&](Risk level, const wchar_t* reason) {
    if (level > risk) risk = level;
    if (reason) reasons.emplace_back(reason);
  };

  if (info.pid == selfPid) {
    elevate(Risk::Critical, L"NetPilot cannot stop itself.");
  }
  if (info.pid <= 4) {
    elevate(Risk::Critical, L"Core Windows kernel process. Stopping it would crash Windows.");
  }
  if (info.protectedProc) {
    elevate(Risk::Critical,
            L"Protected process. Windows blocks tools from stopping it.");
  }

  const size_t criticalCount =
      sizeof(kCriticalNames) / sizeof(kCriticalNames[0]);
  if (matchesAny(lower, kCriticalNames, criticalCount)) {
    elevate(Risk::Critical,
            L"Critical Windows component. Stopping it can crash Windows or cut off "
            L"your network.");
  }

  if (info.systemUser) {
    elevate(Risk::Important,
            L"Runs as a system account (SYSTEM / LOCAL SERVICE / NETWORK SERVICE).");
  } else if (info.sessionId == 0) {
    elevate(Risk::Important, L"Background Windows service running in session 0.");
  }

  if (info.microsoft) {
    elevate(Risk::Important,
            L"Microsoft-published or Windows component. It may be needed by Windows.");
  } else if (!info.path.empty() &&
             startsWithCI(info.path, windowsDirLower())) {
    elevate(Risk::Important, L"Executable lives in the Windows folder.");
  }

  if (lower == L"explorer.exe") {
    elevate(Risk::Important,
            L"Windows shell. Stopping it closes the taskbar and desktop.");
  }

  info.risk = risk;
  info.riskReason.clear();
  for (size_t i = 0; i < reasons.size(); ++i) {
    if (i) info.riskReason += L" ";
    info.riskReason += reasons[i];
  }
}

const wchar_t* riskLabel(Risk risk) {
  switch (risk) {
    case Risk::Critical:
      return L"Critical";
    case Risk::Important:
      return L"Important";
    default:
      return L"Normal";
  }
}

const wchar_t* riskBadge(const ProcessInfo& info) {
  if (info.risk == Risk::Critical) return L"CRIT";
  if (info.risk == Risk::Important) {
    if (info.systemUser || info.sessionId == 0) return L"SYS";
    if (info.microsoft) return L"MS";
    return L"WIN";
  }
  return L"";
}

std::wstring dataHeavyHint(const std::wstring& processName) {
  const std::wstring lower = toLower(processName);
  const size_t count = sizeof(kDataHeavyNames) / sizeof(kDataHeavyNames[0]);
  if (!matchesAny(lower, kDataHeavyNames, count)) return {};
  return L"Known data-heavy app. Background sync, streaming or downloads may "
         L"be using a lot of bandwidth right now.";
}
