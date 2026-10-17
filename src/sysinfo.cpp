#include "sysinfo.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <processthreadsapi.h>
#include <sddl.h>
#include <tcpestats.h>
#include <tlhelp32.h>
#include <winver.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <iterator>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "util.h"

namespace {

constexpr DWORD kProcessSuspendResume = 0x0800;

std::wstring windowsDir() {
  wchar_t buf[MAX_PATH + 1] = {};
  UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
  return n > 0 ? std::wstring(buf, n) : L"C:\\Windows";
}

std::wstring stateName(DWORD state) {
  switch (state) {
    case MIB_TCP_STATE_CLOSED:
      return L"CLOSED";
    case MIB_TCP_STATE_LISTEN:
      return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT:
      return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:
      return L"SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:
      return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:
      return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:
      return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:
      return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:
      return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK:
      return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:
      return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:
      return L"DELETE_TCB";
    default:
      return L"?";
  }
}

std::wstring ipv4String(DWORD addr) {
  IN_ADDR a{};
  a.S_un.S_addr = addr;
  wchar_t buf[INET_ADDRSTRLEN] = {};
  if (!InetNtopW(AF_INET, &a, buf, INET_ADDRSTRLEN)) return L"?";
  return buf;
}

std::wstring ipv6String(const UCHAR bytes[16]) {
  IN6_ADDR a{};
  std::memcpy(a.u.Byte, bytes, 16);
  wchar_t buf[INET6_ADDRSTRLEN] = {};
  if (!InetNtopW(AF_INET6, &a, buf, INET6_ADDRSTRLEN)) return L"?";
  return buf;
}

template <typename Fn>
bool withTable(Fn fn, ULONG& size, std::vector<BYTE>& buffer) {
  DWORD ret = fn(nullptr, &size);
  if (ret != ERROR_INSUFFICIENT_BUFFER) return false;
  buffer.resize(size);
  ret = fn(buffer.data(), &size);
  return ret == NO_ERROR;
}

uint64_t fileTimeToU64(const FILETIME& ft) {
  ULARGE_INTEGER u{};
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return u.QuadPart;
}

std::wstring queryCompany(const std::wstring& path) {
  if (path.empty()) return {};
  DWORD dummy = 0;
  DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
  if (size == 0) return {};
  std::vector<BYTE> data(size);
  if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return {};

  struct Translation {
    WORD language;
    WORD codePage;
  } *trans = nullptr;
  UINT transSize = 0;
  if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                      reinterpret_cast<LPVOID*>(&trans), &transSize) ||
      trans == nullptr || transSize < sizeof(Translation)) {
    return {};
  }

  wchar_t sub[128] = {};
  swprintf_s(sub, L"\\StringFileInfo\\%04x%04x\\CompanyName", trans[0].language,
             trans[0].codePage);
  wchar_t* value = nullptr;
  UINT valueSize = 0;
  if (!VerQueryValueW(data.data(), sub, reinterpret_cast<LPVOID*>(&value),
                      &valueSize) ||
      value == nullptr || valueSize == 0) {
    return {};
  }
  size_t len = wcsnlen(value, valueSize);
  return std::wstring(value, len);
}

uint64_t processCreateTime(HANDLE process) {
  FILETIME creation{}, exit{}, kernel{}, user{};
  if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return 0;
  return fileTimeToU64(creation);
}

ActionOutcome outcomeFromError(DWORD error) {
  switch (error) {
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
      return ActionOutcome::AccessDenied;
    case ERROR_INVALID_PARAMETER:
    case ERROR_NOT_FOUND:
    case ERROR_INVALID_HANDLE:
      return ActionOutcome::NotFound;
    default:
      return ActionOutcome::Failed;
  }
}

using NtProcessFn = LONG(NTAPI*)(HANDLE);

NtProcessFn ntProcessFn(const char* name) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return nullptr;
  return reinterpret_cast<NtProcessFn>(
      reinterpret_cast<void*>(GetProcAddress(ntdll, name)));
}

bool validPid(uint32_t pid) { return pid != 0 && pid != 4; }

}  // namespace

const wchar_t* actionMessage(ActionOutcome outcome) {
  switch (outcome) {
    case ActionOutcome::Ok:
      return L"ok";
    case ActionOutcome::AccessDenied:
      return L"access denied (try running as administrator)";
    case ActionOutcome::NotFound:
      return L"process already exited";
    case ActionOutcome::Changed:
      return L"PID was reused by another process";
    default:
      return L"Windows refused the request";
  }
}

bool NetScanner::isElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const bool ok = GetTokenInformation(token, TokenElevation, &elevation,
                                      sizeof(elevation), &size) != 0;
  CloseHandle(token);
  return ok && elevation.TokenIsElevated != 0;
}

void NetScanner::enableDebugPrivilege() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    return;
  }
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
  }
  CloseHandle(token);
}

NetScanner::Meta NetScanner::queryMeta(uint32_t pid, HANDLE process) const {
  Meta meta;
  if (!process) return meta;

  meta.createTime = processCreateTime(process);

  wchar_t pathBuf[32768] = {};
  DWORD pathSize = static_cast<DWORD>(std::size(pathBuf));
  if (QueryFullProcessImageNameW(process, 0, pathBuf, &pathSize)) {
    meta.path.assign(pathBuf, pathSize);
  }

  meta.company = queryCompany(meta.path);

  DWORD session = 0;
  if (ProcessIdToSessionId(pid, &session)) meta.sessionId = session;

  HANDLE token = nullptr;
  if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation),
                            &size)) {
      meta.elevated = elevation.TokenIsElevated != 0;
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed > 0) {
      std::vector<BYTE> buf(needed);
      if (GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR sid = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &sid) && sid) {
          meta.user = sid;
          meta.systemUser = meta.user == L"S-1-5-18" ||
                            meta.user == L"S-1-5-19" ||
                            meta.user == L"S-1-5-20";
          LocalFree(sid);
        }
      }
    }
    CloseHandle(token);
  }

  PROCESS_PROTECTION_LEVEL_INFORMATION protection{};
  if (GetProcessInformation(process, ProcessProtectionLevelInfo, &protection,
                            sizeof(protection))) {
    // PROTECTION_LEVEL_NONE is 0xFFFFFFFE on current SDKs (0xFFFFFFFF on
    // older ones). Zero means no protection information.
    const DWORD level = protection.ProtectionLevel;
    meta.protectedProc = level != 0 && level != 0xFFFFFFFE &&
                         level != 0xFFFFFFFF;
  }

  meta.microsoft = containsCI(meta.company, L"Microsoft");
  if (!meta.microsoft && !meta.path.empty()) {
    std::wstring dir = windowsDir() + L"\\";
    if (meta.path.size() >= dir.size() &&
        _wcsnicmp(meta.path.c_str(), dir.c_str(), dir.size()) == 0) {
      meta.microsoft = true;
    }
  }

  meta.valid = true;
  return meta;
}

NetScanner::Meta NetScanner::cachedMeta(uint32_t pid,
                                        uint64_t createTime) const {
  for (const auto& [cachedPid, meta] : metaCache_) {
    if (cachedPid == pid && meta.valid &&
        (createTime == 0 || meta.createTime == 0 ||
         meta.createTime == createTime)) {
      return meta;
    }
  }
  return {};
}

void NetScanner::storeMeta(uint32_t pid, const Meta& meta) {
  for (auto& [cachedPid, cached] : metaCache_) {
    if (cachedPid == pid) {
      cached = meta;
      return;
    }
  }
  if (metaCache_.size() >= kMaxCache) metaCache_.erase(metaCache_.begin());
  metaCache_.emplace_back(pid, meta);
}

std::vector<ProcessInfo> NetScanner::scan() {
  // ---- process names ----------------------------------------------------
  std::unordered_map<uint32_t, std::wstring> names;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
      do {
        names[entry.th32ProcessID] = entry.szExeFile;
      } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
  }

  std::map<uint32_t, std::vector<ConnRow>> byPid;

  // ---- TCP IPv4 ---------------------------------------------------------
  {
    std::vector<BYTE> buffer;
    ULONG size = 0;
    auto fn = [](void* table, ULONG* sz) {
      return GetExtendedTcpTable(table, sz, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
    };
    if (withTable(fn, size, buffer)) {
      auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwOwningPid == 0) continue;
        if (row.dwState == MIB_TCP_STATE_TIME_WAIT ||
            row.dwState == MIB_TCP_STATE_DELETE_TCB)
          continue;
        ConnRow c;
        c.tcp = true;
        c.v6 = false;
        c.localAddr = ipv4String(row.dwLocalAddr);
        c.remoteAddr = ipv4String(row.dwRemoteAddr);
        c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        c.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        c.state = stateName(row.dwState);
        c.listening = row.dwState == MIB_TCP_STATE_LISTEN;
        c.established = row.dwState == MIB_TCP_STATE_ESTAB;
        c.localAddrV4 = row.dwLocalAddr;
        c.remoteAddrV4 = row.dwRemoteAddr;
        c.localPortNet = static_cast<uint16_t>(row.dwLocalPort);
        c.remotePortNet = static_cast<uint16_t>(row.dwRemotePort);
        byPid[row.dwOwningPid].push_back(std::move(c));
      }
    }
  }

  // ---- TCP IPv6 ---------------------------------------------------------
  {
    std::vector<BYTE> buffer;
    ULONG size = 0;
    auto fn = [](void* table, ULONG* sz) {
      return GetExtendedTcpTable(table, sz, FALSE, AF_INET6,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
    };
    if (withTable(fn, size, buffer)) {
      auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwOwningPid == 0) continue;
        if (row.dwState == MIB_TCP_STATE_TIME_WAIT ||
            row.dwState == MIB_TCP_STATE_DELETE_TCB)
          continue;
        ConnRow c;
        c.tcp = true;
        c.v6 = true;
        c.localAddr = ipv6String(row.ucLocalAddr);
        c.remoteAddr = ipv6String(row.ucRemoteAddr);
        c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        c.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        c.state = stateName(row.dwState);
        c.listening = row.dwState == MIB_TCP_STATE_LISTEN;
        c.established = row.dwState == MIB_TCP_STATE_ESTAB;
        std::memcpy(c.localAddrV6, row.ucLocalAddr, 16);
        std::memcpy(c.remoteAddrV6, row.ucRemoteAddr, 16);
        c.localScope = row.dwLocalScopeId;
        c.remoteScope = row.dwRemoteScopeId;
        c.localPortNet = static_cast<uint16_t>(row.dwLocalPort);
        c.remotePortNet = static_cast<uint16_t>(row.dwRemotePort);
        byPid[row.dwOwningPid].push_back(std::move(c));
      }
    }
  }

  // ---- UDP IPv4 ---------------------------------------------------------
  {
    std::vector<BYTE> buffer;
    ULONG size = 0;
    auto fn = [](void* table, ULONG* sz) {
      return GetExtendedUdpTable(table, sz, FALSE, AF_INET,
                                 UDP_TABLE_OWNER_PID, 0);
    };
    if (withTable(fn, size, buffer)) {
      auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwOwningPid == 0) continue;
        ConnRow c;
        c.tcp = false;
        c.localAddr = ipv4String(row.dwLocalAddr);
        c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        c.state = L"UDP";
        byPid[row.dwOwningPid].push_back(std::move(c));
      }
    }
  }

  // ---- UDP IPv6 ---------------------------------------------------------
  {
    std::vector<BYTE> buffer;
    ULONG size = 0;
    auto fn = [](void* table, ULONG* sz) {
      return GetExtendedUdpTable(table, sz, FALSE, AF_INET6,
                                 UDP_TABLE_OWNER_PID, 0);
    };
    if (withTable(fn, size, buffer)) {
      auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwOwningPid == 0) continue;
        ConnRow c;
        c.tcp = false;
        c.v6 = true;
        c.localAddr = ipv6String(row.ucLocalAddr);
        c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        c.state = L"UDP";
        byPid[row.dwOwningPid].push_back(std::move(c));
      }
    }
  }

  // ---- join with process metadata --------------------------------------
  std::vector<ProcessInfo> result;
  result.reserve(byPid.size());
  const uint64_t tick = GetTickCount64();
  std::unordered_set<std::string> seen;

  for (auto& [pid, conns] : byPid) {
    ProcessInfo info;
    info.pid = pid;

    auto nameIt = names.find(pid);
    if (nameIt != names.end()) info.name = nameIt->second;
    if (pid == 4) info.name = L"System";
    if (info.name.empty()) info.name = L"PID " + std::to_wstring(pid);

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
      const uint64_t createTime = processCreateTime(process);
      Meta meta = cachedMeta(pid, createTime);
      if (!meta.valid) {
        meta = queryMeta(pid, process);
        if (meta.valid) storeMeta(pid, meta);
      }
      info.createTime = meta.createTime;
      info.path = meta.path;
      info.company = meta.company;
      info.sessionId = meta.sessionId;
      info.elevated = meta.elevated;
      info.systemUser = meta.systemUser;
      info.protectedProc = meta.protectedProc;
      info.microsoft = meta.microsoft;
      CloseHandle(process);
    } else {
      DWORD session = 0;
      if (ProcessIdToSessionId(pid, &session)) info.sessionId = session;
      // A system process we cannot open is almost certainly a service.
      if (info.sessionId == 0 && pid > 4) info.systemUser = true;
    }

    for (ConnRow& c : conns) {
      if (c.tcp && !c.listening) {
        ConnSample sample;
        if (sampleTcp(pid, c, tick, sample)) {
          c.stats = true;
          c.bytesIn = sample.in;
          c.bytesOut = sample.out;
          info.sampledIn += sample.in;
          info.sampledOut += sample.out;
          info.downBps += c.downBps;
          info.upBps += c.upBps;
          info.statsLive = true;
          seen.insert(connKey(pid, c));
        }
      }
      if (c.tcp) {
        if (c.listening) {
          ++info.listenTcp;
        } else {
          ++info.activeTcp;
        }
      } else {
        ++info.udpCount;
      }
    }

    info.conns = std::move(conns);
    std::sort(info.conns.begin(), info.conns.end(),
              [](const ConnRow& a, const ConnRow& b) {
                if (a.listening != b.listening) return !a.listening;
                if (a.state != b.state) return a.state < b.state;
                return a.remoteAddr < b.remoteAddr;
              });

    result.push_back(std::move(info));
  }

  // Drop per-connection samples for sockets that have closed.
  for (auto it = samples_.begin(); it != samples_.end();) {
    if (seen.find(it->first) == seen.end()) {
      it = samples_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = statsEnabled_.begin(); it != statsEnabled_.end();) {
    if (seen.find(*it) == seen.end()) {
      it = statsEnabled_.erase(it);
    } else {
      ++it;
    }
  }

  return result;
}

std::string NetScanner::connKey(uint32_t pid, const ConnRow& conn) {
  return std::to_string(pid) + (conn.v6 ? "|6|" : "|4|") +
         narrow(conn.localAddr) + ":" + std::to_string(conn.localPort) +
         "|" + narrow(conn.remoteAddr) + ":" +
         std::to_string(conn.remotePort);
}

bool NetScanner::sampleTcp(uint32_t pid, ConnRow& conn, uint64_t tick,
                           ConnSample& sample) {
  if (!elevationChecked_) {
    elevatedForStats_ = isElevated();
    elevationChecked_ = true;
  }
  if (!elevatedForStats_ || statsBlocked_) return false;

  MIB_TCPROW row{};
  MIB_TCP6ROW row6{};
  if (conn.v6) {
    row6.State = MIB_TCP_STATE_ESTAB;
    std::memcpy(row6.LocalAddr.u.Byte, conn.localAddrV6, 16);
    row6.dwLocalScopeId = conn.localScope;
    row6.dwLocalPort = conn.localPortNet;
    std::memcpy(row6.RemoteAddr.u.Byte, conn.remoteAddrV6, 16);
    row6.dwRemoteScopeId = conn.remoteScope;
    row6.dwRemotePort = conn.remotePortNet;
  } else {
    row.dwState = MIB_TCP_STATE_ESTAB;
    row.dwLocalAddr = conn.localAddrV4;
    row.dwLocalPort = conn.localPortNet;
    row.dwRemoteAddr = conn.remoteAddrV4;
    row.dwRemotePort = conn.remotePortNet;
  }

  const std::string key = connKey(pid, conn);
  if (statsEnabled_.find(key) == statsEnabled_.end()) {
    TCP_ESTATS_DATA_RW_v0 rw{};
    rw.EnableCollection = TRUE;
    const ULONG status =
        conn.v6 ? SetPerTcp6ConnectionEStats(&row6, TcpConnectionEstatsData,
                                             reinterpret_cast<PUCHAR>(&rw), 0,
                                             sizeof(rw), 0)
                : SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData,
                                            reinterpret_cast<PUCHAR>(&rw), 0,
                                            sizeof(rw), 0);
    if (status == ERROR_ACCESS_DENIED) {
      statsBlocked_ = true;
      return false;
    }
    if (status != NO_ERROR) return false;
    statsEnabled_.insert(key);
  }

  TCP_ESTATS_DATA_RW_v0 rw{};
  TCP_ESTATS_DATA_ROD_v0 rod{};
  const ULONG status =
      conn.v6 ? GetPerTcp6ConnectionEStats(
                    &row6, TcpConnectionEstatsData,
                    reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), nullptr, 0, 0,
                    reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod))
              : GetPerTcpConnectionEStats(
                    &row, TcpConnectionEstatsData,
                    reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), nullptr, 0, 0,
                    reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod));
  if (status != NO_ERROR || !rw.EnableCollection) {
    // A connection can report that collection is still off even after the
    // setter succeeded; retry the enable on the next scan.
    if (status == NO_ERROR) statsEnabled_.erase(key);
    return false;
  }

  double down = 0.0;
  double up = 0.0;
  auto it = samples_.find(key);
  if (it != samples_.end() && tick > it->second.tick) {
    const double seconds = static_cast<double>(tick - it->second.tick) / 1000.0;
    if (seconds >= 0.05) {
      if (rod.DataBytesIn >= it->second.in) {
        down = static_cast<double>(rod.DataBytesIn - it->second.in) / seconds;
      }
      if (rod.DataBytesOut >= it->second.out) {
        up = static_cast<double>(rod.DataBytesOut - it->second.out) / seconds;
      }
    }
  }
  samples_[key] = ConnSample{rod.DataBytesIn, rod.DataBytesOut, tick};

  conn.downBps = down;
  conn.upBps = up;
  sample.in = rod.DataBytesIn;
  sample.out = rod.DataBytesOut;
  sample.tick = tick;
  return true;
}

AdapterTotals NetScanner::adapterTotals() const {
  AdapterTotals totals;
  PMIB_IF_TABLE2 table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) return totals;

  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IF_ROW2& row = table->Table[i];
    if (row.OperStatus != IfOperStatusUp) continue;
    if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || row.Type == IF_TYPE_TUNNEL) {
      continue;
    }
    if (!row.InterfaceAndOperStatusFlags.HardwareInterface) continue;
    totals.in += row.InOctets;
    totals.out += row.OutOctets;
    totals.ok = true;
  }

  FreeMibTable(table);
  return totals;
}

int64_t NetScanner::bootTime() const {
  return static_cast<int64_t>(std::time(nullptr)) -
         static_cast<int64_t>(GetTickCount64() / 1000ULL);
}

bool NetScanner::stillAlive(uint32_t pid, uint64_t createTime) const {
  HANDLE process = OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
  if (!process) return false;
  bool alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
  if (alive && createTime != 0) {
    const uint64_t actual = processCreateTime(process);
    alive = actual == 0 || actual == createTime;
  }
  CloseHandle(process);
  return alive;
}

ActionOutcome NetScanner::terminate(uint32_t pid, uint64_t createTime) {
  if (!validPid(pid)) return ActionOutcome::NotFound;
  HANDLE process =
      OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION |
                      SYNCHRONIZE,
                  FALSE, pid);
  if (!process) return outcomeFromError(GetLastError());

  if (createTime != 0) {
    const uint64_t actual = processCreateTime(process);
    if (actual != 0 && actual != createTime) {
      CloseHandle(process);
      return ActionOutcome::Changed;
    }
  }

  if (!TerminateProcess(process, 1)) {
    const DWORD error = GetLastError();
    CloseHandle(process);
    return outcomeFromError(error);
  }
  WaitForSingleObject(process, 1500);
  CloseHandle(process);
  return ActionOutcome::Ok;
}

ActionOutcome NetScanner::setSuspended(uint32_t pid, uint64_t createTime,
                                       bool suspend) {
  if (!validPid(pid)) return ActionOutcome::NotFound;

  HANDLE process = OpenProcess(kProcessSuspendResume |
                                   PROCESS_QUERY_LIMITED_INFORMATION |
                                   SYNCHRONIZE,
                               FALSE, pid);
  if (!process) return outcomeFromError(GetLastError());

  if (createTime != 0) {
    const uint64_t actual = processCreateTime(process);
    if (actual != 0 && actual != createTime) {
      CloseHandle(process);
      return ActionOutcome::Changed;
    }
  }

  NtProcessFn fn = ntProcessFn(suspend ? "NtSuspendProcess" : "NtResumeProcess");
  if (!fn) {
    CloseHandle(process);
    return ActionOutcome::Failed;
  }

  const LONG status = fn(process);
  CloseHandle(process);
  if (status == 0) return ActionOutcome::Ok;
  if (status == static_cast<LONG>(0xC0000022)) return ActionOutcome::AccessDenied;
  if (status == static_cast<LONG>(0xC000010A)) return ActionOutcome::NotFound;
  return ActionOutcome::Failed;
}
