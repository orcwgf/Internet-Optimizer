#pragma once

#include <cstdint>
#include <string>
#include <vector>

// A single socket owned by a process.
struct ConnRow {
  bool tcp = true;
  bool v6 = false;
  std::wstring localAddr;
  std::wstring remoteAddr;
  uint16_t localPort = 0;
  uint16_t remotePort = 0;
  std::wstring state;  // "ESTABLISHED", "LISTEN", "UDP", ...
  bool listening = false;
  bool established = false;

  // Raw values needed to ask Windows for TCP extended statistics.
  uint32_t localAddrV4 = 0;
  uint32_t remoteAddrV4 = 0;
  unsigned char localAddrV6[16] = {};
  unsigned char remoteAddrV6[16] = {};
  uint32_t localScope = 0;
  uint32_t remoteScope = 0;
  uint16_t localPortNet = 0;
  uint16_t remotePortNet = 0;

  // Per-connection counters, when Windows extended statistics are available.
  bool stats = false;
  uint64_t bytesIn = 0;
  uint64_t bytesOut = 0;
  double downBps = 0.0;
  double upBps = 0.0;
};

enum class Risk {
  Normal = 0,
  Important = 1,
  Critical = 2,
};

// Everything the UI needs to know about one process with network sockets.
struct ProcessInfo {
  uint32_t pid = 0;
  std::wstring name;
  std::wstring path;
  std::wstring company;
  uint32_t sessionId = 0;
  bool elevated = false;
  bool systemUser = false;      // SYSTEM / LOCAL SERVICE / NETWORK SERVICE
  bool protectedProc = false;   // Windows protected process
  bool microsoft = false;       // Microsoft-published or Windows-owned binary
  Risk risk = Risk::Normal;
  std::wstring riskReason;
  uint64_t createTime = 0;      // 100ns units, guards against PID reuse

  int activeTcp = 0;            // non-listening TCP sockets
  int listenTcp = 0;
  int udpCount = 0;

  // Live rates summed from TCP extended statistics (administrator only).
  double downBps = 0.0;
  double upBps = 0.0;
  uint64_t sampledIn = 0;
  uint64_t sampledOut = 0;
  bool statsLive = false;

  bool suspended = false;       // suspended by NetPilot
  std::vector<ConnRow> conns;

  int traffic() const { return activeTcp + udpCount; }
  double rate() const { return downBps + upBps; }
};
