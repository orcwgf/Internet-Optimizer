#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "model.h"

struct AdapterTotals {
  uint64_t in = 0;
  uint64_t out = 0;
  bool ok = false;
};

enum class ActionOutcome {
  Ok,
  AccessDenied,
  NotFound,
  Changed,  // PID was reused by a different process
  Failed,
};

const wchar_t* actionMessage(ActionOutcome outcome);

class NetScanner {
 public:
  // Enumerates TCP/UDP endpoints, groups them by owning process, fills in
  // process metadata (cached between scans) and samples per-process TCP rates.
  std::vector<ProcessInfo> scan();

  AdapterTotals adapterTotals() const;
  int64_t bootTime() const;

  bool stillAlive(uint32_t pid, uint64_t createTime) const;

  static bool isElevated();
  static void enableDebugPrivilege();

  static ActionOutcome terminate(uint32_t pid, uint64_t createTime);
  static ActionOutcome setSuspended(uint32_t pid, uint64_t createTime,
                                    bool suspend);

 private:
  struct Meta {
    uint64_t createTime = 0;
    std::wstring path;
    std::wstring company;
    std::wstring user;
    uint32_t sessionId = 0;
    bool elevated = false;
    bool systemUser = false;
    bool protectedProc = false;
    bool microsoft = false;
    bool valid = false;
  };

  struct ConnSample {
    uint64_t in = 0;
    uint64_t out = 0;
    uint64_t tick = 0;
  };

  Meta queryMeta(uint32_t pid, HANDLE process) const;
  Meta cachedMeta(uint32_t pid, uint64_t createTime) const;
  void storeMeta(uint32_t pid, const Meta& meta);

  // Reads (and enables on first sight) TCP extended statistics for one
  // connection. Returns true when `sample` was filled with fresh counters.
  bool sampleTcp(uint32_t pid, ConnRow& conn, uint64_t tick,
                 ConnSample& sample);
  static std::string connKey(uint32_t pid, const ConnRow& conn);

  std::vector<std::pair<uint32_t, Meta>> metaCache_;
  std::unordered_map<std::string, ConnSample> samples_;
  std::unordered_set<std::string> statsEnabled_;

  bool elevationChecked_ = false;
  bool elevatedForStats_ = false;
  bool statsBlocked_ = false;

  static constexpr size_t kMaxCache = 512;
};
