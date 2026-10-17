#include "filter.h"

#include <algorithm>

#include "util.h"

const wchar_t* sortName(SortMode mode) {
  switch (mode) {
    case SortMode::Name:
      return L"name A-Z";
    case SortMode::Pid:
      return L"PID";
    case SortMode::Risk:
      return L"risk";
    case SortMode::Session:
      return L"session";
    default:
      return L"speed";
  }
}

SortMode nextSort(SortMode mode) {
  int next = (static_cast<int>(mode) + 1) % 5;
  if (next < 0) next = 0;
  return static_cast<SortMode>(next);
}

std::vector<size_t> buildVisible(const std::vector<ProcessInfo>& processes,
                                 bool hideSystem, bool hideListenOnly,
                                 std::wstring_view search, SortMode mode) {
  std::vector<size_t> out;
  out.reserve(processes.size());

  const std::wstring needle = trimW(search);

  for (size_t i = 0; i < processes.size(); ++i) {
    const ProcessInfo& p = processes[i];

    if (hideListenOnly && !p.suspended && p.activeTcp == 0 && p.udpCount == 0) {
      continue;
    }
    if (hideSystem && (p.systemUser || p.sessionId == 0)) {
      continue;
    }
    if (!needle.empty()) {
      if (!containsCI(p.name, needle) && !containsCI(p.path, needle) &&
          !containsCI(p.company, needle)) {
        continue;
      }
    }
    out.push_back(i);
  }

  auto lowerName = [&](size_t i) { return toLower(processes[i].name); };

  switch (mode) {
    case SortMode::Name:
      std::sort(out.begin(), out.end(), [&](size_t a, size_t b) {
        return lowerName(a) < lowerName(b);
      });
      break;
    case SortMode::Pid:
      std::sort(out.begin(), out.end(), [&](size_t a, size_t b) {
        return processes[a].pid < processes[b].pid;
      });
      break;
    case SortMode::Risk:
      std::sort(out.begin(), out.end(), [&](size_t a, size_t b) {
        const ProcessInfo& pa = processes[a];
        const ProcessInfo& pb = processes[b];
        if (pa.risk != pb.risk) return pa.risk > pb.risk;
        if (pa.rate() != pb.rate()) return pa.rate() > pb.rate();
        if (pa.traffic() != pb.traffic()) return pa.traffic() > pb.traffic();
        return lowerName(a) < lowerName(b);
      });
      break;
    case SortMode::Session:
      std::sort(out.begin(), out.end(), [&](size_t a, size_t b) {
        if (processes[a].sessionId != processes[b].sessionId)
          return processes[a].sessionId < processes[b].sessionId;
        if (processes[a].rate() != processes[b].rate())
          return processes[a].rate() > processes[b].rate();
        if (processes[a].traffic() != processes[b].traffic())
          return processes[a].traffic() > processes[b].traffic();
        return lowerName(a) < lowerName(b);
      });
      break;
    case SortMode::Traffic:
    default:
      std::sort(out.begin(), out.end(), [&](size_t a, size_t b) {
        const ProcessInfo& pa = processes[a];
        const ProcessInfo& pb = processes[b];
        // "Traffic" now means observed throughput: the process downloading
        // right now is the one at the top, even if it has one connection.
        if (pa.downBps != pb.downBps) return pa.downBps > pb.downBps;
        if (pa.upBps != pb.upBps) return pa.upBps > pb.upBps;
        if (pa.traffic() != pb.traffic()) return pa.traffic() > pb.traffic();
        if (pa.risk != pb.risk) return pa.risk > pb.risk;
        return lowerName(a) < lowerName(b);
      });
      break;
  }

  return out;
}
