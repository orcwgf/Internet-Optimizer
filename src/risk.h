#pragma once

#include <string>

#include "model.h"

// Fills `risk` and `riskReason` based on process name, owner, session and path.
void assessRisk(ProcessInfo& info, uint32_t selfPid);

// Short badge used in the process table: CRIT / SYS / MS / WIN / "".
const wchar_t* riskBadge(const ProcessInfo& info);
const wchar_t* riskLabel(Risk risk);

// Returns a hint for well-known data-hungry apps (sync, streaming, torrents).
std::wstring dataHeavyHint(const std::wstring& processName);
