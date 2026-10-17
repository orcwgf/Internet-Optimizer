#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "model.h"

enum class SortMode {
  Traffic = 0,
  Name = 1,
  Pid = 2,
  Risk = 3,
  Session = 4,
};

const wchar_t* sortName(SortMode mode);
SortMode nextSort(SortMode mode);

// Returns indices into `processes` that should be displayed, sorted.
std::vector<size_t> buildVisible(const std::vector<ProcessInfo>& processes,
                                 bool hideSystem, bool hideListenOnly,
                                 std::wstring_view search, SortMode mode);
