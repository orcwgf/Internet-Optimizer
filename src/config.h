#pragma once

#include <string>

struct Config {
  bool hideSystem = false;
  bool hideListenOnly = true;
  int sortMode = 0;  // matches SortMode in filter.h

  bool fileExisted = false;
};

std::wstring defaultConfigPath();
bool loadConfig(const std::wstring& path, Config& cfg);
bool saveConfig(const std::wstring& path, const Config& cfg);
