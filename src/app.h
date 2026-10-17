#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "config.h"
#include "filter.h"
#include "model.h"
#include "sysinfo.h"

class Console;
class Screen;
struct InputEvent;

enum class ModalKind {
  None,
  Kill,
  Suspend,
  Details,
  Help,
};

enum class ToastKind { Info, Ok, Warn, Error };

struct KillTarget {
  uint32_t pid = 0;
  uint64_t createTime = 0;
  std::wstring name;
  Risk risk = Risk::Normal;
  std::wstring reason;
  int traffic = 0;
  double downBps = 0.0;
  double upBps = 0.0;
};

struct ModalState {
  ModalKind kind = ModalKind::None;
  std::vector<KillTarget> targets;
  uint32_t detailsPid = 0;
  uint64_t detailsCreateTime = 0;
  std::wstring input;
  bool typedRequired = false;
  bool blocked = false;
  int scroll = 0;
};

class App {
 public:
  struct Options {
    bool allowCritical = false;
  };

  App(Config cfg, std::wstring configPath, Options options);

  bool init();
  void run(Console& console);

  // Exposed for the headless --dump mode.
  const std::vector<ProcessInfo>& processes() const { return procs_; }
  const Config& config() const { return cfg_; }

 private:
  using ProcessKey = std::pair<uint32_t, uint64_t>;

  // data
  NetScanner scanner_;
  Config cfg_;
  std::wstring configPath_;
  Options options_;

  std::vector<ProcessInfo> procs_;
  std::vector<size_t> visible_;
  std::map<ProcessKey, ProcessInfo> suspendedInfo_;
  std::set<ProcessKey> marked_;

  int cursor_ = 0;
  int scroll_ = 0;
  SortMode sort_ = SortMode::Traffic;
  std::wstring search_;
  bool searchEditing_ = false;

  ModalState modal_;
  std::wstring toast_;
  ToastKind toastKind_ = ToastKind::Info;
  int64_t toastUntil_ = 0;

  bool elevated_ = false;
  bool quit_ = false;
  int64_t now_ = 0;
  int64_t lastScan_ = 0;
  int64_t updatedAt_ = 0;

  // Global adapter throughput, sampled more often than the process table.
  AdapterTotals prevTotals_;
  uint64_t prevTotalsTick_ = 0;
  double downBps_ = 0.0;
  double upBps_ = 0.0;
  uint64_t sessionIn_ = 0;
  uint64_t sessionOut_ = 0;

  // behavior
  void tickNetwork();
  void refresh();
  void rebuildVisible(const ProcessKey& preferred);
  ProcessInfo* currentProc();
  const ProcessInfo* currentProc() const;
  ProcessKey selectedKey() const;

  void handle(const InputEvent& event);
  void handleMainKey(const InputEvent& event);
  void handleSearchKey(const InputEvent& event);
  void handleModalKey(const InputEvent& event);

  void moveCursor(int delta);
  void pageCursor(int pages);
  void toggleMark();
  void beginKill();
  void beginSuspend();
  void beginDetails();
  void confirmKill();
  void confirmSuspend();
  std::vector<KillTarget> collectTargets() const;
  void pruneState();

  void setToast(std::wstring text, ToastKind kind, int seconds = 4);
  void saveNow();
  void toggleFilter(bool systemFilter);
  void cycleSort();

  // drawing (render.cpp)
 public:
  void draw(Screen& screen);

 private:
  void drawHeader(Screen& screen, int w, int h);
  void drawTable(Screen& screen, int w, int h);
  void drawFooter(Screen& screen, int w, int h);
  void drawModal(Screen& screen, int w, int h);
};
