#include "app.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <cwctype>

#include "console.h"
#include "risk.h"
#include "screen.h"
#include "util.h"

namespace {

bool isPrintable(wchar_t c) { return c >= 32 && c != 127; }

}  // namespace

App::App(Config cfg, std::wstring configPath, Options options)
    : cfg_(std::move(cfg)),
      configPath_(std::move(configPath)),
      options_(options) {
  sort_ = static_cast<SortMode>(std::clamp(cfg_.sortMode, 0, 4));
}

bool App::init() {
  elevated_ = NetScanner::isElevated();
  if (elevated_) NetScanner::enableDebugPrivilege();

  now_ = nowUnix();
  tickNetwork();  // prime the adapter counters
  refresh();

  if (!elevated_) {
    setToast(L"Not running as administrator: per-app speeds and system "
             L"process control are unavailable. Restart and accept the UAC "
             L"prompt for full access.",
             ToastKind::Warn, 10);
  } else {
    setToast(L"Sampling network traffic. The busiest process moves to the top.",
             ToastKind::Info, 5);
  }

  saveNow();
  return true;
}

void App::run(Console& console) {
  while (!quit_ && !console.interrupted()) {
    now_ = nowUnix();
    tickNetwork();
    if (now_ - lastScan_ >= 2) refresh();

    Screen screen(console.width(), console.height());
    draw(screen);
    console.draw(screen);

    InputEvent event = console.poll(250);
    if (event.key != Key::None) handle(event);
  }
  saveNow();
}

void App::tickNetwork() {
  const AdapterTotals totals = scanner_.adapterTotals();
  const uint64_t tick = GetTickCount64();
  if (!totals.ok) {
    downBps_ = 0.0;
    upBps_ = 0.0;
    return;
  }

  if (prevTotals_.ok && prevTotalsTick_ > 0 && tick > prevTotalsTick_) {
    const double seconds =
        static_cast<double>(tick - prevTotalsTick_) / 1000.0;
    if (seconds >= 0.05) {
      uint64_t deltaIn = 0;
      uint64_t deltaOut = 0;
      if (totals.in >= prevTotals_.in) deltaIn = totals.in - prevTotals_.in;
      if (totals.out >= prevTotals_.out) deltaOut = totals.out - prevTotals_.out;
      downBps_ = static_cast<double>(deltaIn) / seconds;
      upBps_ = static_cast<double>(deltaOut) / seconds;
      sessionIn_ += deltaIn;
      sessionOut_ += deltaOut;
    }
  }

  prevTotals_ = totals;
  prevTotalsTick_ = tick;
}

void App::refresh() {
  const ProcessKey preferred = selectedKey();
  std::vector<ProcessInfo> scanned = scanner_.scan();

  for (ProcessInfo& p : scanned) {
    const ProcessKey key{p.pid, p.createTime};
    p.suspended = suspendedInfo_.find(key) != suspendedInfo_.end();
    if (p.suspended) {
      p.downBps = 0.0;
      p.upBps = 0.0;
    }
  }

  // Keep suspended processes visible (and resumable) even after their sockets
  // disappear.
  for (auto it = suspendedInfo_.begin(); it != suspendedInfo_.end();) {
    bool found = false;
    for (const ProcessInfo& p : scanned) {
      if (p.pid == it->first.first && p.createTime == it->first.second) {
        found = true;
        break;
      }
    }
    if (!found) {
      if (scanner_.stillAlive(it->first.first, it->first.second)) {
        ProcessInfo copy = it->second;
        copy.suspended = true;
        copy.conns.clear();
        copy.activeTcp = 0;
        copy.listenTcp = 0;
        copy.udpCount = 0;
        copy.downBps = 0.0;
        copy.upBps = 0.0;
        scanned.push_back(std::move(copy));
      } else {
        it = suspendedInfo_.erase(it);
        continue;
      }
    }
    ++it;
  }

  for (ProcessInfo& p : scanned) {
    assessRisk(p, GetCurrentProcessId());
  }

  procs_ = std::move(scanned);
  pruneState();
  rebuildVisible(preferred);
  updatedAt_ = now_;
  lastScan_ = now_;
}

void App::pruneState() {
  std::set<ProcessKey> alive;
  for (const ProcessInfo& p : procs_) alive.insert({p.pid, p.createTime});
  for (auto it = marked_.begin(); it != marked_.end();) {
    if (alive.find(*it) == alive.end()) {
      it = marked_.erase(it);
    } else {
      ++it;
    }
  }
}

void App::rebuildVisible(const ProcessKey& preferred) {
  visible_ = buildVisible(procs_, cfg_.hideSystem, cfg_.hideListenOnly,
                          search_, sort_);

  // Do not keep marks on rows that are currently filtered out.
  if (!marked_.empty()) {
    std::set<ProcessKey> shown;
    for (size_t idx : visible_) {
      shown.insert({procs_[idx].pid, procs_[idx].createTime});
    }
    for (auto it = marked_.begin(); it != marked_.end();) {
      if (shown.find(*it) == shown.end()) {
        it = marked_.erase(it);
      } else {
        ++it;
      }
    }
  }

  if (visible_.empty()) {
    cursor_ = 0;
    scroll_ = 0;
    return;
  }

  int found = -1;
  for (size_t i = 0; i < visible_.size(); ++i) {
    if (procs_[visible_[i]].pid == preferred.first &&
        procs_[visible_[i]].createTime == preferred.second) {
      found = static_cast<int>(i);
      break;
    }
  }
  if (found >= 0) {
    cursor_ = found;
  } else {
    cursor_ = std::clamp(cursor_, 0, static_cast<int>(visible_.size()) - 1);
  }
  scroll_ = std::clamp(scroll_, 0, std::max(0, static_cast<int>(visible_.size()) - 1));
}

App::ProcessKey App::selectedKey() const {
  if (visible_.empty() || cursor_ < 0 ||
      cursor_ >= static_cast<int>(visible_.size())) {
    return {0, 0};
  }
  const ProcessInfo& p = procs_[visible_[static_cast<size_t>(cursor_)]];
  return {p.pid, p.createTime};
}

ProcessInfo* App::currentProc() {
  if (visible_.empty() || cursor_ < 0 ||
      cursor_ >= static_cast<int>(visible_.size())) {
    return nullptr;
  }
  return &procs_[visible_[static_cast<size_t>(cursor_)]];
}

const ProcessInfo* App::currentProc() const {
  if (visible_.empty() || cursor_ < 0 ||
      cursor_ >= static_cast<int>(visible_.size())) {
    return nullptr;
  }
  return &procs_[visible_[static_cast<size_t>(cursor_)]];
}

void App::moveCursor(int delta) {
  if (visible_.empty()) return;
  cursor_ = std::clamp(cursor_ + delta, 0, static_cast<int>(visible_.size()) - 1);
}

void App::pageCursor(int pages) { moveCursor(pages * 10); }

void App::toggleMark() {
  ProcessInfo* p = currentProc();
  if (!p) return;
  const ProcessKey key{p->pid, p->createTime};
  if (marked_.count(key)) {
    marked_.erase(key);
  } else {
    marked_.insert(key);
  }
}

void App::toggleFilter(bool systemFilter) {
  const ProcessKey preferred = selectedKey();
  if (systemFilter) {
    cfg_.hideSystem = !cfg_.hideSystem;
    setToast(cfg_.hideSystem ? L"System processes hidden." : L"System processes shown.",
             ToastKind::Info);
  } else {
    cfg_.hideListenOnly = !cfg_.hideListenOnly;
    setToast(cfg_.hideListenOnly
                 ? L"Showing only processes with active traffic."
                 : L"Showing listening-only processes too.",
             ToastKind::Info);
  }
  rebuildVisible(preferred);
  saveNow();
}

void App::cycleSort() {
  const ProcessKey preferred = selectedKey();
  sort_ = nextSort(sort_);
  cfg_.sortMode = static_cast<int>(sort_);
  rebuildVisible(preferred);
  setToast(std::wstring(L"Sorted by ") + sortName(sort_) + L".", ToastKind::Info);
  saveNow();
}

void App::beginKill() {
  std::vector<KillTarget> targets = collectTargets();
  if (targets.empty()) return;

  bool blocked = false;
  bool important = false;
  for (const KillTarget& t : targets) {
    if (t.risk == Risk::Critical && !options_.allowCritical) blocked = true;
    if (t.risk >= Risk::Important) important = true;
  }

  modal_ = ModalState{};
  modal_.kind = ModalKind::Kill;
  modal_.targets = std::move(targets);
  modal_.typedRequired = important && !blocked;
  modal_.blocked = blocked;
}

void App::beginSuspend() {
  ProcessInfo* p = currentProc();
  if (!p) return;

  const ProcessKey key{p->pid, p->createTime};
  if (p->suspended) {
    const ActionOutcome outcome =
        NetScanner::setSuspended(p->pid, p->createTime, false);
    if (outcome == ActionOutcome::Ok) {
      suspendedInfo_.erase(key);
      setToast(L"Resumed " + p->name + L".", ToastKind::Ok);
      refresh();
    } else {
      setToast(L"Could not resume " + p->name + L": " + actionMessage(outcome) +
                   L".",
               ToastKind::Error, 6);
    }
    return;
  }

  modal_ = ModalState{};
  modal_.kind = ModalKind::Suspend;
  KillTarget target;
  target.pid = p->pid;
  target.createTime = p->createTime;
  target.name = p->name;
  target.risk = p->risk;
  target.reason = p->riskReason;
  target.traffic = p->traffic();
  target.downBps = p->downBps;
  target.upBps = p->upBps;
  modal_.targets.push_back(std::move(target));
  modal_.blocked = p->risk == Risk::Critical;
}

void App::beginDetails() {
  const ProcessInfo* p = currentProc();
  if (!p) return;
  modal_ = ModalState{};
  modal_.kind = ModalKind::Details;
  modal_.detailsPid = p->pid;
  modal_.detailsCreateTime = p->createTime;
}

std::vector<KillTarget> App::collectTargets() const {
  std::vector<KillTarget> out;
  auto add = [&out](const ProcessInfo& p) {
    out.push_back({p.pid, p.createTime, p.name, p.risk, p.riskReason,
                   p.traffic(), p.downBps, p.upBps});
  };
  if (!marked_.empty()) {
    for (const ProcessInfo& p : procs_) {
      if (marked_.count({p.pid, p.createTime})) add(p);
    }
  } else if (const ProcessInfo* p = currentProc()) {
    add(*p);
  }
  return out;
}

void App::confirmKill() {
  if (modal_.blocked) {
    setToast(L"Blocked: critical Windows processes are protected. "
             L"Restart with --allow-critical to override.",
             ToastKind::Error, 8);
    return;
  }
  if (modal_.typedRequired && toLower(trimW(modal_.input)) != L"kill") {
    setToast(L"Type KILL (capital letters) and press Enter to confirm.",
             ToastKind::Warn);
    return;
  }

  int success = 0;
  int failed = 0;
  int skipped = 0;
  std::wstring firstError;
  const uint32_t self = GetCurrentProcessId();

  for (const KillTarget& t : modal_.targets) {
    if (t.pid == self || t.pid <= 4) {
      ++skipped;
      continue;
    }
    if (t.risk == Risk::Critical && !options_.allowCritical) {
      ++skipped;
      continue;
    }
    const ActionOutcome outcome =
        NetScanner::terminate(t.pid, t.createTime);
    if (outcome == ActionOutcome::Ok) {
      ++success;
    } else {
      ++failed;
      if (firstError.empty()) {
        firstError = L"Could not stop " + t.name + L": " +
                     actionMessage(outcome) + L".";
      }
    }
  }

  modal_ = ModalState{};
  marked_.clear();
  refresh();

  std::wstring message;
  if (success > 0) {
    message = L"Stopped " + std::to_wstring(success);
    message += success == 1 ? L" process." : L" processes.";
  }
  if (failed > 0) {
    if (!message.empty()) message += L" ";
    message += firstError;
  }
  if (skipped > 0) {
    if (!message.empty()) message += L" ";
    message += std::to_wstring(skipped) + L" skipped (protected).";
  }
  if (message.empty()) message = L"No process was stopped.";
  setToast(message, failed > 0 ? ToastKind::Warn : ToastKind::Ok, 7);
}

void App::confirmSuspend() {
  if (modal_.targets.empty()) {
    modal_ = ModalState{};
    return;
  }
  if (modal_.blocked) {
    setToast(L"Blocked: suspending a critical Windows component can freeze "
             L"Windows. No action taken.",
             ToastKind::Error, 7);
    return;
  }

  const KillTarget target = modal_.targets.front();
  ProcessInfo* p = currentProc();
  ProcessInfo snapshot;
  if (p) snapshot = *p;

  const ActionOutcome outcome =
      NetScanner::setSuspended(target.pid, target.createTime, true);
  if (outcome == ActionOutcome::Ok) {
    if (p) {
      snapshot.suspended = true;
      snapshot.downBps = 0.0;
      snapshot.upBps = 0.0;
      suspendedInfo_[{target.pid, target.createTime}] = snapshot;
    }
    setToast(L"Suspended " + target.name +
                 L". Its traffic is paused; press S to resume.",
             ToastKind::Ok, 6);
    modal_ = ModalState{};
    refresh();
  } else {
    setToast(L"Could not suspend " + target.name + L": " +
                 actionMessage(outcome) + L".",
             ToastKind::Error, 6);
  }
}

void App::setToast(std::wstring text, ToastKind kind, int seconds) {
  toast_ = std::move(text);
  toastKind_ = kind;
  toastUntil_ = (now_ > 0 ? now_ : nowUnix()) + seconds;
}

void App::saveNow() { saveConfig(configPath_, cfg_); }

void App::handle(const InputEvent& event) {
  if (event.key == Key::Resize) return;
  if (event.key == Key::Char && event.ch == 3) {  // Ctrl+C
    quit_ = true;
    return;
  }

  if (modal_.kind != ModalKind::None) {
    handleModalKey(event);
    return;
  }
  if (searchEditing_) {
    handleSearchKey(event);
    return;
  }
  handleMainKey(event);
}

void App::handleSearchKey(const InputEvent& event) {
  switch (event.key) {
    case Key::Escape:
      searchEditing_ = false;
      search_.clear();
      rebuildVisible(selectedKey());
      return;
    case Key::Enter:
      searchEditing_ = false;
      return;
    case Key::Backspace:
      if (!search_.empty()) {
        if (search_.size() >= 2 &&
            search_[search_.size() - 1] >= 0xDC00 &&
            search_[search_.size() - 1] <= 0xDFFF) {
          search_.erase(search_.size() - 2);
        } else {
          search_.pop_back();
        }
        rebuildVisible(selectedKey());
      }
      return;
    case Key::Up:
      moveCursor(-1);
      return;
    case Key::Down:
      moveCursor(1);
      return;
    case Key::Char:
      if (isPrintable(event.ch)) {
        search_.push_back(event.ch);
        rebuildVisible(selectedKey());
      }
      return;
    default:
      return;
  }
}

void App::handleMainKey(const InputEvent& event) {
  switch (event.key) {
    case Key::Up:
      moveCursor(-1);
      return;
    case Key::Down:
      moveCursor(1);
      return;
    case Key::PageUp:
      pageCursor(-1);
      return;
    case Key::PageDown:
      pageCursor(1);
      return;
    case Key::Home:
      moveCursor(-static_cast<int>(visible_.size()));
      return;
    case Key::End:
      moveCursor(static_cast<int>(visible_.size()));
      return;
    case Key::Escape:
      if (!search_.empty()) {
        search_.clear();
        rebuildVisible(selectedKey());
        setToast(L"Search cleared.", ToastKind::Info);
      } else if (!marked_.empty()) {
        marked_.clear();
        setToast(L"Selection cleared.", ToastKind::Info);
      }
      return;
    case Key::F5:
      refresh();
      setToast(L"Refreshed.", ToastKind::Info, 2);
      return;
    case Key::Enter:
      beginDetails();
      return;
    case Key::Char:
      break;
    default:
      return;
  }

  switch (event.ch) {
    case L' ':
      toggleMark();
      return;
    case L'k':
    case L'K':
      beginKill();
      return;
    case L's':
    case L'S':
      beginSuspend();
      return;
    case L'd':
    case L'D':
      beginDetails();
      return;
    case L'/':
      searchEditing_ = true;
      return;
    case L'h':
    case L'H':
      toggleFilter(true);
      return;
    case L'l':
    case L'L':
      toggleFilter(false);
      return;
    case L'o':
    case L'O':
      cycleSort();
      return;
    case L'r':
      refresh();
      setToast(L"Refreshed.", ToastKind::Info, 2);
      return;
    case L'?':
      modal_ = ModalState{};
      modal_.kind = ModalKind::Help;
      return;
    case L'q':
    case L'Q':
      quit_ = true;
      return;
    default:
      return;
  }
}

void App::handleModalKey(const InputEvent& event) {
  if (event.key == Key::Escape) {
    modal_ = ModalState{};
    return;
  }

  if (modal_.kind == ModalKind::Details || modal_.kind == ModalKind::Help) {
    switch (event.key) {
      case Key::Up:
      case Key::Left:
        modal_.scroll = std::max(0, modal_.scroll - 1);
        return;
      case Key::Down:
      case Key::Right:
        modal_.scroll += 1;
        return;
      case Key::PageUp:
        modal_.scroll = std::max(0, modal_.scroll - 12);
        return;
      case Key::PageDown:
        modal_.scroll += 12;
        return;
      case Key::Home:
        modal_.scroll = 0;
        return;
      case Key::End:
        modal_.scroll = 100000;
        return;
      case Key::Char:
        if (event.ch == L'q' || event.ch == L'Q') modal_ = ModalState{};
        return;
      default:
        return;
    }
  }

  if (modal_.kind == ModalKind::Kill || modal_.kind == ModalKind::Suspend) {
    if (modal_.kind == ModalKind::Kill && modal_.typedRequired &&
        !modal_.blocked) {
      if (event.key == Key::Enter) {
        confirmKill();
        return;
      }
      if (event.key == Key::Backspace) {
        if (!modal_.input.empty()) modal_.input.pop_back();
        return;
      }
      if (event.key == Key::Char && isPrintable(event.ch) &&
          modal_.input.size() < 16) {
        modal_.input.push_back(static_cast<wchar_t>(std::towupper(event.ch)));
      }
      return;
    }

    if (event.key == Key::Char) {
      if (event.ch == L'y' || event.ch == L'Y') {
        if (modal_.kind == ModalKind::Kill) {
          confirmKill();
        } else {
          confirmSuspend();
        }
        return;
      }
      if (event.ch == L'n' || event.ch == L'N') {
        modal_ = ModalState{};
        return;
      }
    }
  }
}
