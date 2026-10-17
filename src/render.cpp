#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "app.h"
#include "console.h"
#include "risk.h"
#include "screen.h"
#include "util.h"

namespace {

struct UiLine {
  std::wstring text;
  Style style;
};

struct Columns {
  int pid = 5;
  int proc = 12;
  int down = 40;  // right edge of the DOWN value
  int up = 52;    // right edge of the UP value
  int tcp = 59;
  int udp = 64;
  int sess = 70;
  int risk = 74;
  int procWidth = 23;
};

Columns columnsFor(int w) {
  Columns c;
  c.risk = w - 7;
  c.sess = c.risk - 5;
  c.udp = c.sess - 5;
  c.tcp = c.udp - 5;
  c.up = c.tcp - 12;
  c.down = c.up - 13;
  c.procWidth = std::max(10, c.down - 4 - c.proc);
  return c;
}

void addLine(std::vector<UiLine>& out, std::wstring text, Style style = sty::text) {
  out.push_back({std::move(text), style});
}

void addWrapped(std::vector<UiLine>& out, const std::wstring& text, Style style,
                int width) {
  for (const std::wstring& line : wrapTextLines(text, width)) {
    out.push_back({line, style});
  }
}

void addPrefixed(std::vector<UiLine>& out, const std::wstring& prefix,
                 const std::wstring& text, Style style, int width) {
  std::vector<std::wstring> lines =
      wrapTextLines(text, std::max(4, width - textWidth(prefix)));
  for (size_t i = 0; i < lines.size(); ++i) {
    out.push_back({(i == 0 ? prefix : std::wstring(static_cast<size_t>(textWidth(prefix)), L' ')) +
                       lines[i],
                   style});
  }
}

std::wstring endpointText(const std::wstring& addr, uint16_t port) {
  if (addr.find(L':') != std::wstring::npos) {
    return L"[" + addr + L"]:" + std::to_wstring(port);
  }
  return addr + L":" + std::to_wstring(port);
}

Style toastStyle(ToastKind kind) {
  switch (kind) {
    case ToastKind::Ok:
      return sty::green;
    case ToastKind::Warn:
      return sty::yellow;
    case ToastKind::Error:
      return sty::red;
    default:
      return sty::dim;
  }
}

}  // namespace

void App::draw(Screen& screen) {
  const int w = screen.width();
  const int h = screen.height();
  screen.clear();

  if (w < 80 || h < 24) {
    screen.put(1, 0, L"NetPilot needs a larger window (80 x 24 or more).",
               sty::warn);
    return;
  }

  drawHeader(screen, w, h);
  drawTable(screen, w, h);
  drawFooter(screen, w, h);

  if (modal_.kind != ModalKind::None) drawModal(screen, w, h);
}

void App::drawHeader(Screen& screen, int w, int h) {
  screen.fill(0, 0, w, 1, L' ', sty::titleText);
  screen.put(2, 0, L"NetPilot", sty::titleText);
  screen.put(11, 0, L"network optimizer", sty::titleSub);

  const int clockX = w - 2 - 8;
  screen.putRight(clockX, 0, 8, widen(formatLocalTime(now_).substr(11)),
                  sty::titleSub);

  const std::wstring role = elevated_ ? L"administrator" : L"standard user";
  const int roleW = textWidth(role) + 1;
  const int roleX = clockX - 3 - roleW;
  Style roleStyle = elevated_ ? sty::green : sty::yellow;
  roleStyle.bg = 24;
  if (roleX > 30) {
    screen.putRight(roleX, 0, roleW, role, roleStyle);
    screen.put(clockX - 2, 0, L"\u2502", sty::titleSub);
  }

  const std::wstring subtitle = L"network optimizer";
  if (roleX > 30 &&
      11 + textWidth(subtitle) + 2 < roleX) {
    screen.put(11, 0, subtitle, sty::titleSub);
  }

  // ---- live network rates ----------------------------------------------
  int y = 1;
  screen.put(2, y, L"LIVE", sty::accent);

  int x = 8;
  const std::wstring down = L"\u2193 " + formatRateW(downBps_);
  screen.put(x, y, down, downBps_ >= 1.0 ? sty::green : sty::dim);
  x += textWidth(down) + 3;

  const std::wstring up = L"\u2191 " + formatRateW(upBps_);
  screen.put(x, y, up, upBps_ >= 1.0 ? sty::yellow : sty::dim);
  x += textWidth(up) + 3;

  if (x + 24 < w) {
    screen.put(x, y, L"\u2502", sty::border);
    x += 2;
    const std::wstring session = L"session  \u2193 " + formatBytesW(sessionIn_) +
                                 L"   \u2191 " + formatBytesW(sessionOut_);
    screen.put(x, y, truncateToWidth(session, w - 2 - x), sty::dim);
  }

  // ---- status line ------------------------------------------------------
  y = 2;
  const int rightX = w - 2 - 16;
  const std::wstring right =
      L"updated " +
      std::to_wstring(std::max<int64_t>(0, now_ - updatedAt_)) + L"s ago";
  screen.putRight(rightX, y, 16, right, sty::dim);

  const int leftLimit = std::max(10, rightX - 4);
  if (!toast_.empty() && now_ <= toastUntil_) {
    screen.put(2, y, truncateToWidth(toast_, leftLimit - 2), toastStyle(toastKind_));
  } else {
    std::wstring info = std::to_wstring(procs_.size()) +
                        L" processes with sockets  \u00b7  sort: " +
                        std::wstring(sortName(sort_));
    if (cfg_.hideListenOnly) info += L"  \u00b7  listeners hidden (L)";
    if (cfg_.hideSystem) info += L"  \u00b7  system hidden (H)";
    screen.put(2, y, truncateToWidth(info, leftLimit - 2), sty::dim);
  }

  y = 3;
  if (!elevated_) {
    screen.put(2, y,
               truncateToWidth(
                   L"Per-app DOWN/UP need administrator rights: restart and "
                   L"accept the UAC prompt.",
                   w - 4),
               sty::yellow);
  } else {
    screen.put(2, y,
               truncateToWidth(
                   L"DOWN/UP are live per-app TCP rates; Windows exposes no "
                   L"per-app UDP byte counter.",
                   w - 4),
               sty::dim);
  }

  // ---- table box --------------------------------------------------------
  const int boxY = 4;
  const int boxH = h - 6;
  screen.box(0, boxY, w, boxH, sty::border,
             L" Network processes \u00b7 " +
                 std::to_wstring(visible_.size()) + L" shown ",
             sty::accent);
}

void App::drawTable(Screen& screen, int w, int h) {
  if (h < 16) return;

  const Columns c = columnsFor(w);
  const int headerY = 5;
  const int headerBottom = 6;
  const int rowsTop = 7;
  const int rowsBottom = h - 4;
  const int rowCount = std::max(0, rowsBottom - rowsTop + 1);

  screen.fill(1, headerY, w - 2, 1, L' ', sty::header);
  screen.putRight(c.pid, headerY, 6, L"PID", sty::header);
  screen.put(c.proc, headerY, L"PROCESS", sty::header);
  screen.putRight(c.down, headerY, 11, L"DOWN", sty::header);
  screen.putRight(c.up, headerY, 10, L"UP", sty::header);
  screen.putRight(c.tcp, headerY, 4, L"TCP", sty::header);
  screen.putRight(c.udp, headerY, 4, L"UDP", sty::header);
  screen.putRight(c.sess, headerY, 4, L"SESS", sty::header);
  screen.put(c.risk, headerY, L"RISK", sty::header);
  screen.hline(0, headerBottom, w, L'\u251C', L'\u2500', L'\u2524',
               sty::border);

  if (visible_.empty()) {
    std::wstring msg = search_.empty() ? L"No processes with network sockets."
                                       : L"No processes match \"" + search_ + L"\".";
    screen.put(std::max(2, (w - textWidth(msg)) / 2), rowsTop + 2, msg,
               sty::dim);
    screen.put(std::max(2, (w - 46) / 2), rowsTop + 4,
               L"H shows system processes, L shows listeners.", sty::dim);
    return;
  }

  if (cursor_ < scroll_) scroll_ = cursor_;
  if (cursor_ >= scroll_ + rowCount) scroll_ = cursor_ - rowCount + 1;
  scroll_ = std::clamp(scroll_, 0, std::max(0, static_cast<int>(visible_.size()) - rowCount));

  for (int row = 0; row < rowCount; ++row) {
    const int idx = scroll_ + row;
    if (idx >= static_cast<int>(visible_.size())) break;

    const ProcessInfo& p = procs_[visible_[static_cast<size_t>(idx)]];
    const bool selected = idx == cursor_;
    const bool isMarked = marked_.count({p.pid, p.createTime}) > 0;
    const int y = rowsTop + row;

    const Style base = selected ? sty::selected : sty::text;
    screen.fill(1, y, w - 2, 1, L' ', base);

    if (selected) {
      screen.put(2, y, L"\u25B8", sty::accent);
    }
    if (isMarked) {
      screen.put(3, y, L"*", sty::marked);
    }

    screen.putRight(c.pid, y, 6, std::to_wstring(p.pid),
                    selected ? base : sty::dim);

    std::wstring name = p.name;
    if (p.suspended) name += L" (paused)";
    name = truncateToWidth(name, c.procWidth);
    Style nameStyle = selected ? base : (p.suspended ? sty::yellow : sty::text);
    if (p.risk == Risk::Critical && !selected) nameStyle = sty::red;
    screen.put(c.proc, y, name, nameStyle);

    const std::wstring downText = p.statsLive ? formatRateW(p.downBps)
                                              : (elevated_ ? L"\u2014" : L"n/a");
    const std::wstring upText = p.statsLive ? formatRateW(p.upBps)
                                            : (elevated_ ? L"\u2014" : L"n/a");
    const Style downStyle = selected ? base
                            : (p.downBps >= 1.0 ? sty::green : sty::dim);
    const Style upStyle = selected ? base
                          : (p.upBps >= 1.0 ? sty::yellow : sty::dim);
    screen.putRight(c.down, y, 11, downText, downStyle);
    screen.putRight(c.up, y, 10, upText, upStyle);

    screen.putRight(c.tcp, y, 4, std::to_wstring(p.activeTcp),
                    p.activeTcp > 0 ? (selected ? base : sty::text)
                                    : (selected ? base : sty::dim));
    screen.putRight(c.udp, y, 4, std::to_wstring(p.udpCount),
                    p.udpCount > 0 ? (selected ? base : sty::text)
                                   : (selected ? base : sty::dim));
    screen.putRight(c.sess, y, 4, std::to_wstring(p.sessionId),
                    selected ? base : sty::dim);

    const std::wstring badge = riskBadge(p);
    Style riskStyle = sty::dim;
    if (p.risk == Risk::Critical) {
      riskStyle = sty::red;
    } else if (p.risk == Risk::Important) {
      riskStyle = sty::yellow;
    }
    if (selected) {
      riskStyle.bg = 238;
      riskStyle.bold = true;
    }
    screen.put(c.risk, y, badge, riskStyle);
  }
}

void App::drawFooter(Screen& screen, int w, int h) {
  const int statusY = h - 2;
  const int keysY = h - 1;

  screen.fill(0, statusY, w, 2, L' ', sty::text);

  // status line
  std::wstring status;
  Style statusStyle = sty::dim;
  if (!toast_.empty() && now_ <= toastUntil_) {
    status = toast_;
    statusStyle = toastStyle(toastKind_);
  } else {
    status = std::to_wstring(visible_.size()) + L" shown";
    if (!marked_.empty()) {
      status += L"  \u00b7  " + std::to_wstring(marked_.size()) + L" marked";
    }
    status += L"  \u00b7  sort: " + std::wstring(sortName(sort_));
    if (cfg_.hideSystem) status += L"  \u00b7  system hidden";
    if (search_.empty()) {
      status += L"  \u00b7  press / to search";
    } else {
      status += L"  \u00b7  filter: \"" + search_ + L"\"";
    }
    if (!elevated_) status += L"  \u00b7  no admin rights";
    if (options_.allowCritical) status += L"  \u00b7  CRITICAL OVERRIDE ON";
    statusStyle = options_.allowCritical ? sty::yellow : sty::dim;
  }
  screen.put(2, statusY, truncateToWidth(status, w - 4), statusStyle);

  if (searchEditing_) {
    std::wstring line = L"/ " + search_ + L"\u2588";
    screen.put(2, keysY, line, sty::accent);
    screen.put(std::min(w - 2, 4 + textWidth(line)),
               keysY, L"  Enter apply \u00b7 Esc clear", sty::dim);
    return;
  }

  std::wstring keys;
  if (w >= 150) {
    keys = L"\u2191\u2193 move  Space mark  K stop  S pause/resume  D details  "
           L"/ search  H system  L listeners  O sort  "
           L"F5 refresh  ? help  Q quit";
  } else if (w >= 112) {
    keys = L"\u2191\u2193 move  Space mark  K stop  S pause  D details  / search  "
           L"H system  L listeners  O sort  ? help  Q quit";
  } else if (w >= 92) {
    keys = L"\u2191\u2193 move  Space mark  K stop  S pause  D info  / find  "
           L"H sys  L listeners  O sort  ? help  Q quit";
  } else {
    keys = L"\u2191\u2193 Space K stop S pause D info / find H sys L listen O sort ? help Q quit";
  }
  screen.put(2, keysY, truncateToWidth(keys, w - 4), sty::dim);
}

void App::drawModal(Screen& screen, int w, int h) {
  std::vector<UiLine> lines;
  std::wstring title;
  bool scrollable = false;
  bool reserveHint = false;

  const bool fullScreen = modal_.kind == ModalKind::Details ||
                          modal_.kind == ModalKind::Help;
  int boxW = fullScreen ? w - 2 : std::min(w - 6, 88);
  boxW = std::max(44, boxW);
  const int innerW = boxW - 4;

  switch (modal_.kind) {
    case ModalKind::Kill: {
      title = L" Stop processes ";
      const size_t shown = std::min<size_t>(3, modal_.targets.size());
      addLine(lines, L"Stopping these processes will cut their network activity:",
              sty::text);
      addLine(lines, L"");
      for (size_t i = 0; i < shown; ++i) {
        const KillTarget& t = modal_.targets[i];
        std::wstring row = L"  \u2022 " + t.name + L"  (PID " +
                           std::to_wstring(t.pid) + L")";
        if (t.traffic > 0) {
          row += L"  \u00b7  " + std::to_wstring(t.traffic) + L" socket";
          if (t.traffic != 1) row += L"s";
        }
        if (t.downBps >= 1.0 || t.upBps >= 1.0) {
          row += L"  \u00b7  \u2193 " + formatRateW(t.downBps) + L"  \u2191 " +
                 formatRateW(t.upBps);
        }
        addLine(lines, truncateToWidth(row, innerW), sty::text);
      }
      if (modal_.targets.size() > shown) {
        addLine(lines, L"  \u2026 and " +
                           std::to_wstring(modal_.targets.size() - shown) +
                           L" more process(es)",
                sty::dim);
      }
      addLine(lines, L"");

      std::set<std::wstring> reasons;
      for (const KillTarget& t : modal_.targets) {
        if (!t.reason.empty()) reasons.insert(t.reason);
      }
      size_t warnings = 0;
      for (const std::wstring& reason : reasons) {
        if (warnings++ >= 2) break;
        addPrefixed(lines, L"! ", reason, sty::yellow, innerW);
      }
      std::set<std::wstring> hints;
      for (const KillTarget& t : modal_.targets) {
        const std::wstring hint = dataHeavyHint(t.name);
        if (!hint.empty()) hints.insert(hint);
      }
      for (const std::wstring& hint : hints) {
        if (warnings++ >= 3) break;
        addPrefixed(lines, L"! ", hint, sty::yellow, innerW);
      }
      if (!reasons.empty() || !hints.empty()) addLine(lines, L"");
      addWrapped(lines, L"Killing an app can lose unsaved work and interrupt "
                        L"downloads. This cannot be undone.",
                 sty::dim, innerW);
      addLine(lines, L"");

      if (modal_.blocked) {
        addWrapped(lines,
                   L"BLOCKED: this is a critical Windows process. Restart "
                   L"NetPilot with --allow-critical and type KILL if you "
                   L"really need to stop it.",
                   sty::red, innerW);
        addLine(lines, L"");
        addLine(lines, L"[N] close", sty::accent);
      } else if (modal_.typedRequired) {
        addLine(lines, L"Type KILL to confirm:", sty::yellow);
        const std::wstring typed = toLower(trimW(modal_.input));
        Style inputStyle = typed == L"kill" ? sty::green : sty::text;
        addLine(lines, L"> " + modal_.input + L"\u2588", inputStyle);
        addLine(lines, L"Enter confirm  \u00b7  Esc cancel", sty::dim);
      } else {
        addLine(lines, L"[Y] stop these processes     [N] cancel", sty::accent);
      }
      break;
    }
    case ModalKind::Suspend: {
      title = L" Suspend process ";
      const KillTarget& t = modal_.targets.front();
      addLine(lines, L"Pause " + t.name + L" (PID " + std::to_wstring(t.pid) +
                         L")?",
              sty::text);
      if (t.downBps >= 1.0 || t.upBps >= 1.0) {
        addLine(lines, L"Current rate:  \u2193 " + formatRateW(t.downBps) +
                           L"   \u2191 " + formatRateW(t.upBps),
                sty::yellow);
      }
      addLine(lines, L"");
      addWrapped(lines,
                 L"Its open connections stay in place but stop transferring. "
                 L"Apps may time out or disconnect. You can resume it from the "
                 L"list with S.",
                 sty::text, innerW);
      if (!t.reason.empty()) {
        addLine(lines, L"");
        addPrefixed(lines, L"! ", t.reason, sty::yellow, innerW);
      }
      const std::wstring hint = dataHeavyHint(t.name);
      if (!hint.empty()) {
        addPrefixed(lines, L"! ", hint, sty::yellow, innerW);
      }
      addLine(lines, L"");
      if (modal_.blocked) {
        addWrapped(lines,
                   L"BLOCKED: suspending a critical Windows component can freeze "
                   L"Windows. Choose another process.",
                   sty::red, innerW);
        addLine(lines, L"");
        addLine(lines, L"[N] close", sty::accent);
      } else {
        addLine(lines, L"[Y] suspend     [N] cancel", sty::accent);
      }
      break;
    }
    case ModalKind::Details: {
      const ProcessInfo* p = nullptr;
      for (const ProcessInfo& q : procs_) {
        if (q.pid == modal_.detailsPid &&
            q.createTime == modal_.detailsCreateTime) {
          p = &q;
          break;
        }
      }
      if (!p) {
        title = L" Process details ";
        addLine(lines, L"This process is no longer running.", sty::yellow);
        break;
      }
      scrollable = true;
      reserveHint = true;
      title = L" " + truncateToWidth(p->name, boxW - 22) + L" \u00b7 details ";
      addLine(lines, p->name + L"   PID " + std::to_wstring(p->pid),
              sty::accent);
      if (!p->path.empty()) {
        addWrapped(lines, p->path, sty::dim, innerW);
      }
      std::wstring meta;
      if (!p->company.empty()) meta += L"Publisher: " + p->company + L"   ";
      meta += L"Session: " + std::to_wstring(p->sessionId) + L"   ";
      meta += p->elevated ? L"Elevated" : L"Standard rights";
      addWrapped(lines, meta, sty::text, innerW);
      addLine(lines, p->systemUser ? L"Account: SYSTEM / service account"
                                   : L"Account: interactive user",
              sty::dim);
      if (p->suspended) {
        addLine(lines, L"State: suspended by NetPilot (press S to resume)",
                sty::yellow);
      }
      addLine(lines, L"");
      addLine(lines, std::wstring(L"Risk: ") + riskLabel(p->risk), 
              p->risk == Risk::Critical ? sty::red
                                        : (p->risk == Risk::Important ? sty::yellow
                                                                      : sty::green));
      if (!p->riskReason.empty()) addWrapped(lines, p->riskReason, sty::text, innerW);
      if (p->statsLive) {
        addLine(lines, L"Network now:  \u2193 " + formatRateW(p->downBps) +
                           L"   \u2191 " + formatRateW(p->upBps) +
                           L"   \u00b7  " + std::to_wstring(p->activeTcp) +
                           L" active TCP, " + std::to_wstring(p->udpCount) +
                           L" UDP",
                sty::green);
      } else if (!elevated_) {
        addLine(lines, L"Network now:  unavailable (per-app rates need "
                        L"administrator rights)",
                sty::dim);
      } else {
        addLine(lines, L"Network now:  not measurable (no TCP connection; "
                        L"Windows exposes no per-app UDP bytes)",
                sty::dim);
      }
      const std::wstring hint = dataHeavyHint(p->name);
      if (!hint.empty()) addWrapped(lines, hint, sty::yellow, innerW);
      addLine(lines, L"");
      addLine(lines, L"Connections (" + std::to_wstring(p->conns.size()) + L")",
              sty::accent);
      size_t connShown = 0;
      for (const ConnRow& conn : p->conns) {
        if (++connShown > 200) {
          addLine(lines, L"  \u2026 more connections not shown", sty::dim);
          break;
        }
        std::wstring row;
        if (conn.tcp) {
          row = L"  TCP  " + endpointText(conn.localAddr, conn.localPort);
          if (!conn.listening) {
            row += L"  \u2192  " +
                   endpointText(conn.remoteAddr, conn.remotePort);
          }
          row += L"   " + conn.state;
        } else {
          row = L"  UDP  " + endpointText(conn.localAddr, conn.localPort);
        }
        if (conn.stats && (conn.downBps >= 1.0 || conn.upBps >= 1.0)) {
          row += L"   \u2193 " + formatRateW(conn.downBps) + L"  \u2191 " +
                 formatRateW(conn.upBps);
        }
        addLine(lines, truncateToWidth(row, innerW),
                conn.established ? sty::text : sty::dim);
      }
      addLine(lines, L"");
      break;
    }
    case ModalKind::Help: {
      scrollable = true;
      reserveHint = true;
      title = L" NetPilot help ";
      addLine(lines, L"KEYS", sty::accent);
      addLine(lines, L"  \u2191 \u2193 / PgUp PgDn / Home End   move the selection",
              sty::text);
      addLine(lines, L"  Space                          mark a process (multi-select)",
              sty::text);
      addLine(lines, L"  K                              stop marked or selected process(es)",
              sty::text);
      addLine(lines, L"  S                              suspend / resume the selected process",
              sty::text);
      addLine(lines, L"  D / Enter                      details and connection list",
              sty::text);
      addLine(lines, L"  /                              search name, path or publisher",
              sty::text);
      addLine(lines, L"  H                              hide/show system (session 0) processes",
              sty::text);
      addLine(lines, L"  L                              hide/show listening-only processes",
              sty::text);
      addLine(lines, L"  O                              cycle sort (speed, name, PID, ...)",
              sty::text);
      addLine(lines, L"  F5 / r                         refresh now",
              sty::text);
      addLine(lines, L"  Q / Ctrl+C                     quit",
              sty::text);
      addLine(lines, L"");
      addLine(lines, L"SAFETY", sty::accent);
      addWrapped(lines,
                 L"Critical Windows components are blocked. Important or "
                 L"Microsoft-published processes require typing KILL. "
                 L"Suspend is reversible and is the safer first choice.",
                 sty::text, innerW);
      addLine(lines, L"");
      addLine(lines, L"SPEED AND VISIBILITY", sty::accent);
      addWrapped(lines,
                 L"DOWN and UP are live per-process rates summed from that "
                 L"process's TCP connections. They need administrator rights. "
                 L"Windows has no per-app UDP byte counter, so UDP-only apps "
                 L"show a dash.",
                 sty::text, innerW);
      addLine(lines, L"");
      addWrapped(lines,
                 L"Can't find a download? The default list is sorted by speed, "
                 L"so the busiest app should be on top. Press H to show system "
                 L"processes and L to show listening-only processes. A process "
                 L"that already closed all its sockets will not appear.",
                 sty::dim, innerW);
      break;
    }
    default:
      return;
  }

  // Wrap plain text lines that were added long, preserving style.
  std::vector<UiLine> wrapped;
  for (const UiLine& line : lines) {
    if (textWidth(line.text) <= innerW || line.text.empty()) {
      wrapped.push_back(line);
      continue;
    }
    for (const std::wstring& part : wrapTextLines(line.text, innerW)) {
      wrapped.push_back({part, line.style});
    }
  }

  // Small terminals: drop blank spacer lines (and, if needed, middle lines)
  // so the confirmation prompt stays visible.
  if (!fullScreen) {
    const int maxContent = std::max(5, (h - 4) - 2);
    if (static_cast<int>(wrapped.size()) > maxContent) {
      std::vector<UiLine> compact;
      for (const UiLine& line : wrapped) {
        if (!line.text.empty()) compact.push_back(line);
      }
      wrapped.swap(compact);
    }
    if (static_cast<int>(wrapped.size()) > maxContent && maxContent > 2) {
      std::vector<UiLine> trimmed;
      trimmed.insert(trimmed.end(), wrapped.begin(),
                     wrapped.begin() + (maxContent - 2));
      trimmed.push_back(wrapped[wrapped.size() - 2]);
      trimmed.push_back(wrapped.back());
      wrapped.swap(trimmed);
    }
  }

  int boxH;
  if (fullScreen) {
    boxH = h - 2;
  } else {
    boxH = std::min(h - 4, static_cast<int>(wrapped.size()) + 2);
    boxH = std::max(boxH, 7);
  }
  int contentRows = boxH - 2;
  if (reserveHint) contentRows -= 1;
  contentRows = std::max(1, contentRows);

  int scroll = modal_.scroll;
  const int maxScroll = std::max(0, static_cast<int>(wrapped.size()) - contentRows);
  scroll = std::clamp(scroll, 0, maxScroll);
  if (modal_.kind == ModalKind::Details || modal_.kind == ModalKind::Help) {
    modal_.scroll = scroll;
  }

  const int boxX = fullScreen ? 1 : std::max(1, (w - boxW) / 2);
  const int boxY = fullScreen ? 1 : std::max(1, (h - boxH) / 2);

  if (fullScreen) {
    screen.fill(0, 0, w, h, L' ', sty::modalBg);
  } else {
    screen.dimAll();
  }
  screen.fill(boxX, boxY, boxW, boxH, L' ', sty::modalBg);
  screen.box(boxX, boxY, boxW, boxH, sty::modalBorder, title, sty::modalTitle);

  for (int i = 0; i < contentRows; ++i) {
    const int idx = scroll + i;
    if (idx >= static_cast<int>(wrapped.size())) break;
    screen.put(boxX + 2, boxY + 1 + i,
               truncateToWidth(wrapped[static_cast<size_t>(idx)].text, innerW),
               wrapped[static_cast<size_t>(idx)].style);
  }

  if (scrollable && wrapped.size() > static_cast<size_t>(contentRows)) {
    if (scroll > 0) {
      screen.put(boxX + boxW - 2, boxY + 1, L"\u25B2", sty::accent);
    }
    if (scroll < maxScroll) {
      screen.put(boxX + boxW - 2, boxY + contentRows, L"\u25BC", sty::accent);
    }
  }

  if (reserveHint) {
    std::wstring hint = L"\u2191\u2193 scroll   \u00b7   Esc close   \u00b7   " +
                        std::to_wstring(scroll + 1) + L"/" +
                        std::to_wstring(std::max<size_t>(1, wrapped.size()));
    screen.put(boxX + 2, boxY + boxH - 2,
               truncateToWidth(hint, innerW), sty::dim);
  }
}
