# NetPilot

## Made by Taka & Deepseek

A small Windows console app that shows which processes are using your network
**right now**, how fast each one is transferring, and lets you stop or pause
them with a warning for anything important.

```
  NetPilot network optimizer                                      administrator │ 22:42:00
  LIVE  ↓ 600.0 KB/s   ↑ 12.0 KB/s   │ session  ↓ 1.9 GB   ↑ 80.2 MB
  18 processes with sockets  ·  sort: speed                    updated 0s ago
  DOWN/UP are live per-app TCP rates; Windows exposes no per-app UDP byte counter.
┌─  Network processes · 18 shown ────────────────────────────────────────────────┐
│       PID PROCESS                        DOWN          UP   TCP  UDP SESS RISK   │
├──────────────────────────────────────────────────────────────────────────────────┤
│ ▸    9812 brave.exe                   600.0 KB/s    3.2 KB/s    9   11    5       │
│      7032 bun.exe                       1.2 KB/s    4.0 KB/s   11    0    5       │
│     16168 Discord.exe                   0 B/s       1.1 KB/s    3    2    5       │
│     14020 svchost.exe                     —            —        0    8    0 CRIT  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Run it

```bat
build.bat
build\bin\netpilot.exe
```

The app asks for administrator rights on startup. Accept the prompt to see
per-app speeds and to control services. If you decline, the list and global
speed still work, but per-app speeds show `n/a`.

To build without launching anything:

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

`build.bat` finds Visual Studio, configures CMake, builds and runs the tests.
The MSVC runtime is linked statically, so no Visual C++ redistributable is
needed on the target PC.

## Finding the process that is downloading

* The list is sorted by **current speed** by default, so the busiest process is
  at the top. If a download is not near the top, press `O` to cycle sorting.
* Press `H` to show **system / session-0 processes**. Background updaters and
  services often live there and were hidden by older builds.
* Press `L` to show **listening-only** processes too.
* Press `/` and search for part of the app name, path or publisher.
* Press `D` on a row to see every socket it owns, plus its current rates.
* If the app already closed all its sockets, it is not in the list. NetPilot
  cannot see a transfer that has already finished.

Windows exposes per-app byte counters for **TCP only**. A process downloading
over QUIC/UDP will appear in the list and its socket count will be visible, but
its `DOWN`/`UP` cells show a dash. This is a Windows limitation, not a bug.

## Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `PgUp` `PgDn` / `Home` `End` | Move the selection |
| `Space` | Mark/unmark a process (multi-select) |
| `K` | Stop the marked processes, or the selected one |
| `S` | Suspend / resume the selected process |
| `D` or `Enter` | Details: path, publisher, session, every socket and rate |
| `/` | Search name, path or publisher (`Enter` apply, `Esc` clear) |
| `H` | Hide/show system (session-0) processes |
| `L` | Hide/show listening-only processes |
| `O` | Cycle sort: speed, name, PID, risk, session |
| `F5` / `r` | Refresh now |
| `?` | Help |
| `Q` / `Ctrl+C` | Quit |

## Safety model

* **Critical** Windows components (`svchost.exe`, `lsass.exe`, `csrss.exe`,
  `dwm.exe`, kernel processes, protected processes and NetPilot itself) are
  **blocked**, with an explanation. `--allow-critical` lifts the block, but you
  must then type `KILL` exactly.
* **Important** processes — SYSTEM/service accounts, session-0 services,
  Microsoft-published apps and Windows-folder binaries — open a warning that
  requires typing `KILL`.
* Everything else gets a plain `[Y] stop / [N] cancel` confirmation.
* **Suspend** is the reversible option: it freezes the process; press `S` on
  the same row to resume. Suspending critical Windows components is always
  blocked because it can freeze the desktop or logon session.
* Every action re-checks the process creation time first, so a recycled PID
  cannot be hit by mistake. PID 0/4 and NetPilot's own PID are never stopped.
* Killing an app can lose unsaved work and interrupt downloads. The dialog
  says so before you commit.

## How the speed numbers work

* `LIVE` is read from the physical network adapters and includes every app,
  Windows itself and LAN traffic. It is a true total for the machine.
* `DOWN`/`UP` per process are summed from Windows TCP extended statistics
  (`GetPerTcpConnectionEStats`). NetPilot enables collection per connection
  and samples it every two seconds, so a rate appears after the first refresh.
* This requires administrator rights. UDP, loopback and non-TCP transfers are
  not counted per app.
* The `session` totals are traffic seen by NetPilot since it started, not an
  ISP bill or a quota counter.

There is no quota, window, reset, or "used data" tracking in this version.
It is a live network monitor and process manager, nothing else.

## Give it to a friend

```bat
package.bat
```

This builds Release, runs the tests, and creates:

```
dist\NetPilot\NetPilot.exe
dist\NetPilot\README.md
dist\NetPilot.zip
```

Send `NetPilot.zip`. Your friend unzips it and runs `NetPilot.exe`; Windows
shows the UAC prompt and the app starts. No installer, Python, .NET or
redistributable is required.

## Command line

```
netpilot [options]

  --allow-critical    allow stopping critical processes (typed KILL still required)
  --dump              print one 1.1s sampled snapshot and exit (no UI)
  --all               with --dump: include system and listening-only rows
  --no-elevate        do not ask for administrator rights on startup
  --config <path>     alternate config file
  -h, --help
  --version
```

`--dump` works without administrator rights (rates show `n/a`) and is handy for
logs and scripts. Set `NETPILOT_NO_ELEVATE=1` to skip the UAC prompt when
launching the UI from a script.

## Project layout

```
src/
  main.cpp       CLI, dump mode, auto-elevation
  app.cpp/.h     state machine, keys, actions, warning dialogs
  render.cpp     TUI layout, speed table, modals
  screen.cpp/.h  cell buffer with wide-character-aware ANSI output
  console.cpp/.h Windows console mode, alternate screen, input queue
  sysinfo.cpp/.h sockets, process metadata, TCP ESTATS rates, stop/suspend
  risk.cpp/.h    critical/important classification
  filter.cpp/.h  search, hides, sorting
  config.cpp/.h  INI preferences
  util.cpp/.h    formatting, UTF-16 widths, wrapping
tests/
  test_core.cpp      formatting, widths, risk rules, filters, config, screen
  socket_holder.cpp harmless listener fixture for manual UI action tests
```

Config file: `%APPDATA%\NetPilot\config.ini` (sort order and view filters only).
Delete it to reset the view.

## Limitations

* Only processes that currently own a TCP or UDP socket are listed.
* Per-app rates are TCP-only, and only after NetPilot has sampled a connection
  at least twice. A very short transfer may finish before it is measured.
* Protected processes cannot be opened even for details unless NetPilot is
  elevated. Windows may also deny termination for PPL/antimalware-protected
  services.
* The UI needs a real interactive console (Windows Terminal, conhost). Use
  `--dump` when output is redirected.
* Some antivirus products flag locally built, unsigned process-killing tools.
  Build it yourself from this short source if that happens.
* Nothing is sent over the network. There are no DNS lookups, update checks or
  telemetry calls.
