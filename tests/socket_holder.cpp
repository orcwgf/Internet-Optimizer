#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>

// Test fixture: opens a loopback listening socket (so NetPilot sees a process
// with network activity) and waits until killed or until the timeout.
int main(int argc, char** argv) {
  int port = argc > 1 ? std::atoi(argv[1]) : 45679;
  int seconds = argc > 2 ? std::atoi(argv[2]) : 300;

  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

  SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server == INVALID_SOCKET) return 1;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<u_short>(port));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
    return 1;
  }
  if (listen(server, SOMAXCONN) != 0) return 1;

  std::printf("READY %d\n", port);
  std::fflush(stdout);
  Sleep(static_cast<DWORD>(seconds) * 1000);
  closesocket(server);
  WSACleanup();
  return 0;
}
