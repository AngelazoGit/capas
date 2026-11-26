// Sustituto de unrar/isnt.cpp SOLO para compilación cruzada a Windows desde
// Linux/macOS: unrar_sys decide con cfg(windows) del anfitrión y en ese caso no
// compila isnt.cpp. Mismas firmas (enlace C++) y mismo significado.
#include <windows.h>

typedef LONG(WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);

static void version_windows(DWORD &mayor, DWORD &menor, DWORD &build) {
  mayor = 10; menor = 0; build = 19041;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == NULL) return;
  RtlGetVersionFn f = (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion");
  RTL_OSVERSIONINFOW v;
  ZeroMemory(&v, sizeof(v));
  v.dwOSVersionInfoSize = sizeof(v);
  if (f != NULL && f(&v) == 0) {
    mayor = v.dwMajorVersion; menor = v.dwMinorVersion; build = v.dwBuildNumber;
  }
}

// Codificación igual que WINNT_VERSION de isnt.hpp: 0x0a00 = Windows 10.
DWORD WinNT() {
  DWORD a, b, c;
  version_windows(a, b, c);
  return a * 0x100 + b;
}

bool IsWindows11OrGreater() {
  DWORD a, b, c;
  version_windows(a, b, c);
  return a > 10 || (a == 10 && c >= 22000);
}
