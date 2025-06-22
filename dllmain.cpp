#include "Extensions.h"
#include "detours.h"
#include <SubAuth.h>
#include "CDiscord.h"

//Dll Export To Allow IAT Loading
extern "C" int __declspec(dllexport) __cdecl Join() { return NULL; }

void AttachDetourHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pMove, func_MoveWindow);
    if (DetourTransactionCommit() != NO_ERROR)
    {
        exit(0);
        return;
    }
}

int __fastcall func_Send(void* soc, void* ecx, int a1, int a2) {
    try {
        UINT16 type = *(UINT16*)(a1 + 2);
        switch (type) {
        case 1086: *(UINT16*)(a1 + 2) = 10851; break;
        case 1052: *(UINT16*)(a1 + 2) = 10852; break;
        }
    }
    catch (...) {}
    return MsgSocket(soc, a1, a2);
}

int __cdecl func_Recive(int a1, int a2)
{
    switch (*(UINT16*)(a1 + 2))
    {
    default:
        break;
    }
    return MsgRecv(a1, a2);
}

void Install() {
    if (OpenConsole)
    {
        AllocConsole();
        BindCrtHandlesToStdHandles(true, true, true);
        SetConsoleTitle("Debug Console");
        HWND console = GetConsoleWindow();
        RECT r;
        GetWindowRect(console, &r);
        MoveWindow(console, r.left, r.top, 800, 600, TRUE);
    }

    // Hook packets
    AttachDetourHook();
    LPVOID AddrTqSend = reinterpret_cast<LPVOID>(0x536831);
    TQSendStub.Size = 5;
    CreateHook(AddrTqSend, func_Send, &TQSendStub);

    LPVOID AddrTqRecv = reinterpret_cast<LPVOID>(0x53557D);
    TQReceiveStub.Size = 5;
    CreateHook(AddrTqRecv, func_Recive, &TQReceiveStub);

    MsgSocket = (p_SendFunction)TQSendStub.Address;
    MsgRecv = (p_RecvFunction)TQReceiveStub.Address;
}

BOOL WINAPI ThreadProc()
{
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Install, NULL, NULL, NULL);
    return TRUE;
}

void SetConfig()
{
    char cmd[] = "Setting.exe QertPocnYSH114AAx";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
            Sleep(500);
    }
}

int __cdecl SetValueToMemory(BYTE* a1, int a2, int a3)
{
    if (a3 <= 1)
        *a1 = a2;
    else
        *(DWORD*)a1 = a2;
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        SetConfig();

        // Setup FPS
        int fps = GetPrivateProfileInt("Start", "FPS", 60, ConfigFile);
        int value = 1000 / fps;
        SetValueToMemory((BYTE*)(0x4B9F07 + 2), value, 0);
        SetValueToMemory((BYTE*)(0x4B9F10 + 2), value, 0);

        // Setup screen resolution
        INT FullScreen = GetPrivateProfileInt("Start", "FullScreen", 0, ConfigFile);
        INT ScreenWidth = GetPrivateProfileInt("Start", "ScreenWidth", 1024, ConfigFile);
        INT ScreenHeight = GetPrivateProfileInt("Start", "ScreenHeight", 768, ConfigFile);
        if (FullScreen != 0)
        {
            GetWindowRect(GetDesktopWindow(), &Rect);
            SetupGUI(Rect.right, Rect.bottom);
        }
        else SetupGUI(ScreenWidth, ScreenHeight);

        // Start hook thread
        ThreadProc();

        // Start Discord Rich Presence in background
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CDiscord::Init, NULL, 0, NULL);

        break;
    }
    case DLL_PROCESS_DETACH:
    {
        if (OpenConsole)
        {
            FreeConsole();
        }
        CDiscord::Shutdown(); // Clean up Discord presence
        break;
    }
    }
    return TRUE;
}
