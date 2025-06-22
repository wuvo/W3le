#pragma once
#define WIN32_LEAN_AND_MEAN      
#define _CRT_SECURE_NO_WARNINGS
#define DEFAULT_PROTECTION_PORT "5550"
#define JMP_OPCODE 0xE9
#define NOP_OPCODE 0x90
#define LF(Lib, Func) (GetProcAddress(GetModuleHandle(Lib), Func))
#define SAFE_DELETE(p) { if(p) delete p; p=NULL; }

#include <ws2tcpip.h>
#include <windows.h>
#include <WinSock2.h>
#include <fcntl.h>
#include <thread>
#include <io.h>
#include <iostream>
#include <winnt.h>
#include <time.h>
#include <stdio.h>
#include <random>
#include <fstream>
#include <string>
#include <psapi.h>

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "psapi.lib")

bool OpenConsole = false;

struct tagRECT Rect;

char ConfigFile[13] = "./Config.cfg";

typedef int(__thiscall* p_SendFunction)(void* soc, int a1, int a2);
p_SendFunction MsgSocket;
typedef int(__cdecl* p_RecvFunction)(int a1, int a2);
p_RecvFunction MsgRecv;

typedef struct { LPVOID Address; size_t Size; } HookStub;

HookStub TQSendStub, TQReceiveStub;

BYTE FHeader1[] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC };
BYTE FHeader2[] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };

void LocalWriteToMemory(DWORD pAddress, void* pBuffer, int iSize)
{
	DWORD Protect = NULL;
	VirtualProtect((void*)pAddress, iSize, PAGE_EXECUTE_READWRITE, &Protect);
	WriteProcessMemory(GetCurrentProcess(), (void*)pAddress, pBuffer, iSize, NULL);
	VirtualProtect((void*)pAddress, iSize, Protect, &Protect);
}

VOID LocalWriteIntMemory(DWORD Address, int Value, int Size) {
	DWORD Protect = NULL;
	VirtualProtect((VOID*)Address, Size, PAGE_EXECUTE_READWRITE, &Protect);
	if (Size > 1) { *(INT*)Address = Value; }
	else { *(BYTE*)Address = Value; }
	VirtualProtect((VOID*)Address, Size, Protect, &Protect);
}

VOID LocalWriteFloatMemory(DWORD Address, float Value, int Size) {
	DWORD Protect = NULL;
	VirtualProtect((VOID*)Address, Size, PAGE_EXECUTE_READWRITE, &Protect);
	if (Size > 1) { *(float*)Address = Value; }
	else { *(BYTE*)Address = Value; }
	VirtualProtect((VOID*)Address, Size, Protect, &Protect);
}

VOID LocalWriteByteMemory(DWORD Address, BYTE Value, int Size) {
	DWORD Protect = NULL;
	VirtualProtect((VOID*)Address, Size, PAGE_EXECUTE_READWRITE, &Protect);
	if (Size > 1) { *(BYTE*)Address = Value; }
	else { *(BYTE*)Address = Value; }
	VirtualProtect((VOID*)Address, Size, Protect, &Protect);
}

int IsKnownHookHeader(LPVOID Address, int Default) {
	DWORD Protect;
	VirtualProtect(Address, 5, PAGE_EXECUTE_READWRITE, &Protect);
	VirtualProtect(FHeader1, 5, PAGE_EXECUTE_READWRITE, &Protect);
	VirtualProtect(FHeader2, 5, PAGE_EXECUTE_READWRITE, &Protect);
	if (memcmp(Address, &FHeader1[0], sizeof(FHeader1)) == 0) return 11;
	if (memcmp(Address, &FHeader2[0], sizeof(FHeader2)) == 0) return 5;
	return Default;
}

DWORD GetDestAddress(DWORD StartAddress, DWORD GotoAddress) {
	DWORD Address = (DWORD)((StartAddress - GotoAddress) + 4);
	return (DWORD)(0xFFFFFFFF - Address);
}

void CreateHook(LPVOID Address, LPVOID Target, HookStub* Stub) {
	DWORD Protect;
	Stub->Size = IsKnownHookHeader(Address, Stub->Size);
	PBYTE PTR = new BYTE[Stub->Size + 5];
	VirtualProtect(PTR, Stub->Size + 5, PAGE_EXECUTE_READWRITE, &Protect);
	memcpy(PTR, Address, Stub->Size);
	PTR[Stub->Size] = JMP_OPCODE;
	*((DWORD*)&PTR[Stub->Size + 1]) = GetDestAddress((DWORD)&PTR[Stub->Size], (DWORD)Address + Stub->Size);
	BYTE Patch[5];
	Patch[0] = JMP_OPCODE;
	*((DWORD*)&Patch[1]) = GetDestAddress((DWORD)Address, (DWORD)Target);
	memcpy(Address, Patch, 5);
	Stub->Address = PTR;
}

MODULEINFO GetModuleInfo(char* szModule)
{
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = GetModuleHandleA(szModule);
	if (hModule == 0)
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

DWORD FindPattern(CHAR* Pattern, CHAR* Mask) {
	MODULEINFO ModuleInfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &ModuleInfo, sizeof(MODULEINFO));
	DWORD Base = (DWORD)ModuleInfo.lpBaseOfDll;
	DWORD Size = (DWORD)ModuleInfo.SizeOfImage;
	DWORD PatternLength = strlen(Mask);
	for (DWORD I = 0; I < Size - PatternLength; I++) {
		BOOL Found = TRUE;
		for (DWORD J = 0; J < PatternLength; J++) {
			Found &= Mask[J] == '?' || Pattern[J] == *(CHAR*)(Base + I + J);
		}
		if (Found) return Base + I;
	}
	return NULL;
}

DWORD FindPattern(char* module, char* pattern, char* mask)
{
	//Get all module related information
	MODULEINFO mInfo = GetModuleInfo(module);
	//Assign our base and module size
	//Having the values right is ESSENTIAL, this makes sure
	//that we don't scan unwanted memory and leading our game to crash
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size = (DWORD)mInfo.SizeOfImage;
	//Get length for our mask, this will allow us to loop through our array
	DWORD patternLength = (DWORD)strlen(mask);

	for (DWORD i = 0; i < size - patternLength; i++) {
		bool found = true;
		for (DWORD j = 0; j < patternLength; j++) {
			//if we have a ? in our mask then we have true by default, 
			//or if the bytes match then we keep searching until finding it or not
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
		}

		//found = true, our entire pattern was found
		//return the memory addy so we can write to it
		if (found) {
			return base + i;
		}
	}

	return NULL;
}

void BindCrtHandlesToStdHandles(bool bindStdIn, bool bindStdOut, bool bindStdErr) {
	// Re-initialize the C runtime "FILE" handles with clean handles bound to "nul". We do this because it has been
	// observed that the file number of our standard handle file objects can be assigned internally to a value of -2
	// when not bound to a valid target, which represents some kind of unknown internal invalid state. In this state our
	// call to "_dup2" fails, as it specifically tests to ensure that the target file number isn't equal to this value
	// before allowing the operation to continue. We can resolve this issue by first "re-opening" the target files to
	// use the "nul" device, which will place them into a valid state, after which we can redirect them to our target
	// using the "_dup2" function.
	if (bindStdIn) {
		FILE* dummyFile;
		freopen_s(&dummyFile, "nul", "r", stdin);
	}
	if (bindStdOut) {
		FILE* dummyFile;
		freopen_s(&dummyFile, "nul", "w", stdout);
	}
	if (bindStdErr) {
		FILE* dummyFile;
		freopen_s(&dummyFile, "nul", "w", stderr);
	}

	// Redirect unbuffered stdin from the current standard input handle
	if (bindStdIn) {
		HANDLE stdHandle = GetStdHandle(STD_INPUT_HANDLE);
		if (stdHandle != INVALID_HANDLE_VALUE) {
			int fileDescriptor = _open_osfhandle((intptr_t)stdHandle, _O_TEXT);
			if (fileDescriptor != -1) {
				FILE* file = _fdopen(fileDescriptor, "r");
				if (file != NULL) {
					int dup2Result = _dup2(_fileno(file), _fileno(stdin));
					if (dup2Result == 0) {
						setvbuf(stdin, NULL, _IONBF, 0);
					}
				}
			}
		}
	}

	// Redirect unbuffered stdout to the current standard output handle
	if (bindStdOut) {
		HANDLE stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (stdHandle != INVALID_HANDLE_VALUE) {
			int fileDescriptor = _open_osfhandle((intptr_t)stdHandle, _O_TEXT);
			if (fileDescriptor != -1) {
				FILE* file = _fdopen(fileDescriptor, "w");
				if (file != NULL) {
					int dup2Result = _dup2(_fileno(file), _fileno(stdout));
					if (dup2Result == 0) {
						setvbuf(stdout, NULL, _IONBF, 0);
					}
				}
			}
		}
	}

	// Redirect unbuffered stderr to the current standard error handle
	if (bindStdErr) {
		HANDLE stdHandle = GetStdHandle(STD_ERROR_HANDLE);
		if (stdHandle != INVALID_HANDLE_VALUE) {
			int fileDescriptor = _open_osfhandle((intptr_t)stdHandle, _O_TEXT);
			if (fileDescriptor != -1) {
				FILE* file = _fdopen(fileDescriptor, "w");
				if (file != NULL) {
					int dup2Result = _dup2(_fileno(file), _fileno(stderr));
					if (dup2Result == 0) {
						setvbuf(stderr, NULL, _IONBF, 0);
					}
				}
			}
		}
	}

	// Clear the error state for each of the C++ standard stream objects. We need to do this, as attempts to access the
	// standard streams before they refer to a valid target will cause the iostream objects to enter an error state. In
	// versions of Visual Studio after 2005, this seems to always occur during startup regardless of whether anything
	// has been read from or written to the targets or not.
	if (bindStdIn) {
		std::wcin.clear();
		std::cin.clear();
	}
	if (bindStdOut) {
		std::wcout.clear();
		std::cout.clear();
	}
	if (bindStdErr) {
		std::wcerr.clear();
		std::cerr.clear();
	}
}


int Width_Pos;
int Y_Pos;

BOOL(WINAPI* pMove)(HWND, int, int, int, int, BOOL) = MoveWindow;
BOOL __stdcall func_MoveWindow(HWND hWnd, int X, int Y, int nWidth, int nHeight, BOOL bRepaint)
{
	if (X == 574)
	{
		X = ((Width_Pos - 1024) / 2) + 574;
	}
	if (Y == Y_Pos && nWidth == Width_Pos && X == 0)
	{
		X = ((Width_Pos - 1024) / 2);
	}
	return pMove(hWnd, X, Y, nWidth, nHeight, bRepaint);
}

void SetupGUI(int Width, int Height) {

	Width_Pos = Width;
	Y_Pos = 627 + (Height - 768);

	LocalWriteIntMemory((DWORD)(0x4BC096 + 6), Width, sizeof(Width));
	LocalWriteIntMemory((DWORD)(0x4BC0A3 + 6), Height, sizeof(Height));
	LocalWriteIntMemory((DWORD)(0x4FEFF5 + 1), Width, sizeof(Width));
	LocalWriteIntMemory((DWORD)(0x4FF00C + 1), Height, sizeof(Height));

	WritePrivateProfileString("Group", "GroupRecord", "0", "ini\\DefaultGameSetup.ini");
	WritePrivateProfileString("Server", "ServerRecord", "0", "ini\\DefaultGameSetup.ini");

	WritePrivateProfileString("ScreenMode", "ScreenModeRecord", "2", "ini\\GameSetup.ini");
	WritePrivateProfileString("ScreenMode", "FullScrType", "0", "ini\\GameSetup.ini");

	char NWidth[18];
	char NHeight[18];

	sprintf(NWidth, TEXT("%d"), Width);
	sprintf(NHeight, TEXT("%d"), Height);

	WritePrivateProfileString("ScreenMode", "ScrWidth", NWidth, "ini\\GameSetup.ini");
	WritePrivateProfileString("ScreenMode", "ScrHeight", NHeight, "ini\\GameSetup.ini");

	int ScreenWidth = GetPrivateProfileInt(TEXT("0-0"), TEXT("w"), 1024, TEXT("ini\\GUI.ini"));
	int ScreenHeight = GetPrivateProfileInt(TEXT("0-0"), TEXT("h"), 768, TEXT("ini\\GUI.ini"));

	wchar_t wx[32];
	int x = (Width - 1024) / 2;
	_itow_s(x, wx, 10);

	wchar_t hy[32];
	int y = Height - 141;
	_itow_s(y, hy, 10);

	wchar_t h[32];
	_itow_s(Height, h, 10);

	wchar_t w[32];
	_itow_s(Width, w, 10);

	if (ScreenWidth != Width || ScreenHeight != Height)
	{
		WritePrivateProfileStringW(TEXT(L"0-0"), TEXT(L"w"), w, TEXT(L"ini\\GUI.ini"));
		WritePrivateProfileStringW(TEXT(L"0-0"), TEXT(L"h"), h, TEXT(L"ini\\GUI.ini"));

		WritePrivateProfileStringW(TEXT(L"0-130"), TEXT(L"x"), wx, TEXT(L"ini\\GUI.ini"));
		WritePrivateProfileStringW(TEXT(L"0-130"), TEXT(L"y"), hy, TEXT(L"ini\\GUI.ini"));
		WritePrivateProfileStringW(TEXT(L"0-130"), TEXT(L"w"), h, TEXT(L"ini\\GUI.ini"));

		x = (Width - 1024) / 2 + 260;
		_itow_s(x, wx, 10);
		WritePrivateProfileStringW(TEXT(L"0-338"), TEXT(L"x"), wx, TEXT(L"ini\\GUI.ini"));//vip_window
		x = (Width - 1024) / 2 + 560;
		_itow_s(x, wx, 10);
		WritePrivateProfileStringW(TEXT(L"0-340"), TEXT(L"x"), wx, TEXT(L"ini\\GUI.ini"));//vip_window

		x = (Width - 1024) / 2 + 400;
		_itow_s(x, wx, 10);
		WritePrivateProfileStringW(TEXT(L"0-158"), TEXT(L"x"), wx, TEXT(L"ini\\GUI.ini"));//msg_box


#pragma region [0-272] BTN_HELP
		{
			wchar_t BTN_HELP[32];
			int BTN_HELP_width = ((Width - 1024) / 2) + 110;
			_itow_s(BTN_HELP_width, BTN_HELP, 10);
			WritePrivateProfileStringW(TEXT(L"0-272"), TEXT(L"x"), BTN_HELP, TEXT(L"ini\\GUI.ini"));
			wchar_t BTN_HELP_Y[32];
			int BTN_HELP_height = Height - 105;
			_itow_s(BTN_HELP_height, BTN_HELP_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-272"), TEXT(L"y"), BTN_HELP_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-325] MENTOR
		{
			wchar_t MENTOR[32];
			int MENTOR_width = ((Width - 1024) / 2) + 165;
			_itow_s(MENTOR_width, MENTOR, 10);
			WritePrivateProfileStringW(TEXT(L"0-325"), TEXT(L"x"), MENTOR, TEXT(L"ini\\GUI.ini"));
			wchar_t MENTOR_Y[32];
			int MENTOR_Y_height = Height - 129;
			_itow_s(MENTOR_Y_height, MENTOR_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-325"), TEXT(L"y"), MENTOR_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-328] LOCK_ITEM
		{
			wchar_t LOCK_ITEM[32];
			int LOCK_ITEM_width = ((Width - 1024) / 2) + 223;
			_itow_s(LOCK_ITEM_width, LOCK_ITEM, 10);
			WritePrivateProfileStringW(TEXT(L"0-328"), TEXT(L"x"), LOCK_ITEM, TEXT(L"ini\\GUI.ini"));
			wchar_t LOCK_ITEM_Y[32];
			int LOCK_ITEM_Y_height = Height - 114;
			_itow_s(LOCK_ITEM_Y_height, LOCK_ITEM_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-328"), TEXT(L"y"), LOCK_ITEM_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-1200] SIZE_MAP
		{
			wchar_t SIZE_MAP[32];
			int SIZE_MAP_width = Width - 20;
			_itow_s(SIZE_MAP_width, SIZE_MAP, 10);
			WritePrivateProfileStringW(TEXT(L"0-1200"), TEXT(L"x"), SIZE_MAP, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-464] EVENTS
		{
			wchar_t EVENTS[32];
			int EVENTS_width = Width - 254;
			_itow_s(EVENTS_width, EVENTS, 10);
			WritePrivateProfileStringW(TEXT(L"0-464"), TEXT(L"x"), EVENTS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-1199] ZOME_MAP
		{
			wchar_t ZOME_MAP[32];
			int ZOME_MAP_width = Width - 40;
			_itow_s(ZOME_MAP_width, ZOME_MAP, 10);
			WritePrivateProfileStringW(TEXT(L"0-1199"), TEXT(L"x"), ZOME_MAP, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-304] PATH_FINDING
		{
			wchar_t PATH_FINDING[32];
			int PATH_FINDING_width = Width - 189;
			_itow_s(PATH_FINDING_width, PATH_FINDING, 10);
			WritePrivateProfileStringW(TEXT(L"0-304"), TEXT(L"x"), PATH_FINDING, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-174] TTYPE_CHAT_ZONE
		{
			wchar_t TTYPE_CHAT[32];
			int TTYPE_CHAT_height = Height - 316;
			_itow_s(TTYPE_CHAT_height, TTYPE_CHAT, 10);
			wchar_t TTYPE_CHAT_x[32];
			int TTYPE_chat_x = ((Width - 1024) / 2) + 254;
			_itow_s(TTYPE_chat_x, TTYPE_CHAT_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-174"), TEXT(L"y"), TTYPE_CHAT, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-174"), TEXT(L"x"), TTYPE_CHAT_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-145] CHAT_ZONE
		{
			wchar_t CHAT_ZONE[32];
			int CHAT_ZONE_height = Height - 71;
			_itow_s(CHAT_ZONE_height, CHAT_ZONE, 10);
			wchar_t CHAT_ZONE_x[32];
			int chat_x = ((Width - 1024) / 2) + 82;
			_itow_s(chat_x, CHAT_ZONE_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-145"), TEXT(L"y"), CHAT_ZONE, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-145"), TEXT(L"x"), CHAT_ZONE_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-289] SHOP_MALL_ICON
		{
			wchar_t SHOP_MALL_ICON[32];
			int SHOP_MALL_ICON_height = Height - 115;
			_itow_s(SHOP_MALL_ICON_height, SHOP_MALL_ICON, 10);
			WritePrivateProfileStringW(TEXT(L"0-289"), TEXT(L"y"), SHOP_MALL_ICON, TEXT(L"ini\\GUI.ini"));
			wchar_t SHOP_MALL_ICON_01[32];
			int SHOP_MALL_ICON_01_width = ((Width - 1024) / 2) + 132;
			_itow_s(SHOP_MALL_ICON_01_width, SHOP_MALL_ICON_01, 10);
			WritePrivateProfileStringW(TEXT(L"0-289"), TEXT(L"x"), SHOP_MALL_ICON_01, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-3] WINDOW_CHAT_ZONE
		{
			wchar_t WINDOW_CHAT_ZONE[32];
			int WINDOW_CHAT_ZONE_height = Height - 118;
			_itow_s(WINDOW_CHAT_ZONE_height, WINDOW_CHAT_ZONE, 10);
			wchar_t WINDOW_CHAT_x[32];
			int CHAT_x = ((Width - 1024) / 2) + 610;
			_itow_s(CHAT_x, WINDOW_CHAT_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-3"), TEXT(L"y"), WINDOW_CHAT_ZONE, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-3"), TEXT(L"x"), WINDOW_CHAT_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-141] BTN_TEAM
		{
			wchar_t BTN_TEAM_x[32];
			int TEAM_x = ((Width - 1024) / 2) + 380;
			_itow_s(TEAM_x, BTN_TEAM_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-141"), TEXT(L"x"), BTN_TEAM_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-138] BTN_OPTION
		{
			wchar_t BTN_OPTION_x[32];
			int OPTION_x = ((Width - 1024) / 2) + 327;
			_itow_s(OPTION_x, BTN_OPTION_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-138"), TEXT(L"x"), BTN_OPTION_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-191] BTN_CAPTUER
		{
			wchar_t BTN_CAPTUER[32];
			int BTN_CAPTUER_height = Height - 98;
			_itow_s(BTN_CAPTUER_height, BTN_CAPTUER, 10);
			wchar_t BTN_CAPTUER_x[32];
			int CAPTUER_x = ((Width - 1024) / 2) + 734;
			_itow_s(CAPTUER_x, BTN_CAPTUER_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-191"), TEXT(L"y"), BTN_CAPTUER, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-191"), TEXT(L"x"), BTN_CAPTUER_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-484] BTN_HIDE_GUI
		{
			wchar_t BTN_HIDE_GUI[32];
			int BTN_HIDE_GUI_height = Height - 98;
			_itow_s(BTN_HIDE_GUI_height, BTN_HIDE_GUI, 10);
			wchar_t BTN_HIDE_GUI_x[32];
			int BTN_HIDE_GUI_x_x = ((Width - 1024) / 2) + 90;
			_itow_s(BTN_HIDE_GUI_x_x, BTN_HIDE_GUI_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-484"), TEXT(L"y"), BTN_HIDE_GUI, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-484"), TEXT(L"x"), BTN_HIDE_GUI_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-140] BTN_ACTION
		{
			wchar_t BTN_ACTION[32];
			int BTN_ACTION_height = Height - 218;
			_itow_s(BTN_ACTION_height, BTN_ACTION, 10);
			wchar_t BTN_ACTION_x[32];
			int action_x = ((Width - 1024) / 2) + 574;
			_itow_s(action_x, BTN_ACTION_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-140"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-140"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-131] BTN_STATUS
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 118;//Height - 650;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-131"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-135] BTN_STATUS2
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 172;// Height - 596;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-135"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-132"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-428"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-163"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-134"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-451] BTN_STATUS3
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 148;// (673 + 62);
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-451"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-132] BTN_STATUS4
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 172;//Height - 596;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-132"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-286] BTN_STATUS5
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 83;// Height - 685;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-286"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-153] BTN_ITEMS
		{
			wchar_t y[32];
			int _y = Width - 270;
			_itow_s(_y, y, 10);
			WritePrivateProfileStringW(TEXT(L"0-153"), TEXT(L"x"), y, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-258"), TEXT(L"x"), y, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-419"), TEXT(L"x"), y, TEXT(L"ini\\GUI.ini"));

			_y = Width - 270 - 205;
			_itow_s(_y, y, 10);
			WritePrivateProfileStringW(TEXT(L"0-450"), TEXT(L"x"), y, TEXT(L"ini\\GUI.ini"));

			_y = Width - 270 - 245;
			_itow_s(_y, y, 10);
			WritePrivateProfileStringW(TEXT(L"0-431"), TEXT(L"x"), y, TEXT(L"ini\\GUI.ini"));

			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 118;//Height - 650;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-153"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-258"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-450"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-339] BTN_VIP
		{
			wchar_t BTN_VIP[32];
			int BTN_VIP_width = ((Width - 1024) / 2) + 276;
			_itow_s(BTN_VIP_width, BTN_VIP, 10);
			WritePrivateProfileStringW(TEXT(L"0-339"), TEXT(L"x"), BTN_VIP, TEXT(L"ini\\GUI.ini"));
			wchar_t BTN_VIP_Y[32];
			int BTN_VIP_Y_height = Height - 118;
			_itow_s(BTN_VIP_Y_height, BTN_VIP_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-339"), TEXT(L"y"), BTN_VIP_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-371] WIN_GROUP
		{
			wchar_t WIN_GROUP[32];
			int WIN_GROUP_width = ((Width - 1024) / 2) + 680;
			_itow_s(WIN_GROUP_width, WIN_GROUP, 10);
			WritePrivateProfileStringW(TEXT(L"0-371"), TEXT(L"x"), WIN_GROUP, TEXT(L"ini\\GUI.ini"));
			wchar_t WIN_GROUP_Y[32];
			int WIN_GROUP_y_height = Height - 188;
			_itow_s(WIN_GROUP_y_height, WIN_GROUP_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-371"), TEXT(L"y"), WIN_GROUP_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-403] BTN_ARENA
		{
			wchar_t BTN_ARENA[32];
			int BTN_ARENA_width = ((Width - 1024) / 2) + 325;
			_itow_s(BTN_ARENA_width, BTN_ARENA, 10);
			WritePrivateProfileStringW(TEXT(L"0-403"), TEXT(L"x"), BTN_ARENA, TEXT(L"ini\\GUI.ini"));
			wchar_t BTN_ARENA_Y[32];
			int BTN_ARENA_Y_height = Height - 118;
			_itow_s(BTN_ARENA_Y_height, BTN_ARENA_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-403"), TEXT(L"y"), BTN_ARENA_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-357] SWAP_CHAT
		{
			wchar_t SWAP_CHAT_Y[32];
			int SWAP_CHAT_Y_height = Height - 453;
			_itow_s(SWAP_CHAT_Y_height, SWAP_CHAT_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-357"), TEXT(L"y"), SWAP_CHAT_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-1198] SWAP_CHAT_ICON
		{
			wchar_t SWAP_CHAT_ICON_Y[32];
			int  SWAP_CHAT_ICON_height = Height - 485;
			_itow_s(SWAP_CHAT_ICON_height, SWAP_CHAT_ICON_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-1198"), TEXT(L"y"), SWAP_CHAT_ICON_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region ExpShowPos
		{
			wchar_t Exp_XPos[32];
			int Exp_XPos_width = Width / 2;
			_itow_s(Exp_XPos_width, Exp_XPos, 10);


			wchar_t AddExp_XPos[32];
			int AddExp_XPos_width = Exp_XPos_width + 90;
			_itow_s(AddExp_XPos_width, AddExp_XPos, 10);

			wchar_t Exp_YPos[32];
			int Exp_YPos_height = Height - 93;
			_itow_s(Exp_YPos_height, Exp_YPos, 10);

			WritePrivateProfileStringW(TEXT(L"ExpShowPos"), TEXT(L"Exp_XPos"), Exp_XPos, TEXT(L"ini\\info.ini"));
			WritePrivateProfileStringW(TEXT(L"ExpShowPos"), TEXT(L"Exp_YPos"), Exp_YPos, TEXT(L"ini\\info.ini"));
			WritePrivateProfileStringW(TEXT(L"ExpShowPos"), TEXT(L"AddExp_XPos"), AddExp_XPos, TEXT(L"ini\\info.ini"));
			WritePrivateProfileStringW(TEXT(L"ExpShowPos"), TEXT(L"AddExp_YPos"), Exp_YPos, TEXT(L"ini\\info.ini"));
		}
#pragma endregion
#pragma region [0-330] BTN_CPS
		{
			wchar_t BTN_ARENA[32];
			int BTN_ARENA_width = ((Width - 1024) / 2) + 380;
			_itow_s(BTN_ARENA_width, BTN_ARENA, 10);
			WritePrivateProfileStringW(TEXT(L"0-330"), TEXT(L"x"), BTN_ARENA, TEXT(L"ini\\GUI.ini"));
			wchar_t BTN_ARENA_Y[32];
			int BTN_ARENA_Y_height = Height - 118;
			_itow_s(BTN_ARENA_Y_height, BTN_ARENA_Y, 10);
			WritePrivateProfileStringW(TEXT(L"0-330"), TEXT(L"y"), BTN_ARENA_Y, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region [0-140] BTN_ACTION
		{
			wchar_t BTN_ACTION[32];
			int BTN_ACTION_height = Height - 218;
			_itow_s(BTN_ACTION_height, BTN_ACTION, 10);
			wchar_t BTN_ACTION_x[32];
			int action_x = ((Width - 1024) / 2) + 574;
			_itow_s(action_x, BTN_ACTION_x, 10);
			WritePrivateProfileStringW(TEXT(L"0-140"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-140"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-274"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-274"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-360"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-360"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-367"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-421"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-421"), TEXT(L"x"), BTN_ACTION_x, TEXT(L"ini\\GUI.ini"));

			BTN_ACTION_height = Height - 248;
			_itow_s(BTN_ACTION_height, BTN_ACTION, 10);
			WritePrivateProfileStringW(TEXT(L"0-367"), TEXT(L"y"), BTN_ACTION, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
#pragma region ArrowShowOffset
		{
			wchar_t x[32];
			int p_x = ((Width_Pos - 1024) / 2) + 105;
			_itow_s(p_x, x, 10);
			WritePrivateProfileStringW(TEXT(L"ArrowShowOffset"), TEXT(L"OffsetX"), x, TEXT(L"ini\\info.ini"));
		}
#pragma endregion
		{
			wchar_t BTN_STATUS[32];
			int BTN_STATUS_height = 118;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-345"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			BTN_STATUS_height = 263;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-345"), TEXT(L"x"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));

			BTN_STATUS_height = 150;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-346"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));

			BTN_STATUS_height = Height - 190;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-383"), TEXT(L"y"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));

			BTN_STATUS_height = Width - 345;
			_itow_s(BTN_STATUS_height, BTN_STATUS, 10);
			WritePrivateProfileStringW(TEXT(L"0-346"), TEXT(L"x"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
			WritePrivateProfileStringW(TEXT(L"0-383"), TEXT(L"x"), BTN_STATUS, TEXT(L"ini\\GUI.ini"));
		}
	}
#pragma region CounterVigor
	{
		wchar_t CounterVigor[32];
		int CounterVigor_height = Height - 210;
		_itow_s(CounterVigor_height, CounterVigor, 10);
		WritePrivateProfileStringW(TEXT(L"0-383"), TEXT(L"y"), CounterVigor, TEXT(L"ini\\GUI.ini"));
		}
#pragma endregion
}