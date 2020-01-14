#include <Windows.h>
#include "IATPatcher.h"

typedef int(WINAPI *MyMsgBox)(HWND,LPCSTR,LPCSTR,UINT);

void __fastcall HookedMsgBox(HWND, LPCSTR, LPCSTR, UINT);

int main()
{
	// Creating an object
	IATPatcher OurModule;

	// Calling messagebox
	MessageBoxA(NULL, "OriginalMessageBox", "Test", MB_ICONINFORMATION);

	// Getting addresses for our replace target and hook function
	PROC MsgBoxAddress = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
	PROC MsgBoxHooked = reinterpret_cast<PROC>(&HookedMsgBox);

	// Fast patching, function returns when the first match was replaced
	OurModule.QuickPatchIAT(&MsgBoxAddress, &MsgBoxHooked);

	// Reads the whole module and replaces all matchings (used when the target is packed with something)
	OurModule.FullModulePatchIAT(&MsgBoxAddress, &MsgBoxHooked);
	
	// Calling the same messagebox as at the begining and watch the result
	MessageBoxA(NULL, "OriginalMessageBox", "Test", MB_ICONINFORMATION);

	return 0;
}

// Our hook function
void __fastcall HookedMsgBox(HWND hwnd, LPCSTR caption, LPCSTR text, UINT type)
{
	MyMsgBox trythis = reinterpret_cast<MyMsgBox>(GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"));
	trythis(hwnd, "I hooked you", "Azaza", MB_ICONERROR);
}