#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment (lib, "dbghelp")
#pragma comment (lib,"psapi")

#define MODULE_METHOD 1
#define DBGHELP_METHOD 2
#define FILESIZE_METHOD 3

class IATPatcher
{
public:
	IATPatcher(int value)
	{
		if (value == MODULE_METHOD)
		{
			MODULEINFO mymodule;
			GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mymodule, sizeof(MODULEINFO));
			beginaddress = reinterpret_cast<uintptr_t>(mymodule.lpBaseOfDll);
			endaddress = beginaddress + mymodule.SizeOfImage;
		}
		else if (value == DBGHELP_METHOD)
		{
			ULONG size;
			beginaddress = reinterpret_cast<uintptr_t>(ImageDirectoryEntryToData(GetModuleHandleA(NULL), TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &size));
			endaddress = beginaddress + size;
		}
		else if (value == FILESIZE_METHOD)
		{
			char FilePath[MAX_PATH];
			GetModuleFileNameA(NULL, FilePath, MAX_PATH);
			HANDLE hFile = CreateFileA(FilePath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
			DWORD size = GetFileSize(hFile, &size);
			beginaddress = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
			endaddress = beginaddress + size;
		}
	}

	IATPatcher(const char* ModuleName, int value)
	{
		if (value == MODULE_METHOD)
		{
			MODULEINFO mymodule;
			GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(ModuleName), &mymodule, sizeof(MODULEINFO));
			beginaddress = reinterpret_cast<uintptr_t>(mymodule.lpBaseOfDll);
			endaddress = beginaddress + mymodule.SizeOfImage;
		}
		else if (value == DBGHELP_METHOD)
		{
			ULONG size;
			beginaddress = reinterpret_cast<uintptr_t>(ImageDirectoryEntryToData(GetModuleHandleA(ModuleName), TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &size));
			endaddress = beginaddress + size;
		}
		else if (value == FILESIZE_METHOD)
		{
			char FilePath[MAX_PATH];
			GetModuleFileNameA(GetModuleHandleA(ModuleName), FilePath, MAX_PATH);
			HANDLE hFile = CreateFileA(FilePath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
			DWORD size = GetFileSize(hFile, &size);
			beginaddress = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
			endaddress = beginaddress + size;
		}
	}

	bool __cdecl QuickPatchIAT(PROC* Original, PROC* New)
	{
		for (uintptr_t temp = beginaddress; temp < (endaddress - sizeof(PROC)); temp += sizeof(PROC))
		{
			if (memcmp((void*)temp, (void*)Original, sizeof(PROC)) == 0)
			{
				VirtualProtect((void*)temp, 1, PAGE_EXECUTE_READWRITE, &protection);
				memcpy((void*)temp, (void*)New, sizeof(PROC));
				VirtualProtect((void*)temp, 1, protection, &protection);
				return true;
			}
		}

		return false;
	}

	bool __cdecl FullModulePatchIAT(PROC* Original, PROC* New)
	{
		bool IsPatched = false;

		for (uintptr_t temp = beginaddress; temp < (endaddress - sizeof(PROC)); temp+=sizeof(PROC))
		{
			if (memcmp((void*)temp, (void*)Original, sizeof(PROC)) == 0)
			{
				IsPatched = true;
				VirtualProtect((void*)temp, 1, PAGE_EXECUTE_READWRITE, &protection);
				memcpy((void*)temp, (void*)New, sizeof(PROC));
				VirtualProtect((void*)temp, 1, protection, &protection);
			}
		}

		return IsPatched;
	}
private:
	uintptr_t beginaddress = 0, endaddress = 0;
	DWORD protection = NULL;
};