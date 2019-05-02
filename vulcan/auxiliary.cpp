#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream> 
#include <string>

#include <psapi.h>

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

VOID displayHelp()
{
	wprintf(TEXT("Usage: vulcan.exe -m <method> -i <input> [<process name for injection> || <full path of process to hollow>]\n"));
	wprintf(TEXT("\nMethod:\n"));
	wprintf(TEXT("  100\tDLL injection via CreateRemoteThread() - vulcan_x64.exe -m 100 -i dllmain_64.dll notepad.exe\n"));
	wprintf(TEXT("  200\tDLL injection via NtCreateThreadEx() - vulcan_x64.exe -m 200 -i dllmain_64.dll notepad.exe\n"));
	wprintf(TEXT("  300\tDLL injection via QueueUserAPC() (aka APC Injection) - vulcan_x64.exe -m 300 -i dllmain_64.dll notepad.exe\n"));
	wprintf(TEXT("  400\tDLL injection via SetWindowsHookEx() -  vulcan_x64.exe -m 400 -i dllpoc_64.dll notepad.exe\n"));
	wprintf(TEXT("  500\tDLL injection via RtlCreateUserThread() - vulcan_x64.exe -m 500 -i dllmain_64.dll notepad.exe\n"));
	wprintf(TEXT("  600\tDLL injection via Code Cave SetThreadContext() - vulcan_x64.exe -m 600 -i dllmain_64.dll notepad.exe\n"));
	wprintf(TEXT("  700\tReflective DLL injection RWX - vulcan_x64.exe -m 700 -i rdll_64.dll notepad.exe\n"));
	wprintf(TEXT("  701\tShellcode Reflective DLL injection - vulcan_x64.exe -m 701 -i srdi_dllmain_x64.dll\n"));
	wprintf(TEXT("  800\tShellcode injection via CreateRemoteThread() - vulcan_x64.exe -m 800 -i 2 notepad.exe\n"));
	//wprintf(TEXT("  900\tShellcode injection via NtCreateThreadEx() - vulcan_x64.exe -m 900 -i 2 notepad.exe\n"));
	wprintf(TEXT("  1000\tShellcode injection via QueueUserAPC() (aka APC Injection) - vulcan_x64.exe -m 1000 -i 2 notepad.exe\n"));
	//wprintf(TEXT("  1100\tShellcode injection via SetWindowsHookEx() - Not supported\n"));
	wprintf(TEXT("  1200\tShellcode injection via RtlCreateUserThread() - vulcan_x64.exe -m 1200 -i 2 notepad.exe\n"));
	//wprintf(TEXT("  1300\tShellcode injection via Code Cave SetThreadContext() - vulcan_x64.exe -m 1300 -i 2 notepad.exe\n"));
	//wprintf(TEXT("  1400\tShellcode injection via Reflective DLL injection\n"));
	wprintf(TEXT("  1500\tShellcode injection via EarlyBird - vulcan_x64.exe -m 1500 -i 2 notepad.exe\n"));
	wprintf(TEXT("  1600\tPE Process Hollowing via NtUnmapViewOfSection() - vulcan_x64.exe -m 1600 -i C:\\windows\\system32\\calc.exe C:\\windows\\system32\\notepad.exe\n"));
	//wprintf(TEXT("  1700\tPE Injection - vulcan_x64.exe -m 1700 notepad.exe\n"));
	wprintf(TEXT("  2000\tDotNET CLR Injection - vulcan_x64.exe -m 2000 -i \"hello from c++\" notepad.exe\n"));
	wprintf(TEXT("\nInput Options:\n"));
	wprintf(TEXT("	File (dll or b64-shellcode) - dll and shellcode injection\n"));
	wprintf(TEXT("	1 - calc x86 - shellcode injection\n"));
	wprintf(TEXT("	2 - calc x64 - shellcode injection\n"));
	wprintf(TEXT("	3 - msgbox x86 - shellcode injection\n"));
	wprintf(TEXT("	4 - msgbox x64 - shellcode injection\n"));
	wprintf(TEXT("	C:\\\\Path\\\\process.exe - process hollowing\n"));
	wprintf(TEXT("	String - dotnet CLR injection"));
}

// from github.com/monoxgas/sRDI
FARPROC GetProcAddressR(UINT_PTR uiLibraryAddress, LPCSTR lpProcName)
{
	FARPROC fpResult = NULL;
	if (uiLibraryAddress == NULL)
		return NULL;

	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// get the VA of the modules NT Header
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// get the VA of the export directory
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);
	// get the VA for the array of addresses
	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
	// get the VA for the array of name pointers
	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
	// get the VA for the array of name ordinals
	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);
	// test if we are importing by name or by ordinal...
	if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
	{
		// import by ordinal...
		// use the import ordinal (- export ordinal base) as an index into the array of addresses
		uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

		// resolve the address for this imported function
		fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
	}
	else
	{
		// import by name...
		DWORD dwCounter = pExportDirectory->NumberOfNames;
		while (dwCounter--)
		{
			char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));
			// test if we have a match...

			if (strcmp(cpExportedFunctionName, lpProcName) == 0)
			{
				// use the functions name ordinal as an index into the array of name pointers
				uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
				// calculate the virtual address for the function
				fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
				// finish...
				break;
			}
			// get the next exported function name
			uiNameArray += sizeof(DWORD);
			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}
	return fpResult;
}

// from github.com/monoxgas/sRDI 
BOOL is64BitDLL(UINT_PTR uiLibraryAddress)
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
	return pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

void resumeAtIP(PVOID new_ip, HANDLE t_handle)
{
	CONTEXT ctx;

	// set the RIP to our shellcode
	// and resume
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(t_handle, &ctx);
#ifdef _M_AMD64
	ctx.Rip = (DWORD64)new_ip;
#else
	ctx.Eip = (DWORD32)new_ip;
#endif
	ctx.ContextFlags = CONTEXT_CONTROL;

	SetThreadContext(t_handle, &ctx);
	ResumeThread(t_handle);
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

HMODULE getBaseAddress(HANDLE p_handle)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(p_handle, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(p_handle, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR))) {
				//convert to lowercase
				for (TCHAR *p = szModName; *p; p++) {
					*p = tolower(*p);
				}

				if (strcmp("c:\\windows\\system32\\ntdll.dll", (const char*)szModName) == 0) {
					return hMods[i];
				}

			}
		}
	}

	return 0;
}



DWORD findPidByName(wchar_t * pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!_wcsicmp(procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
#ifdef _DEBUG
			wprintf(TEXT("[+] PID found: %ld\n"), pid);
#endif
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

//https://github.com/silentbreaksec/Throwback/blob/master/Throwback/Throwback.cpp
char* WideStringToCharString(PCWSTR input) 
{
	//CONVERT WIDE TO CHAR
	char *commandRes = new char[wcslen(input) + 1];
	commandRes[wcslen(input)] = '\0';
	WideCharToMultiByte(CP_ACP, 0, input, -1, commandRes, wcslen(input), NULL, NULL);
	return commandRes;
}

//https://github.com/silentbreaksec/Throwback/blob/master/Throwback/Throwback.cpp
wchar_t* CharStringToWideString(char *input)
{
	wchar_t *b64Wchar = new wchar_t[strlen(input) + 1];
	b64Wchar[strlen(input)] = '\0';
	MultiByteToWideChar(CP_ACP, 0, input, -1, b64Wchar, strlen(input));
	return b64Wchar;
}


DWORD checkOS() 
{
	OSVERSIONINFO os_version;

	os_version.dwOSVersionInfoSize = sizeof(os_version);

	if (GetVersionEx(&os_version)) 
	{
		if (os_version.dwMajorVersion == 5) 
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows XP\n"));
#endif
			return(1);
		}

		if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 2)
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows 10\n"));
#endif
			return(4);
		}

		if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 0) 
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows Vista\n"));
#endif
			return(2);
		}
		if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 1)
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows 7\n"));
#endif
			return(3);
		}
	}
	else
		wprintf(TEXT("[-] OS version detect failed.\n"));

	return(0);
}

DWORD getThreadID(DWORD pid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
							wprintf(TEXT("[-] Error: Couldn't get thread handle\n"));
						else
							return te.th32ThreadID;
					}
				}
			} while (Thread32Next(h, &te));
		}
	}

	CloseHandle(h);
	return (DWORD)0;
}

// in case you want to play with system-level processes
BOOL SetSePrivilege() 
{
	TOKEN_PRIVILEGES tp = { 0 };
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) == 0) {
				wprintf(TEXT("[-] Error: AdjustTokenPrivilege failed! %u\n"), GetLastError());

				if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
				{
					wprintf(TEXT("[*] Warning: The token does not have the specified privilege.\n"));
					return FALSE;
				}
			}
#ifdef _DEBUG
			else
				wprintf(TEXT("[+] SeDebugPrivilege Enabled.\n"));
#endif
		}

		CloseHandle(hToken);
	}
	else
		return FALSE;

	return TRUE;
}
