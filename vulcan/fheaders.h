// Technique 1: CreateRemoteThread
DWORD demoCreateRemoteThreadW(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoShellcodeCreateRemoteThreadW(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);

// Technique 2: NtCreateThreadEx
DWORD demoShellcodeNtCreateThreadEx(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);
DWORD demoNtCreateThreadEx(PCWSTR pszLibFile, DWORD dwProcessId);

struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

typedef NTSTATUS(WINAPI *LPFUN_NtCreateThreadEx) (
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
	);

// Technique 3: QueueUserAPC
DWORD demoQueueUserAPC(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoShellcodeQueueUserAPC(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);

// Technique 4: SetWindowsHookEx
DWORD demoSetWindowsHookEx(PCWSTR pszLibFile, DWORD dwProcessId, wchar_t *strProcName);
//TODO 
DWORD demoShellcodeSetWindowsHookEx(PCWSTR pszLibFile, DWORD dwProcessId, wchar_t *strProcName);

// Technique 5: RtlCreateUserThread
BOOL RtlCreateUserThread_Injection();
DWORD demoRtlCreateUserThread(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoShellcodeRtlCreateUserThread(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);

// Function Pointer Typedef for RtlCreateUserThread
typedef DWORD(WINAPI * pRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);

// Technique 6: thread suspend/inject/resume
#ifndef _WIN64
DWORD demoSuspendInjectResume(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoShellcodeSuspendInjectResume(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);
#endif

DWORD demoSuspendInjectResume64(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoShellcodeSuspendInjectResume64(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);

// Technique 7: Reflective DLL Injection
DWORD demoReflectiveDllInjection(PCWSTR pszLibFile, DWORD dwProcessId);

// Process Hollowing (PE file replacement)
DWORD demoNtUnmapViewOfSection(PCWSTR start_process, PCWSTR replacement_process);

// Shellcode Injection via Early Bird
DWORD demoShellcodeEarlyBird(PCWSTR start_process,PBYTE pShellcode, SIZE_T szShellcodeLength);

// Shellcode Injection via ThreadExecutionHijack - 
DWORD demoShellcodeSuspendInjectResume(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessId);

// Inject into a PE
DWORD demoInjectPE(DWORD dwProcessId);

//DWORD demoSRDI(PCWSTR pszLibFile, DWORD dwProcessId);
DWORD demoSRDI(PCWSTR pszLibFile);

DWORD demoCLR(PCWSTR pszLibFile, DWORD dwProcessId);