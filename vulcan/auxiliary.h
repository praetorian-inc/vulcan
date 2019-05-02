/*
 * definitions for auxiliary functions
 */
DWORD findPidByName(wchar_t * pname);
VOID displayHelp();
DWORD checkOS();
DWORD getThreadID(DWORD pid);
BOOL SetSePrivilege();

FARPROC GetProcAddressR(UINT_PTR uiLibraryAddress, LPCSTR lpProcName);

char* WideStringToCharString(PCWSTR input);
wchar_t* CharStringToWideString(char *input);

