### Description

Single Visual Studio project that implements many injection techniques. This project was built to make it fast and easy to validate detection controls for injection techniques.

### Compiling

- Install Visual Studio Community 2015 and Windows 8.1 SDK [Downloads and Old SDK Archives](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive)
- If you are using Visual Studio 2017, you will need to install Windows Universal CRT SDK.
- Open vulcan.sln using Visual Studio.
- If prompted to upgrade, select "No upgrade".
- If desired, add static shellcode for calc/msgbox using the steps in the Shellcode section of this file.
- Compile by clicking the menu Build -> Batch Build. Click Select All. Click Build.

### Usage

Use vulcan_x32.exe to inject into 32 bit processes and vulcan_x64.exe to inject into 64 bit processes.

Always use a new process for injection, otherwise the process may become unstable and crash. If you need to kill all instances of a process by name, use the following:

```
taskkill /F /IM <processname.exe> /T
```

Each technique includes an example of basic usage:

```
Usage: vulcan.exe -m <method> -i <input> [<process name for injection> || <full path of process to hollow>]

Method:
  100   DLL injection via CreateRemoteThread() - vulcan_x64.exe -m 100 -i dllmain_64.dll notepad.exe
  200   DLL injection via NtCreateThreadEx() - vulcan_x64.exe -m 200 -i dllmain_64.dll notepad.exe
  300   DLL injection via QueueUserAPC() (aka APC Injection) - vulcan_x64.exe -m 300 -i dllmain_64.dll notepad.exe
  400   DLL injection via SetWindowsHookEx() -  vulcan_x64.exe -m 400 -i dllpoc_64.dll notepad.exe
  500   DLL injection via RtlCreateUserThread() - vulcan_x64.exe -m 500 -i dllmain_64.dll notepad.exe
  600   DLL injection via Code Cave SetThreadContext() - vulcan_x64.exe -m 600 -i dllmain_64.dll notepad.exe
  700   Reflective DLL injection RWX - vulcan_x64.exe -m 700 -i rdll_64.dll notepad.exe
  701   Shellcode Reflective DLL injection - vulcan_x64.exe -m 701 -i srdi_dllmain_x64.dll
  800   Shellcode injection via CreateRemoteThread() - vulcan_x64.exe -m 800 -i 2 notepad.exe
  1000  Shellcode injection via QueueUserAPC() (aka APC Injection) - vulcan_x64.exe -m 1000 -i 2 notepad.exe
  1200  Shellcode injection via RtlCreateUserThread() - vulcan_x64.exe -m 1200 -i 2 notepad.exe
  1500  Shellcode injection via EarlyBird - vulcan_x64.exe -m 1500 -i 2 notepad.exe
  1600  PE Process Hollowing via NtUnmapViewOfSection() - vulcan_x64.exe -m 1600 -i C:\windows\system32\calc.exe C:\windows\system32\notepad.exe
  2000  DotNET CLR Injection - vulcan_x64.exe -m 2000 -i "hello from c++" notepad.exe

Input Options:
        File (dll or b64-shellcode) - dll and shellcode injection
        1 - calc x86 - shellcode injection
        2 - calc x64 - shellcode injection
        3 - msgbox x86 - shellcode injection
        4 - msgbox x64 - shellcode injection
        C:\\Path\\process.exe - process hollowing
        String - dotnet CLR injection
```

### Shellcode

main.cpp includes sample shellcode for spawning calc and msgbox (x64 and x86). These can be replaced using the process below.

calc:

```
msfvenom -p windows/exec cmd=calc.exe -a x86 --platform windows > calc_x86.bin
msfvenom -p windows/x64/exec cmd=calc.exe -a x64 --platform windows > calc_x64.bin
```

msgbox:

```
msfvenom -p windows/messagebox text="hello world" -a x86 --platform windows > msgbox_x86.bin
msfvenom -p windows/x64/messagebox text="hello world" -a x64 --platform windows > msgbox_x64.bin
```

calc (exitfunc=thread):

```
msfvenom -p windows/exec cmd=calc.exe exitfunc=thread -a x86 --platform windows > calc_thread_x86.bin
msfvenom -p windows/x64/exec cmd=calc.exe exitfunc=thread -a x64 --platform windows > calc_thread_x64.bin
```

msgbox (exitfunc=thread):

```
msfvenom -p windows/messagebox text="hello world" exitfunc=thread -a x86 --platform windows > msgbox_thread_x86.bin
msfvenom -p windows/x64/messagebox text="hello world" exitfunc=thread  -a x64 --platform windows > msgbox_thread_x64.bin
```

Base64 encoded shellcode:

```
cat sc.bin |base64 -w 0 > b64_sc.bin
```

### References

- [injectAlltheThings](https://github.com/fdiskyou/injectAllTheThings)
- [Reflective DLL injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [sRDI](https://github.com/monoxgas/sRDI)
- [DotNetCLR](https://www.codeproject.com/articles/607352/injecting-net-assemblies-into-unmanaged-processes)
- [EarlyBird](https://github.com/theevilbit/injection/tree/master/EarlyBird/EarlyBird)
- [InjectPE](https://github.com/theevilbit/injection/tree/master/InjectPE/InjectPE)
