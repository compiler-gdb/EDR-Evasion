#include <iostream>
#include <iomanip>
#include <windows.h>

// 3개 모듈 import.
import Auditor.Core;
import Auditor.PE;
import Auditor.Syscall;

int main() {
    std::cout << "[+] EDR Evasion Auditor - Integration Testing...\n\n";

    // 1. Core 검증: UnhookEngine 객체 생성 (내부적으로 clean ntdll 매핑)
    // (기존 구조가 class라면 인스턴스 생성, namespace라면 변수 호출로 맞추기)
    Auditor::UnhookEngine engine;

    void* cleanNtdllBase = engine.GetCleanBaseAddress();

    if (!cleanNtdllBase) {
        std::cerr << "[-] Error: Failed to map clean ntdll.dll from disk.\n";
        return 1;
    }
    std::cout << "[+] 1. Core Module OK (Clean ntdll mapped at: 0x" << cleanNtdllBase << ")\n";

    // 2. PE 검증: 깨끗한 ntdll에서 NtOpenProcess의 주소 구하기
    const char* targetFunction = "NtOpenProcess";
    void* funcAddress = Auditor::PE::GetFunctionAddressFromEAT(cleanNtdllBase, targetFunction);

    if (!funcAddress) {
        std::cerr << "[-] Error: Failed to find " << targetFunction << " from EAT.\n";
        return 1;
    }
    std::cout << "[+] 2. PE Module OK (Found " << targetFunction << " at: 0x" << funcAddress << ")\n";

    // 3. Syscall 검증: 기계어 파싱하여 시스콜 번호(SSN) 추출하기 (Hell's Gate)
    WORD ssn = Auditor::Syscall::GetSyscallNumber(funcAddress);

    if (ssn == 0) {
        std::cerr << "[-] Error: Failed to extract Syscall Number. Opcode pattern mismatched!\n";
        return 1;
    }

    // 성공 시 16진수 포맷 출력
    std::cout << "[+] 3. Syscall Module OK (Extracted SSN: 0x"
        << std::setw(4) << std::setfill('0') << std::hex << ssn << ")\n\n";

    std::cout << "[+] All modules are beautifully synchronized! Ready for Assembly phase.\n";
    return 0;
}