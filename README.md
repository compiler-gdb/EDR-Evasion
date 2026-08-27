This project is for educational and research purposes only. It is designed to help security auditors and defenders understand EDR detection mechanisms and evaluate their organization's security posture. The author assumes no liability for any misuse or damage caused by this software.

본 프로젝트는 교육 및 연구 목적으로만 사용됩니다. 보안 감사자와 방어자가 EDR 탐지 메커니즘을 이해하고 조직의 보안 상태를 평가하는 데 도움을 주기 위해 설계되었습니다. 본 소프트웨어의 오용 또는 이로 인해 발생하는 손해에 대해 저작권자는 어떠한 책임도 지지 않습니다.

---

0.0.0 -> 0.1.0

**C++20 모듈 시스템 도입 및 에러 핸들링 구조화**

절차지향적으로 구현된 초기 프로토타입의 구조적 한계를 극복하고, 모듈 간 의존성 분리와 명시적인 예외 처리를 도입하여 확장성을 높인 버전입니다.

**모듈 분리:** 기존 코드를 Auditor.Core와 Auditor.PE 모듈 체계로 분리하여 컴파일 효율성과 캡슐화를 향상시켰습니다.

**커스텀 에러 도입:** Auditor.Types::PEError를 정의하여 파일 매핑 실패 및 DOS/NT 헤더 변조 등의 예외 상황을 명시적으로 핸들링합니다

---

0.1.0 -> 0.2.0

**수동 EAT 파싱 및 동적 시스템 콜 번호(SSN) 추출 구현**

표준 API(GetProcAddress)에 대한 의존성을 제거하고, PE 구조의 Export Address Table(EAT)을 직접 순회하여 함수 주소를 획득하도록 개선한 버전.

**수동 EAT 파싱:** GetFunctionAddressFromEAT를 구현하여 메모리상의 이름 배열, 함수 배열, 오디널 배열을 직접 매칭해 타깃 함수의 실제 RVA를 산출합니다.

**동적 SSN 추출:** 순정 함수의 오프코드 패턴(4C 8B D1 B8)을 분석하여 하드코딩 없이 System Service Number(SSN)를 동적으로 추출하는 파이프라인을 구축했습니다.

**모듈 통합 검증:** 통합 테스트(main_2.cpp)를 통해 Core, PE, Syscall 모듈 간의 유기적 연동성을 검증했습니다.

---

0.2.0 -> 0.3.0

**x64 MASM 어셈블리 연동 및 Direct Syscall PoC 완성**

C++과 x64 MASM 어셈블리를 결합하여 EDR의 후킹 길목을 완전히 건너뛰고 커널(Ring 0)로 직접 진입하는 완전한 PoC를 성립시킨 버전.

**어셈블리 스텁 설계:** x64 Calling Convention(RCX, RDX, R8, R9, 스택 오프셋 [rsp + 40])에 맞춰 인자를 정렬한 뒤 syscall 명령어를 수행하는 DirectSyscallInvoke를 구현했습니다.

**자가 후킹 모사 환경:** DestroyFunction을 통해 메모리상 NtOpenProcess를 인위적으로 오염시켜 EDR 후킹 상황을 완벽히 시뮬레이션합니다.

**우회 검증 완료:** 후킹 상태에서 표준 API 호출이 실패하는 반면, Direct Syscall을 통해 성공적으로 프로세스 핸들을 획득(ATTACK SUCCESS!)함을 실증했습니다.

---

0.3.0 -> 0.3.1

**실무 예외 처리 강화 및 런타임 안정성 고도화**

실제 운영 환경 및 비정상 입력 상황에서의 크래시를 방지하기 위해 방어적 프로그래밍 기법을 대폭 보강하고 진단 기능을 강화한 최신 버전.

**EAT 바운드 체킹:** 오디널 인덱스가 함수 총 개수를 초과하는지 검증하는 안전장치(ordinal >= exportDir->NumberOfFunctions)를 추가하여 비정상 PE 파싱으로 인한 크래시를 원천 차단했습니다.

**상세 진단 로그:** VirtualProtect 실패 시 GetLastError() 에러 코드를 출력하도록 std::cerr 예외 처리를 보강했습니다.

**안정성 검증 및 인코딩 정비:** 초기화 실패 시 즉시 종료하는 engine.IsReady() 검증 로직을 도입하고 UTF-8 콘솔 출력 인코딩을 정비했습니다.

<img width="767" height="333" alt="result" src="https://github.com/user-attachments/assets/fc7557ad-f552-4e6c-962d-866c4e5c82d2" />
