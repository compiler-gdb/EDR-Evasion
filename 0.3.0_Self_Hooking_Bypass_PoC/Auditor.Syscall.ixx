module;
#include<windows.h>

export module Auditor.Syscall;
import Auditor.PE;
//import Auditor.Types;

//PE 구조체를 파싱하여 syscall 번호를 추출하는 기능을 구현합니다.
//단일 책임 원칙에 따라서 Syscall 관련 기능만 구현합니다.

//Syscall Number 추출을 목적으로 할 때는 객체를 찍어내며 메모리를 할당하고 상태를 유지할 필요가 없기 때문에 절차지향 형식으로 설계합니다.

//1. 객체지향 구조는 내부에 멤버 변수를 저장하고 그 데이터를 여러 메서드가 공유하며 상태를 변화시킬 때 의미가 있습니다.
//   하지만 void*를 입력하고 byte 몇 개를 읽고 Syscall 번호를 반환하는 단순한 기능은 상태를 유지할 필요가 없기 때문에 절차지향 구조가 더 적합합니다.

//2. EDR의 탐지를 회피하는 기능을 목적으로 하기에 코드가 메모리에 올라갔을 때의 흔적을 최소화해야 합니다. 
//   절차지향 구조는 기계어 연산만 하고 종료를 하지만 객체지향은 생성을 하기 위해 스택이나 힙 메모리를 할당해야 하고
//   함수를 호출할 때마다 눈에 보이지 않게 this 포인터(객체의 주소)가 rcx 레지스터를 통해 계속 전달됩니다.


export namespace Auditor{


	namespace Syscall {

		// GetSyscallNumber: 특정 Nt함수의 syscall 번호를 동적으로 추출합니다.
		WORD GetSyscallNumber(void* functionAddress) {
			if (!functionAddress) return 0;

			// 함수 시작 주소를 BYTE 포인터로 변환하여 opcode를 읽습니다.
			// Opcode: 컴파일러에 의해 이진수로 변환된 기계어. 프로그램 실행 시 이 기계어가 RAM 특정 구역에 차례대로 로드되며 이 기계어의 한 단위를 오프코드라고 부릅니다.
			// 왜 BYTE*로 변환했는데? 메모리 입장에서는 코드나 데이터나 모두 1byte들의 나열일 뿐이기 때문입니다.
			BYTE* opcode = (BYTE*)functionAddress;

			//순정 Syscall 함수의 패턴을 검증합니다.
			//정상적인 R3(user mode) -> R0(kernel mode) 시도 시에 아래 조건문과 같은 OS 동작들이 발생합니다.
			if(opcode[0] == 0x4c && opcode[1] == 0x8B && opcode[2] == 0xD1){  // mov r10, rcx

				// mov eax, SNN (SNN: Syscall Number이며 4byte 정수입니다.)
				//"mov eax. imm32(4byte 값)"이라는 명령어는 무조건 B8이라는 1byte 기계어로 바뀌도록 정해져 있습니다. 
				// 즉, "지금 바로 뒤에 나오는 값을 eax 레지스터에 넣어라"라고 정해진 약속입니다.
				if(opcode[3] == 0xB8){ 

					// 리틀엔디안 방식이면서 4byte 중 하위 2byte이므로 "0xB8 ?? ?? 00 00" 형태로 SNN이 옵니다.
					// opcode[4]의 주소를 가져오고 2byte WORD로 변환합니다.
					// 해당 주소를 참조 시 읽을 때의 단위를 2byte로 변환했기 때문에 opcode[4]를 지정하면 opcode[5]까지 읽습니다.
					WORD syscallNumber = *(WORD*)&opcode[4];
					return syscallNumber;
				}
			}

			// 패턴이 깨져있다면 후킹을 당했거나 Syscall 함수가 아닌 경우이므로 0을 반환합니다. 
			return 0;
		}
		// c++ 컴파일러는 함수 오버로딩을 지원하기 위해 컴파일할 때 함수 이름을 내부적으로 변형합니다. 하지만 어셈블리 파일에서는 함수 이름이 그대로 노출됩니다. 따라서 어셈블리에서 호출할 때는 함수 이름을 그대로 사용해야 합니다.
		// extern "C"를 붙이면 컴파일러가 이름을 변조하지 않고 이름을 그대로 링커에게 전달합니다.
		// NTSTATUS는 반환 타입을 지정한 것인데, 윈도우 커널이 리턴하는 표준 성공/실패 코드 형식(32bit 정수)입니다. 이 함수의 결과로서 커널의 응답(STUATUS_SUCCESS, STATUS_ACCESS_DENIED 등)을 받을 수 있습니다.
		// 인자의 마지만에 ...은 "가변인자"입니다. 뒤에 몇 개가 오든 무슨 자료형이 오든 상관없이 받아서 처리하겠다는 의미입니다. 따라서 이 함수를 호출할 때는 syscall 번호를 첫 번째 인자로 넣고, 그 뒤에 syscall 함수가 요구하는 인자들을 순서대로 넣으면 됩니다.
		extern "C" NTSTATUS DirectSyscallInvoke(DWORD ssn, ...);
		//DirectSyscallInvoke라는 함수를 사용할 것이고 그것은 다른 파일에 있다 링커에게 알려주겠다. 일단 에러 발생하지 말고 넘어가라.
		// 실제로 링커가 DirectSyscallInvoke를 봤을 때, 링커는 이 함수가 다른 파일에 정의되어 있다는 것을 알고, 그 파일을 링크할 때 해당 함수를 찾아서 연결합니다. 따라서 DirectSyscallInvoke를 호출할 때, 링커는 이 함수의 실제 구현을 찾아서 연결하게 됩니다.
	}
}