//왜 PE File을 열어야 하는가?
/*
원래는 CPU가 NtOpenProcess 함수 같은 것이 메모리에 올라와 있을 때는 아래와 같은 모습입니다.
0x1000 코드 A
0x1004 코드 B
0x1008 코드 C
와 같이 동작합니다.

EDR이 훅을 걸어서 첫 줄을 지우고 자신에게 이동하게 만드는 명령어들 덮어쓰면 아래와 같은 모습이 됩니다.
0x1000 EDR JMP 0x9000 (검문소 주소로 점프)
0x1004 코드 B
0x1008 코드 C

단순히 메모리에 올라온 5byte를 읽기만 하면 이것이 EDR 솔루션에 의해 변조되었는지 알 수 없기 때문입니다.
*/

module;
#include <windows.h>
import Auditor.Types;

export namespace Auditor{

    export class UnhookEngine{
        private: //자식 클래스도 접근할 수 없습니다.
            //HANDLE: 특정 파일, 메모리, 프로세스 같은 리소스를 가리키는 식별 번호.
            HANDLE hFile = INVALID_HANDLE_VALUE;
            HANDLE hMapping = NULL;
            
            LPVOID cleanBaseAddress = nullptr;
            LPVOID hookedBaseAddress = nullptr;

            bool VerifyPEHeaders(){
                if(!cleanBaseAddress) return false;

                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanBaseAddress;
                //PIMAGE_DOS_HEADER는 포인터 자료형입니다. 
                //그 안의 데이터를 볼 때 IMAGE_DOS_HEADER 구조체로 보게 됩니다.

                if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
                //e_mafic: IMAGE_DOS_HEADER 구조체 가장 첫 줄에 있는 2byte 필드. 실행 파일이 맞다고 판단할 수 있습니다.
                // 화살표(->)는 뭐냐? 구주체의 주소를 타고 들어가서 안에 있는 멤버 변수를 가리깁니다.

                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanBaseAddress + dosHeader->e_lfanew);
                if(ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
                //e_lfanew: IMAGE_DOS_HEADER 마지막에 위치한 4byte(LONG) 필드. DOS Header 뒤에 붙는 찌꺼기 코드는 항상 다릅니다.
                //DOS Header부터 NT Header까지의  offset을 가지고 있습니다.


                return true;
            }
        public:
            UnhookEngine(){
            //클래스 이름과 완전히 동일한 이름을 가졌습니다. "생성자"라고 칭하며, 객체가 메모리에 생성될 때 최초로 딱 한 번 자동 호출
            //되어 멤버 변수들을 초기화하거나 필요한 리소스를 할당합니다.
                
                hookedBaseAddress = GetModuleHandleA("ntdll.dll"); 
                //메모리 위에 올라온 ntdll.dll의 정보. "변조되었다"가 아니라 "실행 중인 것인데, 변조되었을 수 있다."는 의도입니다.
                //GetModuleHandleA: 이미 내 프로그램 메모리에 로드된 특정 DLL의 시작주소(Base Address)를 조용히 알아내라.
                //조용히: 디스크를 건드리지 않고 로그를 남기지 않는다.

                hFile = CreateFileA(
                    //위에서 hFile은 HANDLE로 선언. 아래의 파일에 접근할 열쇠를 받아옵니다.
                    "C:\\Windows\\System32\\ntdll.dll", //파일 이름
                    GENERIC_READ,           //나의 접근 권한. 기존 로그 뒤에 이어쓰기 권한.
                    FILE_SHARE_READ,        //남의 공유 권한 설정. 다른 프로그램이 읽는 것은 허용.
                    NULL,                   //보안 속성
                    OPEN_EXISTING,          //파일이 없으면 새로 만들고, 있으면 열람.
                    FILE_ATTRIBUTE_NORMAL,  //일반 파일 속성
                    NULL                    //템플릿 파일 없음.
                );

                if(hFile == INVALID_HANDLE_VALUE){ 
                    return; //실패 시 반환 값 -1.
                }

                hMapping = CreateFileMappingA( //CreateFileA가 가져온 열쇠로 디스크 파일에 접근, 가상 메모리 규격으로 조립합니다.
                    hFile,
                    NULL,
                    PAGE_READONLY | SEC_IMAGE,
                    0,
                    0,
                    NULL
                );

                if(!hMapping){ // 실패 시 반환 값 0.
                    CloseHandle(hFile);
                    return;
                }

                cleanBaseAddress = MapViewOfFile( 
                    //CreateFileA: 커널에게 나 이 파일 쓰겠다. CreateFileMappingA: 커널 공간에 섹션 객체 만들기.
                    //MapViewOfFile: 우리 프로세스의 가상 메모리 주소에 자리를 만들어 디스크의 ntdll.dll 데이터를 그 자리에 연결(Mapping) 해줍니다.
                    hMapping, 
                    FILE_MAP_READ, 
                    0, 
                    0, 
                    0
                );

                if(!cleanBaseAddress){
                    CloseHandle(hMapping);
                    CloseHandle(hFile);
                    return;
                }

                if(!VerifyPEHeaders()){ //VerifyPEHeader의 값은 이미 Public에서 수정했습니다. 그 값으로 검사를 진행합니다.
                    
                    UnmapViewOfFile(cleanBaseAddress);
                    CloseHandle(hMapping);
                    CloseHandle(hFile);
                    
                    cleanBaseAddress = nullptr;
                    hMapping = NULL;
                    hFile = INVALID_HANDLE_VALUE;
                    
                    return;
                }
        }

        ~UnhookEngine(){ //객체가 차지하던 메모리 공간 자체를 OS에 반환
                if(cleanBaseAddress) UnmapViewOfFile(cleanBaseAddress);
                if(hMapping) CloseHandle(hMapping);
                if(hFile!=INVALID_HANDLE_VALUE) CloseHandle(hFile);
            }

        bool IsReady() const { return cleanBaseAddress != nullptr; } 
        /*const? 처음보는 위치에 있는데? -> 함수 내에서는 클래스의 멤버 변수들의 값을 수정하지 않고 읽기만 하겠다.*/

        bool UnhookFunction(const char* funcName){ //찾고자 하는 함수의 이름 입력.
            //함수 단위로 동작하도록 만든 이유
            //1. 통째로 덮어쓸 경우 크기가 메가바이트 단위. 아래를 볼 경우 코드는 32byte 단위만 일시적 수정합니다.
            //2. 우회 도구가 사용할 함수 몇 가지만 사용하도록 수정하면 됩니다.
            //3. Crash 방지. 일부 EDR은 자신들의 hook 코드가 정상 실행되지 않으면 시스템이 뻗도록 설계합니다.
            if(!IsReady()) return false;

            //디스크가 아닌 메모리에 올라온, EDR에 의해 오염되었을 가능성이 있는 함수 주소 구하기.
            BYTE* hookedFunc = (BYTE*)(GetProcAddress((HMODULE)hookedBaseAddress, funcName)); 
            //GetProcAddress: 특정 DLL의 시작 주소를 주면 그 안에 있는 특정 함수의 진짜 실행주소를 찾아라.
            //HMODULE: 현재 프로세스 메모리의 어디부터 시작했는지 나타내는 BaseAddress 자체. hookedBaseAddress는 LPVOID라서 형변환 했습니다.

            if(!hookedFunc) return false;

            //ULONG_PTR: 포인터만큼의 크기를 가지는 Unsigned Long
            ULONG_PTR offset = (BYTE*)hookedFunc - (BYTE*)hookedBaseAddress; 
            //현재 메모리의 ntdll.dll 내의 함수 주소 - ntdll.dll BaseAddress
            BYTE* cleanFunc = (BYTE*)cleanBaseAddress + offset;

            if(cleanFunc[0] != hookedFunc[0]){
                DWORD oldPermission = 0;
                //왜 DWORD여야 하는가? unsigned long입니다.

                /*
                VirualProtect{
                    권한을 변경할 메모리 영역의 시작 주소.
                    권한을 변경할 바이트 단위의 메모리 크기.
                    권한
                    변경 전의 권한을 저장할 상자.
                }
                */
                if(VirtualProtect(hookedFunc, 32, PAGE_EXECUTE_READWRITE, &oldPermission)){ 
                    //4번째 인자는 unsigned log oldPermission과 동일하나, &가 붙어서 unsigned long* oldPermission으로 이해합니다.
                    //VirtualProtect API에서 4번째 인자는 unsigned long*을 받기로 지정해놓아서 unsigned int*같은 것은 허용하지 않습니다.
                    for(int i=0; i<32; i++){
                        hookedFunc[i] = cleanFunc[i];
                    }

                    DWORD dummy = 0;
                    VirtualProtect(hookedFunc, 32, oldPermission, &dummy); //EDR의 의심을 피하기 위해 기존 권한으로 복구합니다.

                    return true;
                }
            }
            return false;
        }

    }; //class 전체 선언 마침. 세미콜론 필요.
}