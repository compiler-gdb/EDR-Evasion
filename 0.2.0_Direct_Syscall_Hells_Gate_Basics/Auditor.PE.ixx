/*
1. GetProcAddress에서 EAT 수동 파싱으로 수정 
IMAGE_EXPORT_DIRECTORY 구조체를 파싱하여 함수의 이름 배열(AddressOfNames)을 루프로 직접 돌리며 원하는 함수의 오프셋 주소를 찾아내도록 클래스 수정.

2. 문자열 흔적 지우기
컴파일 후 우리 프로그램 바이너리 내부에 "NtOpenProcess", "NtAllocateVirtualMemory"같은 문자열이 보이면 EDR은 파일 스캔만으로 차단하게 됩니다.
해시 알고리즘 함수를 클래스에 추가합니다.
위와 같은 문자열을 무의미한 정수형 해시값으로 변환하여 EDR이 키워드 매칭만으로 탐지하게 못하도록 합니다.

3. 가변적인 syscall 전송 구축 (MASM 튜닝)

4. ntdll의 순정 함수 이름(해시)와 syscall 번호를 매핑해서 메모리에 있는 커스텀 syscall 테이블 역할을 만듭니다.
클래스 내부 해시 값과 syscall 번호를 짝지어 저장할 수 있는 구조체 배열이나 Map 형태의 저장소를 선언합니다.
클래스 생성자가 호출 될 때 디스크의 ntdll을 한 번만 스캔해서 내가 자주쓰는 핵심 Nt함수들의 syscall 번호를 테이블에 백업합니다.
그 이후, 어셈블리가 필요할때마다 번호만 꺼내 씁니다.  
*/

module;
#include <windows.h>

export module Auditor.PE;

export namespace Auditor{
    namespace PE{

        bool StringCompare(const char* str1, const char* str2){ //외부 ctrcmp 의존성을 제거하기 위한 문자 대조 함수.
                    int i=0;
                    while(str1[i]!='\0' && str2[i]!='\0'){ //null 문자는 데이터의 끝을 의미합니다. 이 뒤에 프로그램이 허용하지 않는 쓰레기 값이 들어있거나 접근하면 안 되는 구역일 수 있습니다.
                        if(str1[i]!=str2[i]) return false; //서로 문자가 다르면 false 반환
                        i++;
                    }
                    return str1[i] == str2[i];              //여기까지 왔다면 한 쪽은 문자열에 끝에 왔음을 의미합니다. while에서 NULL 바이트를 검사하기 때문입니다.
                }

        bool VerifyPEHeaders(LPVOID cleanBaseAddress){
                    if(!cleanBaseAddress) return false; 
                    //깨진 메모리나 메모리 용량 부족으로 MapViewOfFile이 NULL을 반환했는 경우 false.
                    //nullptr에 가서 e_magic을 검사하려고 하면 crash가 발생합니다.

                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanBaseAddress;
                    //PIMAGE_DOS_HEADER는 포인터 자료형입니다. 
                    //그 안의 데이터를 볼 때 IMAGE_DOS_HEADER 구조체로 보게 됩니다.

                    if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
                    //e_mafic: IMAGE_DOS_HEADER 구조체 가장 첫 줄에 있는 2byte 필드. 실행 파일이 맞다고 판단할 수 있습니다.
                    // 화살표(->)는 뭐냐? 구조체의 주소를 타고 들어가서 안에 있는 멤버 변수를 가리깁니다.

                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanBaseAddress + dosHeader->e_lfanew);
                    if(ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
                    //e_lfanew: IMAGE_DOS_HEADER 마지막에 위치한 4byte(LONG) 필드. DOS Header 뒤에 붙는 찌꺼기 코드는 항상 다릅니다.
                    //DOS Header부터 NT Header까지의 offset을 가지고 있습니다.


                    return true;
                }

        BYTE* GetFunctionAddressFromEAT(LPVOID baseAddress, const char* funcName){
                    if(!baseAddress) return nullptr; //이미 클래스에서 손상되지 않은 dll 파일인지 검사했으므로 간결

                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader-> e_lfanew);

                    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if(exportDirRVA == 0) return nullptr;
                    //OpntionalHeader: 운영체제가 이 프로그램을 올리고 실행할 때 필요한 가장 핵심적인 가이드라인입니다. ex) 메모리를 얼마나 쓸 것인가, 어디부터 시작하는가, 크기는 얼마인가.
                    //DataDirectory: OptionalHeader 구조체 맨 마지막 부분에 있는 16개짜리 크기의 배열. 실행 파일 안 중요정보(가져올 함수 목록, 내보낼 함수 목록, 아이콘 등)를 저장한 목록.
                    //IMAGE_DIRECTORY_ENTRY_EXPORT: 내보낸 함수 목록.
                    //VituralAddress: 상대 가상 주소. baseAddress에 있는 것에대한 ntHeader이므로 baseAddress 기준으로 IMAGE_DIRECTORY_ENTRY_EXPORT와의 offset을 구합니다.

                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress+exportDirRVA);

                    DWORD* nameArray = (DWORD*)((BYTE*)baseAddress + exportDir->AddressOfNames);        //AddressOfNames: DLL이 내보낸 함수 이름이 저장된 RVA가 순서대로 나열되어 있습니다. 
                    DWORD* funcArray = (DWORD*)((BYTE*)baseAddress + exportDir->AddressOfFunctions);    //이 DLL이 가진 실제 함수 기계어 코드의 RVA가 순서대로 배열로 들어가있습니다.
                    WORD* ordinalArray = (WORD*)((BYTE*)baseAddress + exportDir->AddressOfNameOrdinals);   //함수 이름 배열의 인덱스와 함수 주소 배열의 인덱스를 1:1로 매칭해주는 연결 고리 배열입니다. 작은 크기의 메모리를 사용하여 WORD를 사용합니다.
                    //baseAddress는 LPVOID이지만 텍스트처럼 보여도 16진수 숫자입니다. DWORD와 WORD를 사용한 이유입니다.
                    //숫자임에도 int*를 사용하지 않는 것은 int는 signed, DOWRD는 unsigned이기 때문입니다.


                    for (DWORD i=0; i< exportDir->NumberOfNames; i++){ 
                        //exportDir->NumberOfNames: DLL파일이 외부 프로그램에서 사용하라고 이름을 붙여서 내보내는 함수의 총 개수가 저장된 INT값입니다.

                        const char* currentFuncName = (const char*)((BYTE*)baseAddress + nameArray[i]);

                        if(StringCompare(currentFuncName, funcName)){ //ex) funcName이 NtClose인 경우.
                            WORD ordinal = ordinalArray[i];
                            //ex) NtClose = 0
                            DWORD funcRVA = funcArray[ordinal];
                            //ex) funcArray[0]
                            return (BYTE*)baseAddress + funcRVA;
                        }
                    }
                }

    }
}