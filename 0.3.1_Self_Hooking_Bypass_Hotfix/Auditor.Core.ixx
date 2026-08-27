module;
#include <windows.h>
#include <iostream>

export module Auditor.Core;
import Auditor.PE;
import Auditor.Syscall;

export namespace Auditor {
    export class UnhookEngine{
        private: 
            HANDLE hFile = INVALID_HANDLE_VALUE;
            HANDLE hMapping = NULL;
            
            LPVOID cleanBaseAddress = nullptr;
            LPVOID hookedBaseAddress = nullptr;

     public:
            UnhookEngine(){
                hookedBaseAddress = GetModuleHandleA("ntdll.dll"); 

                hFile = CreateFileA(
                    "C:\\Windows\\System32\\ntdll.dll",
                    GENERIC_READ,          
                    FILE_SHARE_READ,        
                    NULL,                   
                    OPEN_EXISTING,          
                    FILE_ATTRIBUTE_NORMAL,  
                    NULL                    
                );

                if(hFile == INVALID_HANDLE_VALUE){ 
                    return; 
                }

                hMapping = CreateFileMappingA( 
                    hFile,
                    NULL,
                    PAGE_READONLY | SEC_IMAGE,
                    0,
                    0,
                    NULL
                );

                if(!hMapping){ 
                    CloseHandle(hFile);
                    return;
                }

                cleanBaseAddress = MapViewOfFile( 
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

                if(!Auditor::PE::VerifyPEHeaders(cleanBaseAddress)){ 
                    UnmapViewOfFile(cleanBaseAddress);
                    CloseHandle(hMapping);
                    CloseHandle(hFile);
                    
                    cleanBaseAddress = nullptr;
                    hMapping = NULL;
                    hFile = INVALID_HANDLE_VALUE;
                    
                    return;
                }
        }

        ~UnhookEngine(){ 
                if(cleanBaseAddress) UnmapViewOfFile(cleanBaseAddress);
                if(hMapping) CloseHandle(hMapping);
                if(hFile!=INVALID_HANDLE_VALUE) CloseHandle(hFile);
            }

		void* GetCleanBaseAddress() const { return cleanBaseAddress; } 
        bool IsReady() const { return cleanBaseAddress != nullptr; } 

        bool UnhookFunction(const char* funcName){ 
            if(!IsReady()) return false;

            BYTE* hookedFunc = (BYTE*)(GetProcAddress((HMODULE)hookedBaseAddress, funcName)); 
            if(!hookedFunc) return false;

            ULONG_PTR offset = (BYTE*)hookedFunc - (BYTE*)hookedBaseAddress; 
            BYTE* cleanFunc = (BYTE*)cleanBaseAddress + offset;

            if(cleanFunc[0] != hookedFunc[0]){
                DWORD oldPermission = 0;
                
                if(VirtualProtect(hookedFunc, 32, PAGE_EXECUTE_READWRITE, &oldPermission)){ 
                    for(int i=0; i<32; i++){
                        hookedFunc[i] = cleanFunc[i];
                    }

                    DWORD dummy = 0;
                    VirtualProtect(hookedFunc, 32, oldPermission, &dummy); 

                    return true;
                } else {
                    std::cerr << "[!] VirtualProtect failed. Error code: " << GetLastError() << "\n";
                }
            }
            return false;
        }
    }; 
}