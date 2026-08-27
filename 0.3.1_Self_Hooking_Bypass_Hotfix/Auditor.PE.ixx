module;
#include <windows.h>

export module Auditor.PE;

export namespace Auditor{
    namespace PE{

        bool StringCompare(const char* str1, const char* str2){ 
                    int i=0;
                    while(str1[i]!='\0' && str2[i]!='\0'){ 
                        if(str1[i]!=str2[i]) return false; 
                        i++;
                    }
                    return str1[i] == str2[i];              
                }

        bool VerifyPEHeaders(LPVOID cleanBaseAddress){
                    if(!cleanBaseAddress) return false; 

                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanBaseAddress;
                    if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanBaseAddress + dosHeader->e_lfanew);
                    if(ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

                    return true;
                }

        BYTE* GetFunctionAddressFromEAT(LPVOID baseAddress, const char* funcName){
                    if(!baseAddress) return nullptr; 

                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader-> e_lfanew);

                    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if(exportDirRVA == 0) return nullptr;

                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress+exportDirRVA);

                    DWORD* nameArray = (DWORD*)((BYTE*)baseAddress + exportDir->AddressOfNames);        
                    DWORD* funcArray = (DWORD*)((BYTE*)baseAddress + exportDir->AddressOfFunctions);    
                    WORD* ordinalArray = (WORD*)((BYTE*)baseAddress + exportDir->AddressOfNameOrdinals);   

                    for (DWORD i=0; i< exportDir->NumberOfNames; i++){ 
                        const char* currentFuncName = (const char*)((BYTE*)baseAddress + nameArray[i]);

                        if(StringCompare(currentFuncName, funcName)){ 
                            WORD ordinal = ordinalArray[i];
                            
                            if (ordinal >= exportDir->NumberOfFunctions) return nullptr;

                            DWORD funcRVA = funcArray[ordinal];
                            return (BYTE*)baseAddress + funcRVA;
                        }
                    }
                    
                    return nullptr;
                }
    }
}