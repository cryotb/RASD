#include <cinttypes>
#include <vector>
#include <map>
#include <filesystem>
#include <intrin.h>
#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>

#include "defs.h"
#include "tools.h"

/*
*   Allocates a small RWX stub and writes a shellcode into it for final execution.
*    Said shellcode will just do a CALL on given address (lpFunction), which means it will call it from unbacked memory.
* 
*   This can be useful to simulate calls from manually mapped cheats, etc.
*/
BOOLEAN MkCall(LPVOID lpFunction)
{
    // THIS SHELLCODE WILL SIMPLY CALL INTO A GIVEN FUNCTION, IN OUR CASE FROM NON-IMAGE MEMORY.
    unsigned char uShell[] =
    {
      0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x38, 0x48,
      0x8B, 0x44, 0x24, 0x40, 0x48, 0x89, 0x44, 0x24, 0x20, 0xFF,
      0x54, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x38, 0xC3
    };

    // EXTERN_C VOID MkCall(LPVOID lpFunction)
    auto tramp = reinterpret_cast<void(*)(LPVOID)>(VirtualAlloc(
        0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (tramp)
    {
        // PAGE_SIZE: 0x1000
        memset(tramp, 0, 0x1000);
        memcpy(tramp, uShell, sizeof(uShell));

        tramp(lpFunction);

        VirtualFree(tramp, 0, MEM_RELEASE);
        return TRUE;
    }

    return FALSE;
}

/*
*   Calculates if a given RIP is resident on a legitimate memory region.
*    In the context of code execution. Doing this check for data is a bit more trickier.
*/
bool is_code_within_legitimate_memory_region(DWORD_PTR rip)
{
    auto vec_modules = tools::get_process_modules((HANDLE)-1);
    std::optional<tools::module_t> opt_ldr_module = { };

    for (const auto& mod : vec_modules)
    {
        if (rip >= mod.m_base && rip < (mod.m_base + mod.m_size))
        {
            opt_ldr_module = mod;
            break;
        }
    }

    //
    // Yes, R5AC actually filters control flow more thoroughly than just checking if they are backed by LDR and whatnot.
    //  Although obviously they do not work the same way internally as what we're doing here, so you'd have to research that yourself.
    // 
    // Currently, on retail, only three regions are whitelisted. You can examine the game binary and find out what is whitelisted yourself.
    // Below list will likely become outdated at some point. Thus further research is necessary.
    //
    std::vector<tools::module_t> vec_whitelisted_modules;
    std::vector<std::string> vec_whitelisted_module_names =
    {
        "r5sw.exe",
        "ntdll.dll",
        "kernel32.dll",
    };

    for (const auto& mod : vec_modules)
    {
        for (const std::string& wlmn : vec_whitelisted_module_names)
        {
            if (mod.m_name.find(wlmn) != std::string::npos)
            {
                //printf("adding whitelisted module with name %s\n", mod.m_name.c_str());
                vec_whitelisted_modules.push_back(mod);
            }
        }
    }

    bool is_within_whitelisted_module = false;

    for (const auto& wlm : vec_whitelisted_modules)
    {
        if (rip >= wlm.m_base && rip < (wlm.m_base + wlm.m_size))
        {
            is_within_whitelisted_module = true;
            break;
        }
    }

    return is_within_whitelisted_module;
}

void protected_func()
{
    //
    //  (EXTRA) This is an extra check added by me, R5AC will not care for return address for now.
    // 

    auto retaddr = BASE_OF(_ReturnAddress());

    if (!is_code_within_legitimate_memory_region(retaddr))
    {
        printf("<<EXTRA>> [FLAG//////UNBACKED CODE EXECUTION(PRIMARY)] caller is originated within non-module memory.\n");
    }

    auto mod_caller = tools::FindProcessModuleByRIP((HANDLE)-1, retaddr);
    char caller_name[MAX_PATH];
    memset(caller_name, 0, sizeof(caller_name));

    const char* caller_fmt = nullptr;

    if (mod_caller != std::nullopt)
    {
        caller_fmt = "<<EXTRA>> [INFO] CALLED BY '%s'+0x%llx\n";
        strcpy_s(caller_name, mod_caller->m_name.c_str());
    }
    else
    {
        caller_fmt = "<<EXTRA>> [INFO] CALLED BY '%s'\n";
        sprintf_s(caller_name, "UNK_%llx", mod_caller->m_base);
    }

    printf(caller_fmt, caller_name, retaddr - mod_caller->m_base);

   //
   // <===============================================================================>
   //

    // This is where R5AC's stackwalk actually comes into play.
    PVOID backtrace[5];
    RtlZeroMemory(backtrace, sizeof(backtrace));

    // Make a CALL to RtlCaptureStackBackTrace, which will give us a backtrace buffer of the currently recorded return addresses.
    WORD num_captured = RtlCaptureStackBackTrace(1, 5, backtrace, 0);
    if (num_captured > 0)
    {
        // Loop until given range to validate legitimacy of backtrace records.
        for (WORD i = 0; i < num_captured; i++)
        {
            PVOID retaddr = backtrace[i];

            if (!is_code_within_legitimate_memory_region(BASE_OF(retaddr)))
            {
                printf("[FLAG//////UNBACKED CODE EXECUTION(SECONDARY)] suspicious record at %i (%p)\n", i, retaddr);
            }

            if( !tools::retaddr_is_call_insn(retaddr) )
            {
                // IF THIS RETURN ADDRESS HAS NOT BEEN GENERATED BY A CALL INSTRUCTION,
                //  PERFORM ADDITIONAL ANALYSIS TO DETERMINE IF A RETURN ADDRESS SPOOFER WAS POTENTIALLY USED.
                DWORD_PTR v50 = BASE_OF(retaddr);
                DWORD_PTR v57 = 2i64;
                while (*(BYTE*)(v50 - v57) != 0xFF || (((*(BYTE*)(v50 - v57 + 1) & 0x38) - 16) & 0xF7) != 0)
                {
                    if (++v57 > 7)
                    {
                        printf("[FLAG//////RETADDR SPOOFER] suspicious record at %i (%p)\n", i, retaddr);
                        break;
                    }
                }
            }
        }
    }
}

#include "spoofers/namazso/namazso.h"
#include "spoofers/beakers/beakers.h"

int main()
{
    printf("------( trying to call from process itself... )------\n");
    protected_func();
    printf("-----------------------------------------------------\n");

    printf("------( trying to call from RWX page... )------\n");
    MkCall(protected_func);
    printf("-----------------------------------------------------\n");

    printf("------( trying to call with spoof (namazso): )------\n");
    spoof_call(&namazso_gadget, protected_func);
    printf("-----------------------------------------------------\n");

    printf("------( trying to call with spoof (beakers): )------\n");
    prepare_proxy_for_module((std::uint8_t*)LoadLibraryA("kernel32.dll"));
    do_spoof_call_test(0, 0, 0, 0, 0, 0);
    printf("-----------------------------------------------------\n");
    
    return getchar();
}
