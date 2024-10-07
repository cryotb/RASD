#include "inc/include.h"

/*
*   Allocates a small RWX stub and writes a shellcode into it for final execution.
*    Said shellcode will just do a CALL on given address (lpFunction), which means it will call it from unbacked memory.
*
*   This can be useful to simulate calls from manually mapped cheats, etc.
*/
BOOLEAN tools::make_call(LPVOID lpFunction)
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
bool tools::is_code_within_legitimate_memory_region(DWORD_PTR rip)
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
