#include "inc/include.h"

SPOOF_CALL_METHOD(protected_func, do_spoof_call_test, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)

int main()
{
    printf("------( trying to call from process itself... )------\n");
    protected_func();
    printf("-----------------------------------------------------\n");

    printf("------( trying to call from RWX page... )------\n");
    tools::make_call(protected_func);
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
