#pragma once

extern "C" void proxy_call_stub();
extern "C" std::uintptr_t proxy_call_returns[];

extern "C" std::size_t proxy_call_fakestack_size;
extern "C" std::uintptr_t * proxy_call_fakestack;

#define SPOOF_CALL_METHOD(method_name_pointer,method_name, return_type, ... ) template <typename... Args> static return_type method_name(Args ...args)									         \
{																												                                                                                 \
	static auto fn = (void*)method_name_pointer;																																				 \
	return reinterpret_cast< return_type (__cdecl* )(__VA_ARGS__, std::uint64_t,void*) >( proxy_call_stub )( std::forward<Args>( args )..., 0x21376969,fn );                                     \
}

inline std::uint64_t spoof_call_test(std::uint64_t x, std::uint64_t x2, std::uint64_t x3, std::uint64_t x4, std::uint64_t x5, std::uint64_t x6)
{
	return x + x2 + x3 + x4 + x5 + x6;
}

inline void prepare_proxy_for_module(std::uint8_t* module, std::uint32_t max_fakestack = 12)
{
	std::map<std::int8_t, std::vector<std::uintptr_t>> proxy_clean_returns;

	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
	auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module + dos->e_lfanew);
	auto image_size = nt->OptionalHeader.SizeOfImage;

	auto section = IMAGE_FIRST_SECTION(nt);

	MEMORY_BASIC_INFORMATION mbi;

	for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
		{
			auto address = module + section->VirtualAddress;
			while (true)
			{
				memset(&mbi, 0, sizeof(mbi));
				if (!VirtualQuery(address, &mbi, sizeof(mbi)))
					break;

				auto base_page = (std::uint8_t*)mbi.BaseAddress;

				if (mbi.Protect == PAGE_EXECUTE_READ ||
					mbi.Protect == PAGE_EXECUTE_READWRITE ||
					mbi.Protect == PAGE_EXECUTE_WRITECOPY)
				{
					for (auto i = 0u; i < (mbi.RegionSize - 0x10); i++)
					{
						//add rsp, xx
						//ret
						if (base_page[i] == 0x48 &&
							base_page[i + 1] == 0x83 &&
							base_page[i + 2] == 0xC4 &&
							base_page[i + 4] == 0xC3)
						{
							proxy_clean_returns[base_page[i + 3]].push_back(std::uintptr_t(base_page + i));
						}
					}
				}
				address = base_page + mbi.RegionSize;
				if (address >= (module + section->VirtualAddress + section->Misc.VirtualSize))
					break;
			}
		}
		section++;
	}

	//you can set proxy_call_fakestack_size = 0 to disable fakestack

	std::vector<std::int8_t> proxy_clean_returns_keys;
	proxy_clean_returns_keys.reserve(proxy_clean_returns.size());

	std::vector<std::uintptr_t> fakestack;
	fakestack.reserve(max_fakestack * 2);

	for (auto& it : proxy_clean_returns)
	{
		const auto index = (it.first / sizeof(std::uintptr_t));
		proxy_call_returns[index] = it.second.at(__rdtsc() % it.second.size());

		if (index < 10 && index % 2 == 1) //for stack align
			proxy_clean_returns_keys.push_back(it.first);
	}

	while (fakestack.size() < max_fakestack)
	{
		const auto pseudo_random_number = __rdtsc();
		const auto return_length = proxy_clean_returns_keys.at(pseudo_random_number % proxy_clean_returns_keys.size());
		const auto params = (return_length / sizeof(std::uintptr_t));
		const auto& address_array = proxy_clean_returns[return_length];
		const auto random_address = address_array.at(pseudo_random_number % address_array.size());

		fakestack.push_back(random_address);
		for (auto i = 0u; i < params; i++)
			fakestack.push_back(std::uintptr_t(module) + (__rdtsc() % image_size));
	}

	proxy_call_fakestack_size = fakestack.size();
	proxy_call_fakestack = new std::uintptr_t[fakestack.size()];
	memcpy(proxy_call_fakestack, fakestack.data(), proxy_call_fakestack_size * sizeof(std::uintptr_t));
}
