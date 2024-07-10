#pragma once

namespace tools
{
	inline bool retaddr_is_call_insn(PVOID cursor)
	{
		return *(BYTE*)(((DWORD_PTR)cursor) - 0x5) == 0xE8;
	}

	inline auto text_to_lower(const std::string& input)
	{
		auto output = std::string(input);

		std::transform(output.begin(), output.end(), output.begin(),
			[](const unsigned char c)
			{ return std::tolower(c); });

		return output;
	}

	struct module_t
	{
		std::string m_name{};
		std::string m_path{};

		std::uintptr_t m_base{};
		std::uintptr_t m_size{};

		PIMAGE_DOS_HEADER m_pDH{};
		PIMAGE_NT_HEADERS m_pNH{};
		bool m_headers_valid{};

		uint32_t m_time_stamp;
	};

	using module_list = std::vector<module_t>;
	inline auto get_process_modules(HANDLE process)
	{
		auto snapshot = HANDLE{};

		auto result = module_list();
		auto entry = MODULEENTRY32{};

		auto process_id = GetProcessId(process);

		entry.dwSize = sizeof(entry);

		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

		if (!Module32First(snapshot, &entry))
		{
			CloseHandle(snapshot);
			return result;
		}

		do
		{
			const auto module_path = std::filesystem::path(entry.szExePath);
			const auto module_name = module_path.filename().string();

			auto& info = result.emplace_back();

			info.m_name = text_to_lower(module_name);
			info.m_path = text_to_lower(module_path.string());
			info.m_base = BASE_OF(entry.modBaseAddr);
			info.m_size = BASE_OF(entry.modBaseSize);

			info.m_pDH = reinterpret_cast<PIMAGE_DOS_HEADER>(info.m_base);
			if (info.m_pDH->e_magic == IMAGE_DOS_SIGNATURE)
			{
				info.m_pNH = reinterpret_cast<PIMAGE_NT_HEADERS>(info.m_base + info.m_pDH->e_lfanew);
				if (info.m_pNH->Signature == IMAGE_NT_SIGNATURE)
				{
					info.m_headers_valid = true;

					info.m_time_stamp = info.m_pNH->FileHeader.TimeDateStamp;
				}
			}

		} while (Module32Next(snapshot, &entry));

		CloseHandle(snapshot);

		return result;
	}

	inline std::optional<module_t> FindProcessModule(HANDLE process, uintptr_t base)
	{
		auto vec_modules = get_process_modules(process);

		for (const auto& mod : vec_modules)
		{
			if (mod.m_base == base)
			{
				return mod;
			}
		}

		return { };
	}

	inline std::optional<module_t> FindProcessModule(HANDLE process, const char* name)
	{
		auto vec_modules = get_process_modules(process);

		for (const auto& mod : vec_modules)
		{
			if (mod.m_name == std::string(name))
			{
				return mod;
			}
		}

		return { };
	}

	inline std::optional<module_t> FindProcessModuleByRIP(HANDLE process, uint64_t rip)
	{
		auto vec_modules = get_process_modules(process);

		for (const auto& mod : vec_modules)
		{
			if (rip >= mod.m_base && rip < (mod.m_base + mod.m_size))
			{
				return mod;
			}
		}

		return { };
	}

	inline std::optional<module_t> FindSelfProcessModule()
	{
		auto vec_modules = get_process_modules((HANDLE)-1);

		for (const auto& mod : vec_modules)
		{
			if (mod.m_base == BASE_OF(&__ImageBase))
				return mod;
		}

		return { };
	}
}
