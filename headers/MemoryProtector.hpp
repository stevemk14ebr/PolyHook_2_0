//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "headers/Enums.hpp"

#include <cstdint>
#include <optional>
namespace PLH {

	template<typename Architecture>
	class MemoryProtector
	{
	public:
		MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot) {
			m_address = address;
			m_length = length;

			m_origProtection = archImp.protect(address, length, TranslateProtection(prot));
		}

		PLH::Maybe<PLH::ProtFlag> originalProt() {
			return m_origProtection;
		}

		~MemoryProtector() {
			if (!m_origProtection || m_origProtection.unwrap() == PLH::ProtFlag::UNSET)
				return;

			archImp.protect(m_address, m_length, TranslateProtection(m_origProtection.unwrap()));
		}

	private:
		Architecture archImp;

		std::optional<PLH::ProtFlag> m_origProtection;

		uint64_t m_address;
		uint64_t m_length;
	};

}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP