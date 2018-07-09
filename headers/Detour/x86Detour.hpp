//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include <sstream>
#include <algorithm>
#include <functional>
using namespace std::placeholders;

#include "headers/Detour/ADetour.hpp"
#include "headers/Enums.hpp"
#include "headers/Instruction.hpp"
#include "headers/ADisassembler.hpp"
#include "headers/ErrorLog.hpp"
#include "headers/MemProtector.hpp"

namespace PLH {

class x86Detour : public Detour
{
public:
	x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis);

	x86Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis);

	virtual bool hook() override;

	virtual bool unHook() override;

    Mode getArchType() const;

    insts_t makeJmp(const uint64_t address, const uint64_t destination) const;

	uint8_t getJmpSize() const;
private:
	template<typename MakeJmpFn>
	std::optional<insts_t> makeTrampoline(insts_t& prologue, const uint64_t roundProlSz, const uint8_t jmpSz, MakeJmpFn makeJmp);
};

template<typename MakeJmpFn>
std::optional<PLH::insts_t> PLH::x86Detour::makeTrampoline(insts_t& prologue, const uint64_t roundProlSz, const uint8_t jmpSz, MakeJmpFn makeJmp)
{
	assert(prologue.size() > 0);
	const uint64_t prolStart = prologue.front().getAddress();

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works**/
	uint8_t neededEntryCount = 5;
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;
	do {
		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
			neededEntryCount = (uint8_t)instsNeedingEntry.size();
		}

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(roundProlSz + jmpSz + jmpSz * neededEntryCount);
		m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

		int64_t delta = m_trampoline - prolStart;

		buildRelocationList(prologue, roundProlSz, delta, instsNeedingEntry, instsNeedingReloc);
	} while (instsNeedingEntry.size() > neededEntryCount);

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + roundProlSz;
	{
		auto jmpToProl = makeJmp(jmpToProlAddr, prologue.front().getAddress() + roundProlSz);
		m_disasm.writeEncoding(jmpToProl);
	}

	uint64_t jmpTblStart = jmpToProlAddr + jmpSz;
	PLH::insts_t jmpTblEntries = relocateTrampoline(prologue, jmpTblStart, delta, jmpSz, makeJmp, instsNeedingReloc, instsNeedingEntry);
	if (jmpTblEntries.size() > 0)
		return jmpTblEntries;
	else
		return std::nullopt;
}
}
#endif //POLYHOOK_2_X86DETOUR_HPP
