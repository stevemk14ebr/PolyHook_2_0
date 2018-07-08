//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include <optional>
#include <cassert>
#include <map>

#include "headers/ADisassembler.hpp"
#include "headers/IHook.hpp"
#include "headers/Enums.hpp"
#include "headers/ErrorLog.hpp"
#include <optional>

#pragma warning(disable:4100)
#pragma warning(disable:4189)

/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

class Detour : public PLH::IHook
{
public:
	Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != 0 && fnCallback != 0);
		m_fnAddress = fnAddress;
		m_fnCallback = fnCallback;
		m_hooked = false;
	}

	Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != nullptr && fnCallback != nullptr);
		m_fnAddress = (uint64_t)fnAddress;
		m_fnCallback = (uint64_t)fnCallback;
		m_hooked = false;
	}

	virtual HookType getType() const {
		return HookType::Detour;
	}

	virtual uint64_t getTrampoline() const {
		assert(m_hooked);
		if (!m_hooked) 
			throw "Must hook before getting trampoline";
		
		return m_trampoline;
	}

	virtual Mode getArchType() const = 0;
protected:
    uint64_t                m_fnAddress;
    uint64_t                m_fnCallback;
	uint64_t				m_trampoline;
	ADisassembler&			m_disasm;

	/**Walks the given vector of instructions and sets roundedSz to the lowest size possible that doesn't split any instructions and is greater than minSz.
	If end of function is encountered before this condition an empty optional is returned. Returns instructions in the range start to adjusted end**/
	std::optional<insts_t> calcNearestSz(const insts_t& functionInsts, const uint64_t minSz,
			uint64_t& roundedSz);

	/**If function starts with a jump follow it until the first non-jump character recursively. This handles already hooked functions
	and also compilers that emit jump tables on function call. Returns true if resolution was successful (nothing to resolve, or resolution worked),
	false if resolution failed.**/
	bool followJmp(insts_t& functionInsts, const uint8_t curDepth = 0, const uint8_t depth = 3);

	/**Expand the prologue up to the address of that last jmp that points back into the prologue. This
	is necessary because we modify the location of things in the prologue, so re-entrant jmps point
	to the wrong place. Therefore we move all of it to the trampoline where there is ample space to 
	relocate and create jmp tbl entries**/
	bool expandProlSelfJmps(insts_t& prol,
		const insts_t& func,
		uint64_t& minProlSz,
		uint64_t& roundProlSz);

	template<typename MakeJmpFn>
	std::optional<insts_t> makeTrampoline(insts_t& prologue, const uint64_t trampStart, const uint64_t roundProlSz, const uint8_t jmpSz,  MakeJmpFn makeJmp);

    bool                    m_hooked;
};

template<typename MakeJmpFn>
std::optional<PLH::insts_t> PLH::Detour::makeTrampoline(insts_t& prologue, const uint64_t trampStart, const uint64_t roundProlSz, const uint8_t jmpSz, MakeJmpFn makeJmp)
{
	const uint64_t delta = std::llabs(prologue.front().getAddress() - trampStart);
	uint64_t trampAddr = trampStart;
	const uint64_t jmpToProlAddr = trampStart + roundProlSz;
	uint64_t jmpTblAddr = jmpToProlAddr + jmpSz; // end of copied prol + space for jmp back to prol is start of tramp jump table
	
	assert(prologue.size() > 0);
	assert(jmpTblAddr > trampAddr);

	auto jmpToProl = makeJmp(jmpToProlAddr, prologue.front().getAddress() + roundProlSz);
	m_disasm.writeEncoding(jmpToProl);

	// just a convenience list to see what the jmp table became
	PLH::insts_t jmpTblEntries;

	for (auto& inst : prologue) {
		uint64_t instDest = inst.getDestination();
		inst.setAddress(trampAddr);

		// relocate if it doesn't point inside trampoline prol
		if (inst.hasDisplacement() &&
			(inst.getDestination() < trampStart ||
				inst.getDestination() > trampStart + roundProlSz)) {

			// can inst just be re-encoded or do we need a tbl entry
			const uint8_t dispSzBits = (uint8_t)inst.getDispSize() * 8;
			const uint64_t maxInstDisp = (uint64_t)(std::pow(2, dispSzBits) / 2.0 - 1.0); // 2^bitSz give max val, /2 and -1 because signed
			if (delta > maxInstDisp) {
				// make an entry pointing to where inst did point to
				auto entry = makeJmp(jmpTblAddr, instDest); 

				// point instruction to entry
				inst.setDestination(jmpTblAddr);
				jmpTblAddr += jmpSz;

				m_disasm.writeEncoding(entry);
				jmpTblEntries.insert(jmpTblEntries.end(), entry.begin(), entry.end());
			} else {
				inst.setDestination(instDest);
			}
		}

		trampAddr += inst.size();
		m_disasm.writeEncoding(inst);
	}

	assert(trampAddr > trampStart);
	if (jmpTblEntries.size() > 0)
		return jmpTblEntries;
	else
		return std::nullopt;
}

/** Before Hook:                                                After hook:
*
* --------fnAddress--------                                    --------fnAddress--------
* |    prologue           |                                   |    jmp fnCallback      | <- this may be an indirect jmp
* |    ...body...         |      ----> Converted into ---->   |    ...jump table...    | if it is, it reads the final
* |                       |                                   |    ...body...          |  dest from end of trampoline (optional indirect loc)
* |    ret                |                                   |    ret                 |
* -------------------------                                   --------------------------
*                                                                           ^ jump table may not exist.
*                                                                           If it does, and it uses indirect style
*                                                                           jumps then prologueJumpTable exists.
*                                                                           prologueJumpTable holds pointers
*                                                                           to where the indirect jump actually
*                                                                           lands.
*
*                               Created during hooking:
*                              --------Trampoline--------
*                              |     prologue            | Executes fnAddress's prologue (we overwrote it with jmp)
*                              |     jmp fnAddress.body  | Jmp back to first address after the overwritten prologue
*                              |  ...jump table...       | Long jmp table that short jmps in prologue point to
*                              |  optional indirect loc  | may or may not exist depending on jmp type we used
*                              --------------------------
*
*                              Conditionally exists:
*                              ----prologueJumpTable-----
*                              |    jump_holder1       | -> points into Trampoline.prologue
*                              |    jump_holder2       | -> points into Trampoline.prologue
*                              |       ...             |
*                              ------------------------
*
*
*                      Example jmp table (with an example prologue, this prologue lives in trampoline):
*
*        Prologue before fix:          Prologue after fix:
*        ------prologue-----           ------prologue----          ----jmp table----
*        push ebp                      push ebp                    jump_table.Entry1: long jmp original je address + 0x20
*        mov ebp, esp                  mov ebp, esp
*        cmp eax, 1                    cmp eax, 1
*        je 0x20                       je jump_table.Entry1
*
*        This jump table is needed because the original je instruction's displacement has a max vale of 0x80. It's
*        extremely likely that our Trampoline was not placed +-0x80 bytes away from fnAddress. Therefore we have
*        to add an intermediate long jmp so that the moved je will still jump to where it originally pointed. To
*        do this we insert a jump table at the end of the trampoline, there's N entrys where conditional jmp N points
*        to jump_table.EntryN.
*
*
*                          User Implements callback as C++ code
*                              --------fnCallback--------
*                              | ...user defined code... |
*                              |   return Trampoline     |
*                              |                         |
*                              --------------------------
* **/
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
