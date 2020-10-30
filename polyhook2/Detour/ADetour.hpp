//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include <functional>
#include <optional>
#include <cassert>
#include <vector>
#include <map>

#include "polyhook2/ADisassembler.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Misc.hpp"

#pragma warning(disable:4100)
#pragma warning(disable:4189)

/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

/**First param is an address to a function that you want to
cast to the type of pFnCastTo. Second param must be a pointer
to function type**/
template<typename T>
T FnCast(uint64_t fnToCast, T pFnCastTo) {
	PH_UNUSED(pFnCastTo);
	return (T)fnToCast;
}

template<typename T>
T FnCast(void* fnToCast, T pFnCastTo) {
	PH_UNUSED(pFnCastTo);
	return (T)fnToCast;
}

class Detour : public PLH::IHook {
public:
	Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != 0 && fnCallback != 0);
		assert(sizeof(*userTrampVar) == sizeof(uint64_t) && "Given trampoline holder to small");

		m_fnAddress = fnAddress;
		m_fnCallback = fnCallback;
		m_trampoline = NULL;
		m_trampolineSz = NULL;
		m_hooked = false;
		m_userTrampVar = userTrampVar;
	}

	Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : m_disasm(dis) {
		assert(fnAddress != nullptr && fnCallback != nullptr);
		assert(sizeof(*userTrampVar) == sizeof(uint64_t) && "Given trampoline holder to small");

		m_fnAddress = (uint64_t)fnAddress;
		m_fnCallback = (uint64_t)fnCallback;
		m_trampoline = NULL;
		m_trampolineSz = NULL;
		m_hooked = false;
		m_userTrampVar = userTrampVar;
	}

	virtual ~Detour() {
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool unHook() override;

	/**
	This is for restoring hook bytes if a 3rd party uninstalled them.
	DO NOT call this after unHook(). This may only be called after hook() 
	but before unHook()
	**/
	virtual bool reHook() override;

	virtual HookType getType() const override {
		return HookType::Detour;
	}

	virtual Mode getArchType() const = 0;
protected:
	uint64_t                m_fnAddress;
	uint64_t                m_fnCallback;
	uint64_t				m_trampoline;
	uint16_t			    m_trampolineSz;
	uint64_t*				m_userTrampVar;
	ADisassembler&			m_disasm;

	PLH::insts_t			m_originalInsts;

	/*Save the instructions used for the hook so that we can re-write in rehook()
	Note: There's a nop range we store too so that it doesn't need to be re-calculated
	*/
	PLH::insts_t            m_hookInsts;
	uint16_t                m_nopProlOffset;
	uint16_t                m_nopSize;
	uint32_t                m_hookSize;

	/**Walks the given vector of instructions and sets roundedSz to the lowest size possible that doesn't split any instructions and is greater than minSz.
	If end of function is encountered before this condition an empty optional is returned. Returns instructions in the range start to adjusted end**/
	std::optional<insts_t> calcNearestSz(const insts_t& functionInsts, const uint64_t minSz,
										 uint64_t& roundedSz);

	/**If function starts with a jump follow it until the first non-jump instruction, recursively. This handles already hooked functions
	and also compilers that emit jump tables on function call. Returns true if resolution was successful (nothing to resolve, or resolution worked),
	false if resolution failed.**/
	bool followJmp(insts_t& functionInsts, const uint8_t curDepth = 0, const uint8_t depth = 5);

	/**Expand the prologue up to the address of the last jmp that points back into the prologue. This
	is necessary because we modify the location of things in the prologue, so re-entrant jmps point
	to the wrong place. Therefore we move all of it to the trampoline where there is ample space to
	relocate and create jmp tbl entries**/
	bool expandProlSelfJmps(insts_t& prol,
							const insts_t& func,
							uint64_t& minProlSz,
							uint64_t& roundProlSz);

	bool buildRelocationList(insts_t& prologue, const uint64_t roundProlSz, const int64_t delta, PLH::insts_t &instsNeedingEntry, PLH::insts_t &instsNeedingReloc);

	template<typename MakeJmpFn>
	PLH::insts_t relocateTrampoline(insts_t& prologue, uint64_t jmpTblStart, const int64_t delta, const uint8_t jmpSz, MakeJmpFn makeJmp, const PLH::insts_t& instsNeedingReloc, const PLH::insts_t& instsNeedingEntry);

	/**
	Insert nops from [Base, Base+size). We _MUST_ insert multi-byte nops so we don't accidentally
	confused our code cave finder for x64
	**/
	void writeNop(uint64_t base, uint32_t size);
};

template<typename MakeJmpFn>
PLH::insts_t PLH::Detour::relocateTrampoline(insts_t& prologue, uint64_t jmpTblStart, const int64_t delta, const uint8_t jmpSz, MakeJmpFn makeJmp, const PLH::insts_t& instsNeedingReloc, const PLH::insts_t& instsNeedingEntry) {
	uint64_t jmpTblCurAddr = jmpTblStart;
	insts_t jmpTblEntries;
	for (auto& inst : prologue) {

		if (std::find(instsNeedingEntry.begin(), instsNeedingEntry.end(), inst) != instsNeedingEntry.end()) {
			assert(inst.hasDisplacement());
			// make an entry pointing to where inst did point to
			auto entry = makeJmp(jmpTblCurAddr, inst.getDestination());
			
			// move inst to trampoline and point instruction to entry
			inst.setAddress(inst.getAddress() + delta);
			inst.setDestination(jmpTblCurAddr);
			jmpTblCurAddr += jmpSz;

			m_disasm.writeEncoding(entry, *this);
			jmpTblEntries.insert(jmpTblEntries.end(), entry.begin(), entry.end());
		} else if (std::find(instsNeedingReloc.begin(), instsNeedingReloc.end(), inst) != instsNeedingReloc.end()) {
			assert(inst.hasDisplacement());

			const uint64_t instsOldDest = inst.getDestination();
			inst.setAddress(inst.getAddress() + delta);
			inst.setDestination(instsOldDest);
		} else {
			inst.setAddress(inst.getAddress() + delta);
		}

		m_disasm.writeEncoding(inst, *this);
	}
	return jmpTblEntries;
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