//
// Created by steve on 7/5/17.
//
#include <set>
#include <sstream>
#include <algorithm>
#include <functional>

#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/MemProtector.hpp"

#include <asmtk/asmtk.h>

PLH::x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ZydisDisassembler& dis, const uint8_t maxDepth) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis, maxDepth), m_allocator(8, 100) {

}

PLH::x64Detour::x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ZydisDisassembler& dis, const uint8_t maxDepth) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis, maxDepth), m_allocator(8, 100) {

}

PLH::x64Detour::~x64Detour() {
	if (m_valloc2_region) {
		m_allocator.deallocate(*m_valloc2_region);
		m_valloc2_region = {};
	}
}

PLH::Mode PLH::x64Detour::getArchType() const {
	return PLH::Mode::x64;
}

uint8_t PLH::x64Detour::getMinJmpSize() const {
	return 6;
}

uint8_t PLH::x64Detour::getPrefJmpSize() const {
	return 16;
}

PLH::x64Detour::detour_scheme_t PLH::x64Detour::getDetourScheme() const {
	return _detourScheme;
}

void PLH::x64Detour::setDetourScheme(detour_scheme_t scheme) {
	_detourScheme = scheme;
}

template<uint16_t SIZE>
std::optional<uint64_t> PLH::x64Detour::findNearestCodeCave(uint64_t addr) {
	const uint64_t chunkSize = 64000;
	unsigned char* data = new unsigned char[chunkSize];
	auto delete_data = finally([=]() {
		delete[] data;
	});

	// RPM so we don't pagefault, careful to check for partial reads

	// these patterns are listed in order of most accurate to least accurate with size taken into account
	// simple c3 ret is more accurate than c2 ?? ?? and series of CC or 90 is more accurate than complex multi-byte nop
	std::string CC_PATTERN_RET = "c3 " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RET = "c3 " + repeat_n("90", SIZE, " ");

	std::string CC_PATTERN_RETN = "c2 ?? ?? " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RETN = "c2 ?? ?? " + repeat_n("90", SIZE, " ");

	const char* NOP2_RET = "c3 0f 1f 44 00 00";
	const char* NOP3_RET = "c3 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RET = "c3 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RET = "c3 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RET = "c3 cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RET = "c3 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RET = "c3 cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RET = "c3 cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

	const char* NOP2_RETN = "c2 ?? ?? 0f 1f 44 00 00";
	const char* NOP3_RETN = "c2 ?? ?? 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RETN = "c2 ?? ?? 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RETN = "c2 ?? ?? 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RETN = "c2 ?? ?? 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

	// Scan in same order as listing above
	const char* PATTERNS_OFF1[] = {
		CC_PATTERN_RET.c_str(), NOP1_PATTERN_RET.c_str(),
		NOP2_RET, NOP3_RET, NOP4_RET, NOP5_RET, NOP6_RET,
		NOP7_RET, NOP8_RET, NOP9_RET, NOP10_RET, NOP11_RET
	};

	const char* PATTERNS_OFF3[] = {
		CC_PATTERN_RETN.c_str(), NOP1_PATTERN_RETN.c_str(),
		NOP2_RETN, NOP3_RETN, NOP4_RETN, NOP5_RETN, NOP6_RETN,
		NOP7_RETN, NOP8_RETN, NOP9_RETN, NOP10_RETN, NOP11_RETN,
	};

	// Most common:
	// https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
	// We check for rets to verify it's not like like a mid function or jmp table pad
	// [0xc3 | 0xC2 ? ? ? ? ] & 6666666666660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccccccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 660f1f840000000000

	// Search 2GB below
	for (uint64_t search = addr - chunkSize; (search + chunkSize) >= calc_2gb_below(addr); search -= chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t) data, chunkSize, read)) {
			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t) findPattern_rev((uint64_t) data, read, pattern)) {
					return search + (found + offset - (uint64_t) data);
				}
				return {};
			};

			for (const char* pat: PATTERNS_OFF1) {
				if (getPatternSize(pat) - 1 < SIZE)
					continue;

				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat: PATTERNS_OFF3) {
				if (getPatternSize(pat) - 3 < SIZE)
					continue;

				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}

	// Search 2GB above
	for (uint64_t search = addr; (search + chunkSize) < calc_2gb_above(addr); search += chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t) data, chunkSize, read)) {
			uint32_t contiguousInt3 = 0;
			uint32_t contiguousNop = 0;

			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t) findPattern((uint64_t) data, read, pattern)) {
					return search + (found + offset - (uint64_t) data);
				}
				return {};
			};

			for (const char* pat: PATTERNS_OFF1) {
				if (getPatternSize(pat) - 1 < SIZE)
					continue;

				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat: PATTERNS_OFF3) {
				if (getPatternSize(pat) - 3 < SIZE)
					continue;

				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}
	return {};
}

namespace {

#pragma pack(push, 1)

	struct InplaceDetour {
		uint16_t mov_r10{0xba49};
		uint64_t target;
		uint16_t push_r10{0x5241};
		uint8_t ret{0xc3};
	};

#pragma pack(pop)

	constexpr auto INPLACE_DETOUR_SIZE = sizeof(InplaceDetour);

	PLH::insts_t makeInplaceDetour(const uint64_t address, const uint64_t destination) {
		PLH::Instruction::Displacement disp{0};

		InplaceDetour dt;
		dt.target = destination;

		std::vector<uint8_t> destBytes;
		destBytes.resize(INPLACE_DETOUR_SIZE);
		memcpy(destBytes.data(), &dt, INPLACE_DETOUR_SIZE);
		return {PLH::Instruction(address, disp, 0, false, false, destBytes, "inplace-detour", "", PLH::Mode::x64)};
	}

}

bool PLH::x64Detour::hook() {
	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
	if (insts.empty()) {
		Log::log("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followJmp(insts, 0, m_maxDepth)) {
		Log::log("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn address to resolved one
	m_fnAddress = insts.front().getAddress();

	// --------------- END RECURSIVE JMP RESOLUTION ---------------------
	Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);


	uint64_t minProlSz = (_detourScheme != detour_scheme_t::INPLACE) ? getMinJmpSize() : INPLACE_DETOUR_SIZE; // min size of patches that may split instructions
	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	std::optional<PLH::insts_t> prologueOpt;
	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
		if (!prologueOpt) {
			Log::log("Function too small to hook safely!", ErrorLevel::SEV);
			return false;
		}

		assert(roundProlSz >= minProlSz);
		prologue = *prologueOpt;

		if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
			Log::log("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
			return false;
		}
	}

	m_originalInsts = prologue;
	Log::log("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

	{   // copy all the prologue stuff to trampoline
		insts_t jmpTblOpt;
		if (!makeTrampoline(prologue, jmpTblOpt)) {
			return false;
		}

		Log::log("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this)) + "\n\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;
	m_hookSize = (uint32_t) roundProlSz;
	m_nopProlOffset = (uint16_t) minProlSz;

	MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	if (_detourScheme & detour_scheme_t::VALLOC2 && boundedAllocSupported()) {
		uint64_t max = (uint64_t) AlignDownwards(calc_2gb_above(m_fnAddress), PLH::getPageSize());
		uint64_t min = (uint64_t) AlignDownwards(calc_2gb_below(m_fnAddress), PLH::getPageSize());

		// each block is m_blocksize (8) at the time of writing. Do not write more than this.
		uint64_t region = (uint64_t) m_allocator.allocate(min, max);
		if (!region) {
			if (_detourScheme & detour_scheme_t::CODE_CAVE || _detourScheme & detour_scheme_t::INPLACE) {
				goto trycave;
			}

			Log::log("VirtualAlloc2 failed to find a region near function", ErrorLevel::SEV);
			return false;
		} else {
			m_valloc2_region = region;

			MemoryProtector holderProt(region, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
			m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, region);
			goto success;
		}
	}

	trycave:
	if (_detourScheme & detour_scheme_t::CODE_CAVE) {
		// we're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
		auto cave = findNearestCodeCave<8>(m_fnAddress);
		if (!cave) {
			if (_detourScheme & detour_scheme_t::INPLACE) {
				goto tryinplace;
			}

			Log::log("No code caves found near function", ErrorLevel::SEV);
			return false;
		} else {
			MemoryProtector holderProt(*cave, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
			m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
			goto success;
		}
	}

	tryinplace:
	if (_detourScheme & detour_scheme_t::INPLACE) {
		//inplace scheme. This is more stable than the cave finder since that may potentially find a region of unstable memory.
		// However, this INPLACE scheme may only be done for functions with a large enough prologue, otherwise this will overwrite adjacent bytes
		m_hookInsts = makeInplaceDetour(m_fnAddress, m_fnCallback);
		goto success;
	} else {
		Log::log("No allowed hooking scheme succeeded", ErrorLevel::SEV);
		return false;
	}

	success:
	m_disasm.writeEncoding(m_hookInsts, *this);

	// Nop the space between jmp and end of prologue
	assert(m_hookSize >= m_nopProlOffset);
	m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
	writeNop(m_fnAddress + m_nopProlOffset, m_nopSize);

	m_hooked = true;
	return true;
}

bool PLH::x64Detour::unHook() {
	bool status = PLH::Detour::unHook();
	if (m_valloc2_region) {
		m_allocator.deallocate(*m_valloc2_region);
		m_valloc2_region = {};
	}
	return status;
}

/**
 * Translations of such instruction require storing contents
 * of the scratch register into the destination
 */
const static std::set<std::string> instructions_to_store{
	"add", "adc"
};

const static std::map<ZydisRegister, ZydisRegister> a_to_b{ // NOLINT(cert-err58-cpp)
	{ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX},
	{ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_EBX},
	{ZYDIS_REGISTER_AX,  ZYDIS_REGISTER_BX},
	{ZYDIS_REGISTER_AH,  ZYDIS_REGISTER_BH},
	{ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_BL},
};

const static std::map<ZydisRegisterClass, ZydisRegister> class_to_reg{ // NOLINT(cert-err58-cpp)
	{ZYDIS_REGCLASS_GPR64, ZYDIS_REGISTER_RAX},
	{ZYDIS_REGCLASS_GPR32, ZYDIS_REGISTER_EAX},
	{ZYDIS_REGCLASS_GPR16, ZYDIS_REGISTER_AX},
	{ZYDIS_REGCLASS_GPR8,  ZYDIS_REGISTER_AL},
};

/**
 * For push/pop operations, we have to use 64-bit operands.
 * This map translates all possible scratch registers into
 * the corresponding 64-bit register for push/pop operations.
 */
const static std::map<std::string, std::string> scratch_to_64{ // NOLINT(cert-err58-cpp)
	{"rbx", "rbx"},
	{"ebx", "rbx"},
	{"bx",  "rbx"},
	{"bh",  "rbx"},
	{"bl",  "rbx"},
	{"rax", "rax"},
	{"eax", "rax"},
	{"ax",  "rax"},
	{"ah",  "rax"},
	{"al",  "rax"},
};


struct TranslationResult {
	std::string instruction;
	std::string scratch_register;
};

TranslationResult translateInstruction(const PLH::Instruction& instruction) {
	const auto& mnemonic = instruction.getMnemonic();
	ZydisRegister scratch_register;
	std::string scratch_register_string;

	if (instruction.hasImmediate()) { // 2nd operand is immediate
		// TODO
		throw std::exception("No translation support for immediate operands yet");
	} else if (instruction.hasRegister()) { // 2nd operand is register
		const auto reg = instruction.getRegister();
		const auto regClass = ZydisRegisterGetClass(reg);
		const std::string reg_string = ZydisRegisterGetString(reg);

		if (a_to_b.count(reg)) {
			// This is a register A
			scratch_register = a_to_b.at(reg);
		} else if (class_to_reg.count(regClass)) {
			// This is not a register A
			scratch_register = class_to_reg.at(regClass);
		} else {
			// Unexpected register
			auto message = "Unexpected register: " + reg_string;
			throw std::exception(message.c_str());
		}

		scratch_register_string = ZydisRegisterGetString(scratch_register);

		if (!scratch_to_64.count(scratch_register_string)) {
			auto message = "Unexpected scratch register: " + scratch_register_string;
			throw std::exception(message.c_str());
		}

		return {
			mnemonic + " " + scratch_register_string + ", " + reg_string,
			scratch_register_string,
		};
	}

	throw std::exception("No translation support for such instruction");
}


std::string generate_jmp_instruction_string(const uint64_t destination) {
	std::stringstream stream;
	stream << "jmp 0x" << std::hex << destination;
	return stream.str();
}

/**
 * @throws std::exception
 */
uint64_t PLH::x64Detour::generateTranslationRoutine(
	const PLH::Instruction& instruction,
	uint64_t resume_address
) {
	// AsmTK parses strings for AsmJit, which generates the binary code.
	asmjit::CodeHolder code;

	// FIXME: Without providing base address, asmjit will likely fail on relocation
	code.init(m_asmjit_rt.environment());

	asmjit::x86::Assembler a(&code);
	asmtk::AsmParser p(&a);

	auto [translated_instruction, scratch_register] = translateInstruction(instruction);

	// Stores vector of instruction strings that comprise translation routine
	std::vector<std::string> translation;

	// Avoid spoiling the shadow space
	translation.emplace_back("lea rsp, ss:[rsp - 0x128]");

	// Save the scratch register
	translation.emplace_back("push " + scratch_to_64.at(scratch_register));

	// Load the destination content into scratch register
	const auto destination = int_to_hex(instruction.getDestination());
	translation.emplace_back("mov " + scratch_register + ", ds:[" + destination + "]");

	// Replace RIP-relative instruction
	translation.emplace_back(translated_instruction);

	// Store the scratch register content into the destination, if necessary
	if (instructions_to_store.count(instruction.getMnemonic())) {
		translation.emplace_back("mov ds:[" + destination + "], " + scratch_register);
	}

	// Restore the scratch register
	translation.emplace_back("pop " + scratch_to_64.at(scratch_register));

	// Restore the stack pointer
	translation.emplace_back("lea rsp, ss:[rsp + 0x128]");

	// Jump back to trampoline
	translation.emplace_back(generate_jmp_instruction_string(resume_address));

	// Join all instructions into one string delimited by newlines
	std::ostringstream translation_stream;
	std::copy(translation.begin(), translation.end(), std::ostream_iterator<std::string>(translation_stream, "\n"));
	const auto translation_string = translation_stream.str();

	PLH::Log::log("Translation:\n" + translation_string, PLH::ErrorLevel::INFO);

	// Parse the instructions via AsmTK
	if (auto error = p.parse(translation_string.c_str())) {
		auto message = std::string("AsmTK error: ") + asmjit::DebugUtils::errorAsString(error);
		throw std::exception(message.c_str());
	}

	// Generate the binary code via AsmJit
	uint64_t translation_address = 0;
	if (auto error = m_asmjit_rt.add(&translation_address, &code)) {
		auto message = std::string("AsmJit error: ") + asmjit::DebugUtils::errorAsString(error);
		throw std::exception(message.c_str());
	}

	PLH::Log::log("Translation address: " + int_to_hex(translation_address) + "\n", PLH::ErrorLevel::INFO);

	return translation_address;
}

bool PLH::x64Detour::makeTrampoline(insts_t& prologue, insts_t& outJmpTable) {
	assert(!prologue.empty());
	assert(m_trampoline == NULL);

	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);
	const uint8_t destHldrSz = 8;

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works

	The relocation could also because of data operations too. But that's specific to the function and can't
	work again on a retry (same function, duh). Return immediately in that case.**/
	uint8_t neededEntryCount = 0;
	insts_t instsNeedingEntry;
	insts_t instsNeedingReloc;
	insts_t instsNeedingTranslation;
	uint8_t retries = 0;
	int64_t delta;

	bool good = false;
	do {
		neededEntryCount = std::max((uint8_t) instsNeedingEntry.size(), (uint8_t) 5);

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t) (prolSz + (getMinJmpSize() + destHldrSz) +
									 (getMinJmpSize() + destHldrSz) * neededEntryCount +
									 7); //extra bytes for dest-holders 8 bytes alignment

		// allocate new trampoline before deleting old to increase odds of new mem address
		auto tmpTrampoline = (uint64_t) new unsigned char[m_trampolineSz];
		if (m_trampoline != NULL) {
			delete[](unsigned char*) m_trampoline;
		}

		m_trampoline = tmpTrampoline;
		delta = m_trampoline - prolStart;

		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation))
			continue;

		good = true;
	} while (retries++ < 5 && !good);

	if (!good) {
		return false;
	}

	Log::log("Trampoline address: " + PLH::int_to_hex(m_trampoline), PLH::ErrorLevel::INFO);

	for (auto& instruction: instsNeedingTranslation) {
		uint64_t translation_address;
		try {
			const auto inst_offset = instruction.getAddress() - prolStart;
			const uint64_t resume_address = m_trampoline + inst_offset + instruction.size();
			translation_address = generateTranslationRoutine(instruction, resume_address);
		} catch (const std::exception& ex) {
			Log::log("Failed to generate translation routine: " + std::string(ex.what()) + "\n", ErrorLevel::SEV);
			return false;
		}

		// replace the rip-relative instruction with jump to translation
		auto inst_iterator = std::find(prologue.begin(), prologue.end(), instruction);
		*inst_iterator = makex86Jmp(instruction.getAddress(), translation_address)[0];
		inst_iterator->setRelativeDisplacement(inst_iterator->getDisplacement().Relative, true);
		instsNeedingReloc.push_back(*inst_iterator);

		// nop the garbage bytes if necessary. TODO: Use writeNop?
		auto current_address = (uint8_t*) (inst_iterator->getAddress() + inst_iterator->size());
		for (int i = 0; i < instruction.size() - 5; i++) {
			auto nop = PLH::Instruction((uint64_t) current_address++, {0}, 0, false, false, {0x90}, "nop", "", PLH::Mode::x64);
			if (inst_iterator == prologue.end()) {
				prologue.push_back(nop);
				inst_iterator = prologue.end();
			} else {
				inst_iterator = prologue.insert(inst_iterator, nop) + 1; // TODO: Is this correct?
			}
		}
	}

	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	const uint64_t jmpHolderCurAddr = (m_trampoline + m_trampolineSz - destHldrSz) & ~0x7; //8 bytes align for performance.
	{
		const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prolStart + prolSz, jmpHolderCurAddr);

		Log::log("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
		PLH::ZydisDisassembler::writeEncoding(jmpToProl, *this);
	}

	// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
	const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
		captureAddress -= destHldrSz;
		assert(captureAddress > (uint64_t) m_trampoline && (captureAddress + destHldrSz) < (m_trampoline + m_trampolineSz));

		// move inst to trampoline and point instruction to entry
		const bool isIndirectCall = inst.isCalling() && inst.isIndirect();
		auto oldDest = inst.getDestination();
		inst.setAddress(inst.getAddress() + delta);
		inst.setDestination(isIndirectCall ? captureAddress : a);

		// ff 25 indirect call re-written to point at dest-holder. e8 direct call, or jmps of any time point to literal jmp instruction
		return isIndirectCall ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
	};

	const uint64_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
	outJmpTable = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry, instsNeedingTranslation);

	return true;
}
