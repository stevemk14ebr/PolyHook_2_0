//
// Created by steve on 7/5/17.
//
#include <algorithm>
#include <functional>
#include <set>
#include <sstream>

#include <asmtk/asmtk.h>

#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {

using std::optional;
using std::string;

using namespace asmjit;

x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar) :
    Detour(fnAddress, fnCallback, userTrampVar, getArchType()), m_allocator(8, 100) {}

x64Detour::~x64Detour() {
    if (m_valloc2_region) {
        m_allocator.deallocate(*m_valloc2_region);
        m_valloc2_region = {};
    }
}

Mode x64Detour::getArchType() const {
    return Mode::x64;
}

uint8_t x64Detour::getMinJmpSize() {
    return 6;
}

x64Detour::detour_scheme_t x64Detour::getDetourScheme() const {
    return m_detourScheme;
}

void x64Detour::setDetourScheme(detour_scheme_t scheme) {
    m_detourScheme = scheme;
}

template<uint16_t SIZE>
optional<uint64_t> x64Detour::findNearestCodeCave(uint64_t address) {
    const uint64_t chunkSize = 64000;
    auto* data = new unsigned char[chunkSize];
    auto delete_data = finally([=]() {
        delete[] data;
    });

    // RPM so we don't pagefault, careful to check for partial reads

    // these patterns are listed in order of most accurate to least accurate with size taken into account
    // simple c3 ret is more accurate than c2 ?? ?? and series of CC or 90 is more accurate than complex multi-byte nop
    string CC_PATTERN_RET = "c3 " + repeat_n("cc", SIZE, " ");
    string NOP1_PATTERN_RET = "c3 " + repeat_n("90", SIZE, " ");

    string CC_PATTERN_RETN = "c2 ?? ?? " + repeat_n("cc", SIZE, " ");
    string NOP1_PATTERN_RETN = "c2 ?? ?? " + repeat_n("90", SIZE, " ");

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

    // Scan in the same order as listing above
    const char* PATTERNS_OFF1[] = {
        CC_PATTERN_RET.c_str(), NOP1_PATTERN_RET.c_str(), NOP2_RET, NOP3_RET, NOP4_RET,
        NOP5_RET, NOP6_RET, NOP7_RET, NOP8_RET, NOP9_RET, NOP10_RET, NOP11_RET
    };

    const char* PATTERNS_OFF3[] = {
        CC_PATTERN_RETN.c_str(), NOP1_PATTERN_RETN.c_str(), NOP2_RETN, NOP3_RETN, NOP4_RETN,
        NOP5_RETN, NOP6_RETN, NOP7_RETN, NOP8_RETN, NOP9_RETN, NOP10_RETN, NOP11_RETN
    };

    // Most common:
    // https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
    // We check for rets to verify it's not like a mid function or jmp table pad
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
    for (uint64_t search = address - chunkSize; (search + chunkSize) >= calc_2gb_below(address); search -= chunkSize) {
        size_t read = 0;
        if (safe_mem_read(search, (uint64_t) data, chunkSize, read)) {
            assert(read <= chunkSize);
            if (read == 0 || read < SIZE)
                continue;

            auto finder = [&](const char* pattern, const uint64_t offset) -> optional<uint64_t> {
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
    for (uint64_t search = address; (search + chunkSize) < calc_2gb_above(address); search += chunkSize) {
        size_t read = 0;
        if (safe_mem_read(search, (uint64_t) data, chunkSize, read)) {
//            uint32_t contiguousInt3 = 0;
//            uint32_t contiguousNop = 0;

            assert(read <= chunkSize);
            if (read == 0 || read < SIZE) {
                continue;
            }

            auto finder = [&](const char* pattern, const uint64_t offset) -> optional<uint64_t> {
                if (auto found = (uint64_t) findPattern((uint64_t) data, read, pattern)) {
                    return search + (found + offset - (uint64_t) data);
                }
                return {};
            };

            for (const char* pat: PATTERNS_OFF1) {
                if (getPatternSize(pat) - 1 < SIZE) {
                    continue;
                }

                if (auto found = finder(pat, 1)) {
                    return found;
                }
            }

            for (const char* pat: PATTERNS_OFF3) {
                if (getPatternSize(pat) - 3 < SIZE) {
                    continue;
                }

                if (auto found = finder(pat, 3)) {
                    return found;
                }
            }
        }
    }
    return {};
}

bool x64Detour::make_inplace_trampoline(
    uint64_t base_address,
    const std::function<void(asmjit::x86::Assembler&)>& builder
) {
    CodeHolder code;
    code.init(m_asmjit_rt.environment(), base_address);
    x86::Assembler a(&code);

    builder(a);

    uint64_t trampoline_address;
    auto error = m_asmjit_rt.add(&trampoline_address, &code);

    if (error) {
        const auto message = std::string("Failed to generate in-place trampoline: ")
                             + asmjit::DebugUtils::errorAsString(error);
        PLH::Log::log(message, PLH::ErrorLevel::SEV);
        return false;
    }

    const auto trampoline_end = trampoline_address + code.codeSize();
    m_hookInsts = m_disasm.disassemble(trampoline_address, trampoline_address, trampoline_end, *this);
    // Fix the addresses
    auto current_address = base_address;
    for (auto& inst: m_hookInsts) {
        inst.setAddress(current_address);
        current_address += inst.size();
    }
    return true;
}

bool x64Detour::allocate_jump_to_callback() {
    // Insert valloc description
    if (m_detourScheme & detour_scheme_t::VALLOC2 && boundedAllocSupported()) {
        auto max = (uint64_t) AlignDownwards(calc_2gb_above(m_fnAddress), getPageSize());
        auto min = (uint64_t) AlignDownwards(calc_2gb_below(m_fnAddress), getPageSize());

        // each block is m_blocksize (8) at the time of writing. Do not write more than this.
        auto region = (uint64_t) m_allocator.allocate(min, max);
        if (region) {
            m_valloc2_region = region;

            MemoryProtector region_protector(region, 8, ProtFlag::RWX, *this, false);
            m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, region);
            m_chosen_scheme = detour_scheme_t::VALLOC2;
            return true;
        }

        Log::log("VirtualAlloc2 failed to find a region near function", ErrorLevel::SEV);
    }

    // The In-place scheme may only be done for functions with a large enough prologue,
    // otherwise this will overwrite adjacent bytes. The default in-place scheme is non-spoiling,
    // but larger, which reduces chances of success.
    if (m_detourScheme & detour_scheme_t::INPLACE) {
        const auto success = make_inplace_trampoline(m_fnAddress, [&](auto& a) {
            a.lea(x86::rsp, x86::ptr(x86::rsp, -0x80));
            a.push(x86::rax);
            a.mov(x86::rax, m_fnCallback);
            a.xchg(x86::ptr(x86::rsp), x86::rax);
            a.ret(0x80);
        });

        if (success) {
            m_chosen_scheme = detour_scheme_t::INPLACE;
            return true;
        }
    }

    // Code cave is our last recommended approach since it may potentially find a region of unstable memory.
    // We're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
    if (m_detourScheme & detour_scheme_t::CODE_CAVE) {
        auto cave = findNearestCodeCave<8>(m_fnAddress);
        if (cave) {
            MemoryProtector cave_protector(*cave, 8, ProtFlag::RWX, *this, false);
            m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
            m_chosen_scheme = detour_scheme_t::CODE_CAVE;
            return true;
        }

        Log::log("No code caves found near function", ErrorLevel::SEV);
    }

    // This short in-place scheme works almost like the default in-place scheme, except that it doesn't
    // try to not spoil shadow space. It doesn't mean that it will necessarily spoil it, though.
    if (m_detourScheme & detour_scheme_t::INPLACE_SHORT) {
        const auto success = make_inplace_trampoline(m_fnAddress, [&](auto& a) {
            a.mov(x86::rax, m_fnCallback);
            a.push(x86::rax);
            a.ret();
        });

        if (success) {
            m_chosen_scheme = detour_scheme_t::INPLACE_SHORT;
            return true;
        }
    }

    Log::log("None of the allowed hooking schemes have succeeded", ErrorLevel::SEV);

    if (m_hookInsts.empty()) {
        Log::log("Invalid state: hook instructions are empty", ErrorLevel::SEV);
    }

    return false;
}

bool x64Detour::hook() {
    insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);

    if (insts.empty()) {
        Log::log("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
        return false;
    }

    if (!followJmp(insts)) {
        Log::log("Prologue jmp resolution failed", ErrorLevel::SEV);
        return false;
    }

    // update given fn address to resolved one
    m_fnAddress = insts.front().getAddress();

    Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

    if (!allocate_jump_to_callback()) {
        return false;
    }

    // min size of patches that may split instructions
    // For valloc & code cave, we insert the jump, hence we take only size of the 1st instruction.
    // For detours, we calculate the size of the generated code.
    uint64_t minProlSz = (m_chosen_scheme == VALLOC2 || m_chosen_scheme == CODE_CAVE) ? m_hookInsts.begin()->size() :
                         m_hookInsts.rbegin()->getAddress() + m_hookInsts.rbegin()->size() -
                         m_hookInsts.begin()->getAddress();

    uint64_t roundProlSz = minProlSz;  // nearest size to min that doesn't split any instructions

    // find the prologue section we will overwrite with jmp + zero or more nops
    auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
    if (!prologueOpt) {
        Log::log("Function too small to hook safely!", ErrorLevel::SEV);
        return false;
    }

    assert(roundProlSz >= minProlSz);
    auto prologue = *prologueOpt;

    if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
        Log::log("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
        return false;
    }

    m_originalInsts = prologue;

    Log::log("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

    // copy all the prologue stuff to trampoline
    insts_t jmpTblOpt;
    if (!makeTrampoline(prologue, jmpTblOpt)) {
        return false;
    }
    Log::log("m_trampoline: " + int_to_hex(m_trampoline) + "\n", ErrorLevel::INFO);
    Log::log("m_trampolineSz: " + int_to_hex(m_trampolineSz) + "\n", ErrorLevel::INFO);

    auto tramp_instructions = m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
    Log::log("Trampoline:\n" + instsToStr(tramp_instructions) + "\n", ErrorLevel::INFO);
    if (!jmpTblOpt.empty()) {
        Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
    }

    *m_userTrampVar = m_trampoline;
    m_hookSize = (uint32_t) roundProlSz;
    m_nopProlOffset = (uint16_t) minProlSz;

    Log::log("Hook instructions: \n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);

    Log::log("Hook size: " + std::to_string(m_hookSize) + "\n", ErrorLevel::INFO);
    Log::log("Prologue offset: " + std::to_string(m_nopProlOffset) + "\n", ErrorLevel::INFO);

    // Nop the space between jmp and end of prologue
    assert(m_hookSize >= m_nopProlOffset);
    m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
    const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
    ZydisDisassembler::writeEncoding(nops, *this);

    m_hooked = true;
    return true;
}

bool x64Detour::unHook() {
    bool status = Detour::unHook();
    if (m_valloc2_region) {
        m_allocator.deallocate(*m_valloc2_region);
        m_valloc2_region = {};
    }
    return status;
}

/**
 * Holds a list of instructions that require us to store contents of the scratch register
 * into the original destination address. For example, in `add [0x...], rbx` after translation
 * we also need to store it: `add rax, rbx` && `mov [r15], rax`, where as in cmp instruction for
 * instance there is no such requirement.
 */
const static std::set<string> instructions_to_store{ // NOLINT(cert-err58-cpp)
    "adc", "add", "and", "bsf", "bsr", "btc", "btr", "bts",
    "cmovb", "cmove", "cmovl", "cmovle", "cmovnb", "cmovnbe", "cmovnl", "cmovnle",
    "cmovno", "cmovnp", "cmovns", "cmovnz", "cmovo", "cmovp", "cmovs", "cmovz",
    "cmpxchg", "crc32", "cvtsi2sd", "cvtsi2ss", "dec", "extractps", "inc", "mov",
    "neg", "not", "or", "pextrb", "pextrd", "pextrq", "rcl", "rcr", "rol", "ror",
    "sal", "sar", "sbb", "setb", "setbe", "setl", "setle", "setnb", "setnbe", "setnl",
    "setnle", "setno", "setnp", "setns", "setnz", "seto", "setp", "sets", "setz", "shl",
    "shld", "shr", "shrd", "sub", "verr", "verw", "xadd", "xchg", "xor"
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
const static std::map<string, string> scratch_to_64{ // NOLINT(cert-err58-cpp)
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
    string instruction;
    string scratch_register;
    string address_register;
};

/**
 * Generates an equivalent instruction that replaces memory operand with register
 * of corresponding size.
 */
optional<TranslationResult> translate_instruction(const Instruction& instruction) {
    const auto& mnemonic = instruction.getMnemonic();
    ZydisRegister scratch_register;
    string scratch_register_string, address_register_string, second_operand_string;

    if (instruction.hasImmediate()) {// 2nd operand is immediate
        const auto inst_contains = [&](const string& needle) {
            return string_contains(instruction.getFullName(), needle);
        };

        // We need to pick a register that matches the pointer size.
        // Only the mov instruction can encode 64-bit immediate, so it is a special case
        scratch_register_string =
            inst_contains("qword") ? (instruction.getMnemonic() == "mov" ? "rax" : "eax") :
            inst_contains("dword") ? "eax" :
            inst_contains("word") ? "ax" :
            inst_contains("byte") ? "al" : "";

        if (scratch_register_string.empty()) {
            Log::log("Failed to detect pointer size: " + instruction.getFullName(), ErrorLevel::SEV);
            return {};
        }

        const auto imm_size = instruction.getImmediateSize();
        const auto immediate_string =
            imm_size == 8 ? int_to_hex((uint64_t) instruction.getImmediate()) :
            imm_size == 4 ? int_to_hex((uint32_t) instruction.getImmediate()) :
            imm_size == 2 ? int_to_hex((uint16_t) instruction.getImmediate()) :
            imm_size == 1 ? int_to_hex((uint8_t) instruction.getImmediate()) : "";

        if (immediate_string.empty()) {
            Log::log("Unexpected size of immediate: " + std::to_string(imm_size), ErrorLevel::SEV);
            return {};
        }

        address_register_string = "r15";
        second_operand_string = immediate_string;
    } else if (instruction.hasRegister()) {// 2nd operand is register
        const auto reg = instruction.getRegister();
        const auto regClass = ZydisRegisterGetClass(reg);
        const string reg_string = ZydisRegisterGetString(reg);

        if (a_to_b.count(reg)) {
            // This is a register A
            scratch_register = a_to_b.at(reg);
        } else if (class_to_reg.count(regClass)) {
            // This is not a register A
            scratch_register = class_to_reg.at(regClass);
        } else {
            // Unexpected register
            Log::log("Unexpected register: " + reg_string, ErrorLevel::SEV);
            return {};
        }

        scratch_register_string = ZydisRegisterGetString(scratch_register);

        if (!scratch_to_64.count(scratch_register_string)) {
            Log::log("Unexpected scratch register: " + scratch_register_string, ErrorLevel::SEV);
            return {};
        }

        address_register_string = string_contains(reg_string, "r15") ? "r14" : "r15";
        second_operand_string = reg_string;
    } else {
        Log::log("No translation support for such instruction", ErrorLevel::SEV);
        return {};
    }

    const auto operand1 = instruction.startsWithDisplacement() ? scratch_register_string : second_operand_string;
    const auto operand2 = instruction.startsWithDisplacement() ? second_operand_string : scratch_register_string;

    TranslationResult result;
    result.instruction = mnemonic + " " + operand1 + ", " + operand2;
    result.scratch_register = scratch_register_string;
    result.address_register = address_register_string;

    return {result};
}

/**
 * Generates a jump with full 64-bit absolute address without spoiling any registers
 */
std::vector<string> generateAbsoluteJump(uint64_t destination, uint16_t stack_clean_size) {
    std::vector<string> instructions;

    // Save rax
    instructions.emplace_back("push rax");

    // Load destination into rax
    instructions.emplace_back("mov rax, " + int_to_hex(destination));

    // Restore rax and set up the return address
    instructions.emplace_back("xchg [rsp], rax");

    // Finally, make the jump
    instructions.emplace_back("ret " + int_to_hex(stack_clean_size));

    return instructions;
}

/**
 * @returns address of the first instructions of the translation routine
 */
optional<uint64_t> x64Detour::generateTranslationRoutine(const Instruction& instruction, uint64_t resume_address) {
    // AsmTK parses strings for AsmJit, which generates the binary code.
    CodeHolder code;
    code.init(m_asmjit_rt.environment());

    x86::Assembler assembler(&code);
    asmtk::AsmParser parser(&assembler);

    const auto result = translate_instruction(instruction);
    if (!result) {
        return {};
    }

    auto [translated_instruction, scratch_register, address_register] = *result;

    const auto& scratch_register_64 = scratch_to_64.at(scratch_register);

    // Stores vector of instruction strings that comprise translation routine
    std::vector<string> translation;

    // Avoid spoiling the shadow space
    translation.emplace_back("lea rsp, [rsp - 0x80]");

    // Save the scratch register
    translation.emplace_back("push " + scratch_register_64);

    // Save the address holder register
    translation.emplace_back("push " + address_register);

    // Load the destination address into the address holder register
    const auto destination = int_to_hex(instruction.getDestination());
    translation.emplace_back("mov " + address_register + ", " + destination);

    // Load the destination content into scratch register
    translation.emplace_back("mov " + scratch_register + ", [" + address_register + "]");

    // Replace RIP-relative instruction
    translation.emplace_back(translated_instruction);

    // Store the scratch register content into the destination, if necessary
    if (instruction.startsWithDisplacement() && instructions_to_store.count(instruction.getMnemonic())) {
        translation.emplace_back("mov [" + address_register + "], " + scratch_register_64);
    }

    // Restore the memory holder register
    translation.emplace_back("pop " + address_register);

    // Restore the scratch register
    translation.emplace_back("pop " + scratch_register_64);

    // Jump back to trampoline, ret cleans up the lea from earlier
    // we do it this way to ensure pushing our return address doesn't overwrite shadow space
    const auto jump_instructions = generateAbsoluteJump(resume_address, 0x80);
    translation.insert(translation.end(), jump_instructions.begin(), jump_instructions.end());

    // Join all instructions into one string delimited by newlines
    std::ostringstream translation_stream;
    std::copy(translation.begin(), translation.end(), std::ostream_iterator<string>(translation_stream, "\n"));
    const auto translation_string = translation_stream.str();

    Log::log("Translation:\n" + translation_string + "\n", ErrorLevel::INFO);

    // Parse the instructions via AsmTK
    if (auto error = parser.parse(translation_string.c_str())) {
        Log::log(string("AsmTK error: ") + DebugUtils::errorAsString(error), ErrorLevel::SEV);
        return {};
    }

    // Generate the binary code via AsmJit
    uint64_t translation_address = 0;
    if (auto error = m_asmjit_rt.add(&translation_address, &code)) {
        Log::log(string("AsmJit error: ") + DebugUtils::errorAsString(error), ErrorLevel::SEV);
        return {};
    }

    Log::log("Translation address: " + int_to_hex(translation_address) + "\n", ErrorLevel::INFO);

    return {translation_address};
}

/**
 * Makes an instruction with stored absolute address, but sets the instruction as relative
 * to fit into the existing entry-table logic
 */
Instruction makeRelJmpWithAbsDest(const uint64_t address, const uint64_t abs_destination) {
    Instruction::Displacement disp{};
    disp.Absolute = abs_destination;
    Instruction instruction(
        address, disp, 1, true, false, {0xE9, 0, 0, 0, 0}, "jmp", int_to_hex(abs_destination), Mode::x64
    );
    instruction.setDisplacementSize(4);
    instruction.setHasDisplacement(true);

    return instruction;
}

bool x64Detour::makeTrampoline(insts_t& prologue, insts_t& outJmpTable) {
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
    insts_t instsNeedingEntry;
    insts_t instsNeedingReloc;
    insts_t instsNeedingTranslation;
    insts_t instsNeedingAbsJmps;
    int64_t delta;

    uint8_t neededEntryCount = std::max((uint8_t) instsNeedingEntry.size(), (uint8_t) 5);

    const auto jmp_size = getMinJmpSize() + destHldrSz;
    const auto alignment_pad_size = 7; //extra bytes for dest-holders 8 bytes alignment

    // prol + jmp back to prol + N * jmpEntries + align pad
    m_trampolineSz = (uint16_t) (prolSz + jmp_size * (1 + neededEntryCount) + alignment_pad_size);

    // allocate new trampoline before deleting old to increase odds of new mem address
    auto tmpTrampoline = (uint64_t) new uint8_t[m_trampolineSz];
    if (m_trampoline != NULL) {
        delete[] (uint8_t*) m_trampoline;
    }

    m_trampoline = tmpTrampoline;
    delta = m_trampoline - prolStart;

    buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
    if(!instsNeedingEntry.empty()) {
        Log::log("Instructions needing entry:\n" + instsToStr(instsNeedingEntry) + "\n", ErrorLevel::INFO);
    }
    if(!instsNeedingReloc.empty()) {
        Log::log("Instructions needing relocation:\n" + instsToStr(instsNeedingReloc) + "\n", ErrorLevel::INFO);
    }
    if(!instsNeedingTranslation.empty()) {
        Log::log("Instructions needing translation:\n" + instsToStr(instsNeedingTranslation) + "\n", ErrorLevel::INFO);
    }

    Log::log("Trampoline address: " + int_to_hex(m_trampoline), ErrorLevel::INFO);

    for (auto& instruction: instsNeedingTranslation) {
        const auto inst_offset = instruction.getAddress() - prolStart;
        // Address of the instruction that follows the problematic instruction
        const uint64_t resume_address = m_trampoline + inst_offset + instruction.size();
        auto opt_translation_address = generateTranslationRoutine(instruction, resume_address);
        if (!opt_translation_address) {
            return false;
        }

        // replace the rip-relative instruction with jump to translation
        auto inst_iterator = std::find(prologue.begin(), prologue.end(), instruction);
        const auto jump = makeRelJmpWithAbsDest(instruction.getAddress(), *opt_translation_address);
        *inst_iterator = jump;
        instsNeedingEntry.push_back(jump);
        instsNeedingAbsJmps.push_back(jump);

        // nop the garbage bytes if necessary.
        const auto nop_size = (uint16_t) (instruction.size() - jump.size());
        if (nop_size < 1) {
            continue;
        }

        const auto nop_base = jump.getAddress() + jump.size();
        for (auto&& nop : make_nops(nop_base, nop_size)) {
            if (inst_iterator == prologue.end()) {
                prologue.push_back(nop);
                inst_iterator = prologue.end();
            } else {
                // insert after current instruction
                inst_iterator = prologue.insert(inst_iterator + 1, nop);
            }
        }
    }

    MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

    // Insert jmp from trampoline -> prologue after overwritten section
    const uint64_t jmpToProlAddr = m_trampoline + prolSz;

    const auto trampoline_end = m_trampoline + m_trampolineSz;
    // & ~0x7 for 8 bytes align for performance.
    const uint64_t jmpHolderCurAddr = (trampoline_end - destHldrSz) & ~0x7;
    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prolStart + prolSz, jmpHolderCurAddr);

    Log::log("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
    ZydisDisassembler::writeEncoding(jmpToProl, *this);

    // each jmp tbl entries holder is one slot down from the previous (lambda holds state)
    const auto makeJmpFn = [&, captureAddress = jmpHolderCurAddr](uint64_t a, Instruction& inst) mutable {
        captureAddress -= destHldrSz;
        assert(captureAddress > (uint64_t) m_trampoline && (captureAddress + destHldrSz) < trampoline_end);

        // move inst to trampoline and point instruction to entry
        const bool isIndirectCall = inst.isCalling() && inst.isIndirect();
        const bool isAbsJmp = vector_contains(instsNeedingAbsJmps, inst);
        auto oldDest = isAbsJmp ? inst.getAbsoluteDestination() : inst.getDestination();
        inst.setAddress(inst.getAddress() + delta);
        inst.setDestination(isIndirectCall ? captureAddress : a);

        // ff 25 indirect call re-written to point at dest-holder.
        // e8 direct call, or jmps of any kind point to literal jmp instruction
        return isIndirectCall
               ? makex64DestHolder(oldDest, captureAddress)
               : makex64MinimumJump(a, oldDest, captureAddress);
    };

    const uint64_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
    outJmpTable = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);

    return true;
}

}
