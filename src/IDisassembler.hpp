//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include <cstdint>
#include <vector>
#include <string>
class IDisassembler
{
public:
    IDisassembler() = default;
    virtual ~IDisassembler() = default;

    struct InstructionEncoding
    {
        

    };

    struct Instruction
    {
        uintptr_t m_Address;
        uint8_t m_Size;

        InstructionEncoding m_Encoding;

        std::vector<uint8_t> m_Bytes;
        std::string m_Mnemonic;
        std::string m_Operands;
    };
};
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
