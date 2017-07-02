//
// Created by steve on 3/25/17.
//

#ifndef POLYHOOK_2_0_INSTRUCTION_HPP
#define POLYHOOK_2_0_INSTRUCTION_HPP

#include <cstring> //memcpy
#include <string>
#include <vector>
#include <memory>
#include <iostream>
namespace PLH {
class Instruction
{
public:
    union Displacement
    {
        int64_t  Relative;
        uint64_t Absolute;
    };

    Instruction(uint64_t Address,
                const Displacement& displacement,
                const uint8_t DisplacementOffset,
                const bool IsRelative,
                const std::vector<uint8_t>& Bytes,
                const std::string Mnemonic,
                const std::string OpStr) {
        Init(Address, displacement, DisplacementOffset, IsRelative, Bytes, Mnemonic, OpStr);
    }

    Instruction(uint64_t Address,
                const Displacement& displacement,
                const uint8_t DisplacementOffset,
                bool IsRelative,
                uint8_t Bytes[],
                size_t ArrLen,
                const std::string Mnemonic,
                const std::string OpStr) {
        std::vector<uint8_t> Arr;
        Arr.assign(Bytes, Bytes + ArrLen);
        Init(Address, displacement, DisplacementOffset, IsRelative, Arr, Mnemonic, OpStr);
    }

    int64_t GetDestination() const {
        if (m_IsRelative) {
            return m_Address + m_Displacement.Relative + Size();
        }
        return m_Displacement.Absolute;
    }

    uint64_t GetAddress() const {
        return m_Address;
    }

    Displacement GetDisplacement() const {
        return m_Displacement;
    }

    void SetDisplacementOffset(const uint8_t offset) {
        m_DispOffset = offset;
    }

    uint8_t GetDisplacementOffset() const {
        return m_DispOffset;
    }

    bool IsDisplacementRelative() const {
        return m_IsRelative;
    }

    bool HasDisplacement() const {
        return m_HasDisplacement;
    }

    const std::vector<uint8_t>& GetBytes() const {
        return m_Bytes;
    }

    std::string GetMnemonic() const {
        return m_Mnemonic;
    }

    std::string GetFullName() const {
        return m_Mnemonic + " " + m_OpStr;
    }

    size_t Size() const {
        return m_Bytes.size();
    }

    void AddChild(const std::shared_ptr<Instruction>& Child) {
        m_Children.push_back(Child);
    }

    const std::vector<std::shared_ptr<Instruction>>& GetChildren() const {
        return m_Children;
    }

    void SetRelativeDisplacement(const int64_t displacement) {
        /**Update our class' book-keeping of this stuff and then modify the byte array.
         * This doesn't actually write the changes to the executeable code, it writes to our
         * copy of the bytes**/
        m_Displacement.Relative = displacement;
        m_IsRelative = true;
        m_HasDisplacement = true;

        memcpy(&m_Bytes[GetDisplacementOffset()], &m_Displacement.Relative, Size() - GetDisplacementOffset());
    }

    void SetAbsoluteDisplacement(const uint64_t displacement) {
        m_Displacement.Absolute = displacement;
        m_IsRelative = false;
        m_HasDisplacement = true;

        /**Update our class' book-keeping of this stuff and then modify the byte array.
         * This doesn't actually write the changes to the executeable code, it writes to our
         * copy of the bytes**/
        memcpy(&m_Bytes[GetDisplacementOffset()], &m_Displacement.Absolute, Size() - GetDisplacementOffset());
    }

protected:
    std::vector<std::shared_ptr<Instruction>> m_Children;
private:
    void Init(uint64_t Address,
              const Displacement& displacement,
              const uint8_t DisplacementOffset,
              const bool IsRelative,
              const std::vector<uint8_t>& Bytes,
              const std::string Mnemonic,
              const std::string OpStr) {
        m_Address      = Address;
        m_Displacement = displacement;
        m_DispOffset   = DisplacementOffset;
        m_IsRelative   = IsRelative;
        m_Bytes        = Bytes;
        m_Mnemonic     = Mnemonic;
        m_OpStr        = OpStr;
        m_HasDisplacement = false;
    }

    uint64_t     m_Address;       //Address the instruction is at
    Displacement m_Displacement;  //Where an instruction points too (valid for jmp + call types)
    uint8_t      m_DispOffset;    //Offset into the byte array where displacement is encoded
    bool         m_IsRelative;    //Does the displacement need to be added to the address to retrieve where it points too?
    bool         m_HasDisplacement; //Does this instruction have the displacement fields filled (only call + jmp types do)

    std::vector<uint8_t> m_Bytes; //All the raw bytes of this instruction
    std::string          m_Mnemonic; //If you don't know what these two are then gtfo of this source code :)
    std::string          m_OpStr;
};
}
#endif //POLYHOOK_2_0_INSTRUCTION_HPP
