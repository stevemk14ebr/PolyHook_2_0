//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include <cstdint>
#include <inttypes.h>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>
#include "TestErrorSystem.hpp"

namespace PLH {
    class Instruction {
    public:
        union Displacement{
            int64_t Relative;
            uint64_t Absolute;
        };

        Instruction(uint64_t Address,const Displacement& displacement,bool IsRelative,const std::vector<uint8_t>& Bytes,const std::string Mnemonic,const std::string OpStr)
        {
            Init(Address,displacement,IsRelative,Bytes,Mnemonic,OpStr);
        }

        Instruction(uint64_t Address,const Displacement& displacement,bool IsRelative,uint8_t Bytes[], size_t ArrLen, const std::string Mnemonic,const std::string OpStr)
        {
            std::vector<uint8_t> Arr;
            Arr.assign(Bytes,Bytes+ArrLen);
            Init(Address,displacement,IsRelative,Arr,Mnemonic,OpStr);
        }

        int64_t GetDestination()
        {
            if(m_IsRelative)
            {
                return m_Address + m_Displacement.Relative + Size();
            }
            return m_Displacement.Absolute;
        }

        uint64_t GetAddress() const {
            return m_Address;
        }

        Displacement GetDisplacement() const
        {
            return m_Displacement;
        }

        const std::vector<uint8_t>& GetBytes() const
        {
            return m_Bytes;
        }

        std::string GetMnemonic() const
        {
            return m_Mnemonic;
        }

        std::string GetFullName() const
        {
            return m_Mnemonic + " " + m_OpStr;
        }

        uint8_t GetByte(uint32_t index) const
        {
            if(index >= Size())
                return 0;

            return m_Bytes[index];
        }

        size_t Size() const
        {
            return m_Bytes.size();
        }
    private:
        void Init(uint64_t Address,const Displacement& displacement,bool IsRelative,const std::vector<uint8_t>& Bytes,const std::string Mnemonic,const std::string OpStr)
        {
            m_Address = Address;
            m_Displacement = displacement;
            m_Bytes = Bytes;
            m_Mnemonic = Mnemonic;
            m_OpStr = OpStr;
            m_IsRelative = IsRelative;
        }
        uint64_t m_Address;
        Displacement m_Displacement;
        bool m_IsRelative;
        std::vector<uint8_t> m_Bytes;
        std::string m_Mnemonic;
        std::string m_OpStr;
    };

    class ADisassembler {
    public:
        enum class Mode {
            x86,
            x64
        };

        ADisassembler(Mode mode)
        {
            m_Mode = mode;
        }

        virtual ~ADisassembler() = default;

        /**Disassemble a code buffer and return a vector holding the asm instructions info
         * @param FirstInstruction: The address of the first instruction
         * @param Start: The address of the code buffer
         * @param End: The address of the end of the code buffer
         * **/
        virtual std::vector<std::unique_ptr<PLH::Instruction>> Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) = 0;

        typedef PLH::EventDispatcher<void(const PLH::Message&)> tErrorHandler;
        virtual tErrorHandler& OnError()
        {
            return m_ErrorCallback;
        }
    protected:
        Mode m_Mode;
        tErrorHandler m_ErrorCallback;
    };
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
