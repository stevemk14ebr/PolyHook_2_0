//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>
#include "ErrorSystem.hpp"

namespace PLH {

    class Instruction {
    public:
        union Displacement {
            int64_t m_Relative; //ex: jmp [rip+0x123], would store 0x123 (relative jmp from rip)
            int64_t m_Absolute; //ex: jmp 0x123, would store 0x123 (absolute jmp to 0x123)
        };

        uint64_t m_Address;
        bool m_IsRelativeToIP;          //is relative to rip/eip
        Displacement m_Displacement;
        std::vector<uint8_t> m_Bytes;   //actual bytes of the instruction
        std::string m_Mnemonic;         //jmp,call,ret,etc
        std::string m_Operands;         //everything after the mnemonic

        uint64_t GetDestination() const {
            if (m_Displacement.m_Absolute == 0 || m_Displacement.m_Relative == 0)
                return 0;

            if (!m_IsRelativeToIP)
                return m_Displacement.m_Absolute;

            return m_Address + m_Displacement.m_Relative + m_Bytes.size();
        }

        void SetNewDestination(const uint64_t Destination) {
            if (m_IsRelativeToIP) {
                if (m_Address < Destination)
                    m_Displacement.m_Relative = 0 - (m_Address - Destination) - Size();
                m_Displacement.m_Relative = Destination - (m_Address + Size());
            } else {
                m_Displacement.m_Absolute = Destination;
            }
        }

        std::string GetMnemonic() const {
            return m_Mnemonic;
        }

        std::string GetFullName() const {
            return m_Mnemonic + " " + m_Operands;
        }

        std::vector<uint8_t> GetBytes() const {
            return m_Bytes;
        }

        bool IsIpRelative() const {
            return m_IsRelativeToIP;
        }

        uint64_t GetAddress() const {
            return m_Address;
        }

        std::string ToString() {
            std::ostream output(nullptr); //no default constructor?
            output << std::hex << std::setfill('0') << std::setw(2) << m_Address;
            output << " ";
            for (uint_fast32_t i = 0; i < m_Bytes.size(); i++)
                output << std::hex << std::setfill('0') << std::setw(2) << m_Bytes[i];

            output << " ";
            output << GetFullName();
        }

        auto Size() const {
            return m_Bytes.size();
        }
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

        virtual std::vector<Instruction> Disassemble(uint64_t Start, uint64_t End) = 0;

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
