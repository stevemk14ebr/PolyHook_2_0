//
// Created by steve on 3/25/17.
//

#ifndef POLYHOOK_2_0_INSTRUCTION_HPP
#define POLYHOOK_2_0_INSTRUCTION_HPP
#include <string>
#include <vector>
namespace PLH
{
    class Instruction
    {
    public:
        union Displacement
        {
            int64_t Relative;
            uint64_t Absolute;
        };

        Instruction(uint64_t Address,
                    const Displacement &displacement,
                    bool IsRelative,
                    const std::vector<uint8_t> &Bytes,
                    const std::string Mnemonic,
                    const std::string OpStr)
        {
            Init(Address, displacement, IsRelative, Bytes, Mnemonic, OpStr);
        }

        Instruction(uint64_t Address,
                    const Displacement &displacement,
                    bool IsRelative,
                    uint8_t Bytes[],
                    size_t ArrLen,
                    const std::string Mnemonic,
                    const std::string OpStr)
        {
            std::vector<uint8_t> Arr;
            Arr.assign(Bytes, Bytes + ArrLen);
            Init(Address, displacement, IsRelative, Arr, Mnemonic, OpStr);
        }

        int64_t GetDestination() const
        {
            if (m_IsRelative) {
                return m_Address + m_Displacement.Relative + Size();
            }
            return m_Displacement.Absolute;
        }

        uint64_t GetAddress() const
        {
            return m_Address;
        }

        Displacement GetDisplacement() const
        {
            return m_Displacement;
        }

        const std::vector<uint8_t> &GetBytes() const
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
            if (index >= Size())
                return 0;

            return m_Bytes[index];
        }

        size_t Size() const
        {
            return m_Bytes.size();
        }

        void AddChild(Instruction* Child)
        {
            m_Children.push_back(Child);
        }

        const std::vector<Instruction*>& GetChildren() const
        {
            return m_Children;
        }

        Instruction* GetChild(size_t index) const
        {
            if(index >= m_Children.size())
                return nullptr;

            return m_Children[index];
        }

        void SetRelativeDisplacement(const int64_t displacement)
        {
            m_Displacement.Relative = displacement;
            m_IsRelative = true;
        }

        void SetAbsoluteDisplacement(const uint64_t displacement)
        {
            m_Displacement.Absolute = displacement;
            m_IsRelative = false;
        }
    protected:
        std::vector<Instruction *> m_Children;
    private:
        void Init(uint64_t Address,
                  const Displacement &displacement,
                  bool IsRelative,
                  const std::vector<uint8_t> &Bytes,
                  const std::string Mnemonic,
                  const std::string OpStr)
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
}
#endif //POLYHOOK_2_0_INSTRUCTION_HPP
