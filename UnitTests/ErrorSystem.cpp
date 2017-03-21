//
// Created by steve on 3/19/17.
//
#include "../src/PolyHook.h"
#include "../Catch.hpp"
class TestDerived : public PLH::IHook
{
public:
    TestDerived() : PLH::IHook()
    {

    }

    virtual bool Hook() {

    }
    virtual void UnHook(){

    }

    virtual PLH::HookType GetType() {
        return PLH::HookType::UNKNOWN;
    }

    void AddError(std::string Msg){
        this->m_ErrorCallback.Invoke(Msg);
    }
};

bool GotEvent = false;
void fOnError(const PLH::Message& Err)
{
    INFO("Received Error")
    REQUIRE(Err.GetMessage().compare("Testing 123, 1.2.3") == 0);
    GotEvent = true;
}

TEST_CASE("Tests Message interface of IHook","[Message, EventDispatcher, IHook::OnError")
{
    TestDerived* Derived = new TestDerived();
    SECTION("Registering Handler and Sending Errors")
    {
        REQUIRE(GotEvent == false);
        Derived->OnError() += fOnError;
        Derived->AddError("Testing 123, 1.2.3");
        REQUIRE(GotEvent == true);
    }

    SECTION("Un-Registering Handler")
    {
        Derived->OnError()--;
        GotEvent = false;
        REQUIRE(GotEvent == false);
        Derived->AddError("Testing 123, 1.2.3");
        REQUIRE(GotEvent == false);
    }
}

