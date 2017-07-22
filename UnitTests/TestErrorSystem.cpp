//
// Created by steve on 3/19/17.
//
#include "headers/IHook.hpp"
#include "Catch.hpp"
class TestDerived : public PLH::IHook
{
public:
    TestDerived() : PLH::IHook()
    {

    }

    virtual bool hook() override {

    }

    virtual bool unHook() override {

    }

    virtual PLH::HookType getType() override {
        return PLH::HookType::UNKNOWN;
    }
};

bool GotEvent = false;
void fOnError(const PLH::Message& Err)
{
    INFO("Received Error")
    REQUIRE(Err.getMessage().compare("Testing 123, 1.2.3") == 0);
    GotEvent = true;
}

TEST_CASE("Tests Message interface of IHook","[Message, EventDispatcher, IHook::OnError")
{
    TestDerived* Derived = new TestDerived();
    SECTION("Registering Handler and Sending Errors")
    {
        REQUIRE(GotEvent == false);
        Derived->onError() += fOnError;
        Derived->sendError("Testing 123, 1.2.3");
        REQUIRE(GotEvent == true);
    }

    SECTION("Un-Registering Handler")
    {
        Derived->onError()--;
        GotEvent = false;
        REQUIRE(GotEvent == false);
        Derived->sendError("Testing 123, 1.2.3");
        REQUIRE(GotEvent == false);
    }
}