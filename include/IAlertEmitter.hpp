#pragma once

#include "AlertEvent.hpp"

namespace netsentinel {

// IAlertEmitter is the contract for delivering an AlertEvent somewhere
// observable (console, log file, etc.).
//
// Interface only; the concrete implementation is ConsoleAlertEmitter.
class IAlertEmitter {
public:
    virtual ~IAlertEmitter() = default;

    virtual void emit(const AlertEvent& alert) = 0;
};

} // namespace netsentinel
