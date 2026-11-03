#pragma once

#include "IAlertEmitter.hpp"

namespace netsentinel {

// ConsoleAlertEmitter is the concrete implementation of
// IAlertEmitter: prints an AlertEvent to standard output in a
// human-readable, explainable form (window, every triggered feature,
// its observed value, and its z-score).
class ConsoleAlertEmitter : public IAlertEmitter {
public:
    void emit(const AlertEvent& alert) override;
};

} // namespace netsentinel
