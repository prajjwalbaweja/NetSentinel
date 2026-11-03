#include "ConsoleAlertEmitter.hpp"

#include <iomanip>
#include <iostream>

namespace netsentinel {

void ConsoleAlertEmitter::emit(const AlertEvent& alert) {
    std::cout << "  !! ANOMALY  window [" << std::fixed << std::setprecision(1)
              << alert.window_start_sec << "s, " << alert.window_end_sec << "s)"
              << std::defaultfloat << std::setprecision(6) << "\n";
    for (const auto& tf : alert.triggered_features) {
        std::cout << "       - " << tf.feature_name << ": observed=" << tf.observed_value
                   << "  z=" << std::fixed << std::setprecision(3) << tf.z_score
                   << std::defaultfloat << std::setprecision(6) << "\n";
    }
}

} // namespace netsentinel
