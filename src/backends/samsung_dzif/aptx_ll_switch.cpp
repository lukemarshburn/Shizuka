// SPDX-License-Identifier: GPL-2.0-only
#include "addresses.h"
#ifndef S25_HAL_ONLY
#include "aptx_ll_switch.h"
extern "C" __attribute__((visibility("hidden"))) void s25_anchor();
extern "C" __attribute__((visibility("hidden"))) bool tramp_ll_msg_send(void *, void *);
namespace {
uintptr_t base() { return (uintptr_t)&s25_anchor - 0x2000000; }
void *create_alarm() {
    return ((void *(*)(const char *, bool))(base() + S25_ADDR_ALARM_NEW))("s25.ll.codec-switch", false);
}
void schedule(void *alarm, uint64_t ms, void (*callback)(void *), void *context) {
    ((void (*)(void *, uint64_t, void (*)(void *), void *, void *, bool))(base() + S25_ADDR_ALARM_SET))(
        alarm, ms, callback, context, nullptr, true);
}
void release(void *buffer) { ((void (*)(void *)) * (uintptr_t *)(base() + S25_ADDR_FREE_GOT))(buffer); }
// Constant initialization: no C++ runtime / guard / global constructors.
s25::ll::SwitchGate gate;
} // namespace
extern "C" bool s25_ll_msg_send(void *ccb, void *buffer) {
    gate.bind({create_alarm, schedule, tramp_ll_msg_send, release});
    return gate.send(ccb, buffer);
}
#endif
