#include "settings.h"

#include <sstream>

namespace RS {
std::string settings::summary() const {
    std::ostringstream os;
    os << "tcp_rate " << tcp_rate_threshold << "/" << tcp_rate_window.count() << "s"
       << ", icmp_rate " << icmp_rate_threshold << "/" << icmp_rate_window.count() << "s"
       << ", scan " << scan_threshold << "/" << scan_window.count() << "s"
       << ", block_timeout " << block_timeout.count() << "s"
       << ", device_expire " << device_expire.count() << "s"
       << ", arp_spoof " << arp_spoof_threshold << "/" << arp_spoof_window.count() << "s";
    return os.str();
}
}
