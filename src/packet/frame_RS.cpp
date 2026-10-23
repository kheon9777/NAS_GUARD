#include "packet/frame_RS.h"

#include "packet/mac.h"

namespace RS::packet {
frame_RS::frame_RS(frame_type type) : type_(type), src_mac_(0) {
}
frame_type frame_RS::type() const {
    return type_;
}
bool frame_RS::is_type(frame_type val) const {
    return type_ == val;
}
uint64_t frame_RS::src_mac() const {
    return src_mac_;
}
void frame_RS::set_src_mac(const uint8_t* bytes6) {
    src_mac_ = mac_pack(bytes6);
}
std::ostream& operator << (std::ostream& os, const frame_RS& f) {
    f.print(os);
    return os;
}
}
