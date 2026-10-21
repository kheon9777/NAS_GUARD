
class ip_UDP_RS : public ip_RS {
private:
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_UDP_RS(const iphdr* ip, const udphdr* udp) : ip_RS(ip, ip_RS_type::UDP) {
        sport_ = ntohs(udp->uh_sport);
        dport_ = ntohs(udp->uh_dport);
        payload_len_ = 8;
        // payload_len = tot_len - ip_header_len - sizeof(udphdr);
    }
    void print(std::ostream& os) const override {
        os << "UDP " << src() << ":" << sport_ << " -> " << dst() << ":" << dport_;
    }
};
