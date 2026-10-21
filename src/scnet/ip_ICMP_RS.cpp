

class ip_ICMP_RS : public ip_RS {
private:
    bool type_echo_;    // echo request
    bool type_echorp_;  // echo replay
    uint8_t type_;      // other type
public:
    ip_ICMP_RS(const iphdr* ip, const icmphdr* icmp) 
    : ip_RS(ip, ip_RS_type::ICMP), type_echo_(false), type_echorp_(false), type_(0) {
        if(icmp->type == ICMP_ECHO) {
            type_echo_ = true;
        } else if (icmp->type == ICMP_ECHOREPLY) {
            type_echorp_ = true;
        }
        type_ = icmp->type;

        payload_len_ = 9;
        // payload_len = tot_len - ip_header_len - sizeof(udphdr);
    }    
    void print(std::ostream& os) const override {
        os << "ICMP " << src() << " -> " << dst();
        if(type_echo_) os << " echo";
        else if(type_echorp_) os << " echo reply";
        else os << " type=" << type_;
    }
};