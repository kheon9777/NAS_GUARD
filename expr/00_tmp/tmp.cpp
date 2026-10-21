#include <iostream>

class ip_rs
{
protected:
    int val_;
public:
    virtual void say() = 0;
    ip_rs(int val) : val_(val) {
        
    }
    ~ip_rs() = default;
    void wow() {
        std::cout << "wow\n";
    }
};

class child : public ip_rs
{
private:
    int data_;
public:
    child(int val, int data) : ip_rs(val), data_(data) {
    }
    ~child() {

    }
    void say() {
        std::cout << val_ << data_ << "\n";
        wow();
    }
    
};



int main()
{
    using namespace std;
    child c1{12,13};
    c1.say();
    c1.wow();

    /* code */
    return 0;
}
