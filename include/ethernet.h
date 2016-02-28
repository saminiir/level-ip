struct eth_hdr 
{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    short ethertype;
    char* payload;
};

struct eth_hdr* init_eth_hdr(char* buf);
void print_eth_hdr(struct eth_hdr *ehdr);
