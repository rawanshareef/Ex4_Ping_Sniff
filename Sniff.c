#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdio.h>

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length
        iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};

struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_ICMP)
        {
            int ip_header_len = ip->iph_ihl * 4;
            struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            char *ip_src = inet_ntoa(ip->iph_sourceip);
            printf("\nFrom: %s -> ", ip_src);
            char *ip_dest = inet_ntoa(ip->iph_destip);
            printf("To: %s\n", ip_dest);
            printf("ICMP code: %d\n", icmph->code);
         //   printf("ICMP type: %d\n", icmph->type);
            if((icmph->type) == 8) //ICMP Type: 8 is request, 0 is reply.
                 printf("ICMP Type: Request\n");
            else if((icmph->type) == 0)
              printf("ICMP Type: Reply\n");
        }
    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}