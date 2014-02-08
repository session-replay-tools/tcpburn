#ifndef  TC_UTIL_INCLUDED
#define  TC_UTIL_INCLUDED

#include <xcopy.h>
#include <gryphon.h>


#define TCP_HDR_LEN(tcph) (tcph->doff << 2)
#define IP_HDR_LEN(iph) (iph->ihl << 2)                                                                 
#define EXTRACT_32BITS(p)   ((uint32_t)ntohl(*(uint32_t *)(p)))

#define TCP_PAYLOAD_LENGTH(iph, tcph) \
        (ntohs(iph->tot_len) - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *target,
        uint32_t ip, uint16_t port);
int check_pack_src(ip_port_pair_mappings_t *target, uint32_t ip, 
        uint16_t port, int src_flag);
bool tcp_seq_before(uint32_t seq1, uint32_t seq2);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
        int pack_len);

int get_l2_len(const unsigned char *frame, const int pkt_len, 
        const int datalink);
unsigned char *
get_ip_data(pcap_t *pcap, unsigned char *frame, const int pkt_len, 
        int *p_l2_len);

#endif   /* ----- #ifndef TC_UTIL_INCLUDED  ----- */

