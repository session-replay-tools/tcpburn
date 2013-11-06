
#include <xcopy.h>
#include <gryphon.h>


ip_port_pair_mapping_t *
get_test_pair(ip_port_pair_mappings_t *transfer, uint32_t ip, uint16_t port)
{
    int                     i;
    ip_port_pair_mapping_t *pair, **mappings;

    pair     = NULL;
    mappings = transfer->mappings;
    for (i = 0; i < transfer->num; i++) {
        pair = mappings[i];
        if (ip == pair->online_ip && port == pair->online_port) {
            return pair;
        } else if (pair->online_ip == 0 && port == pair->online_port) {
            return pair;
        }
    }
    return NULL;
}

int
check_pack_src(ip_port_pair_mappings_t *transfer, uint32_t ip,
        uint16_t port, int src_flag)
{
    int                     i, ret;
    ip_port_pair_mapping_t *pair, **mappings;

    ret = UNKNOWN;
    mappings = transfer->mappings;

    for (i = 0; i < transfer->num; i++) {

        pair = mappings[i];
        if (CHECK_DEST == src_flag) {
            if (ip == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            } else if (0 == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            }
        } else if (CHECK_SRC == src_flag) {
            if (ip == pair->target_ip && port == pair->target_port) {
                ret = REMOTE;
                break;
            }
        }
    }

    return ret;
}

unsigned char *
cp_fr_ip_pack(tc_ip_header_t *ip_header)
{
    int            frame_len;
    uint16_t       tot_len;
    unsigned char *frame;
    
    tot_len   = ntohs(ip_header->tot_len);
    frame_len = ETHERNET_HDR_LEN + tot_len;
    frame     = (unsigned char *) malloc(frame_len);

    if (frame != NULL) {    
        memcpy(frame + ETHERNET_HDR_LEN, ip_header, tot_len);
    }    

    return frame;
}

inline bool
tcp_seq_before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1-seq2) < 0;
}

unsigned short
csum(unsigned short *packet, int pack_len) 
{ 
    register unsigned long sum = 0; 

    while (pack_len > 1) {
        sum += *(packet++); 
        pack_len -= 2; 
    } 
    if (pack_len > 0) {
        sum += *(unsigned char *) packet; 
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); 
    }

    return (unsigned short) ~sum; 
} 


static unsigned short buf[32768]; 

unsigned short
tcpcsum(unsigned char *iphdr, unsigned short *packet, int pack_len)
{       
    unsigned short        res;

    memcpy(buf, iphdr + 12, 8); 
    *(buf + 4) = htons((unsigned short) (*(iphdr + 9)));
    *(buf + 5) = htons((unsigned short) pack_len);
    memcpy(buf + 6, packet, pack_len);
    res = csum(buf, pack_len + 12);

    return res; 
}  

int
get_l2_len(const unsigned char *frame, const int pkt_len, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;
        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *) frame;
            switch (ntohs(eth_hdr->ether_type)) {
                case ETHERTYPE_VLAN:
                    return 18;
                    break;
                default:
                    return 14;
                    break;
            }
            break;
        case DLT_C_HDLC:
            return CISCO_HDLC_LEN;
            break;
        case DLT_LINUX_SLL:
            return SLL_HDR_LEN;
            break;
        default:
            tc_log_info(LOG_ERR, 0, "unsupported DLT type: %s (0x%x)", 
                    pcap_datalink_val_to_description(datalink), datalink);
            break;
    }

    return -1;
}

#ifdef FORCE_ALIGN
static unsigned char pcap_ip_buf[65536];
#endif

unsigned char *
get_ip_data(pcap_t *pcap, unsigned char *frame, const int pkt_len, 
        int *p_l2_len)
{
    int      l2_len;
    u_char  *ptr;

    l2_len    = get_l2_len(frame, pkt_len, pcap_datalink(pcap));
    *p_l2_len = l2_len;

    if (pkt_len <= l2_len) {
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(frame)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(frame)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(frame)[l2_len]);
#endif

    return ptr;

}

