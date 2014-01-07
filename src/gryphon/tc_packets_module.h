#ifndef TC_PACKETS_MODULE_INCLUDED
#define TC_PACKETS_MODULE_INCLUDED

#include <xcopy.h>
#include <gryphon.h>

int tc_send_init(tc_event_loop_t *event_loop);
void read_packets_from_pcap(char *pcap_file, char *filter);
int calculate_mem_pool_size(char *pcap_file, char *filter);

#endif /* TC_PACKETS_MODULE_INCLUDED */
