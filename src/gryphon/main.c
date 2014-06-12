/*
 *  gryphon
 *  A powerful tool to simulate millions of concurrent users for loading testing
 *
 *  Copyright 2013 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      Bin Wang <wangbin579@gmail.com>
 */

#include <xcopy.h>
#include <gryphon.h>

/* global variables for gryphon client */
xcopy_clt_settings clt_settings;

int tc_raw_socket_out;
tc_event_loop_t event_loop;

#if (GRYPHON_SIGACTION)
static signal_t signals[] = {
    { SIGALRM, "SIGALRM", 0,    tc_time_sig_alarm },
    { SIGINT,  "SIGINT",  0,    gryphon_over },
    { SIGPIPE, "SIGPIPE", 0,    gryphon_over },
    { SIGHUP,  "SIGHUP",  0,    gryphon_over },
    { SIGTERM, "SIGTERM", 0,    gryphon_over },
    { 0,        NULL,     0,    NULL }
};
#endif

static void
usage(void)
{
    printf("gryphon " VERSION "\n");
#if (!GRYPHON_PCAP_SEND)
    printf("-x <transfer,> use <transfer,> to specify the IPs and ports of the source and target\n"
           "               servers. Suppose 'sourceIP' and 'sourcePort' are the IP and port \n"
           "               number of the source server you want to copy from, 'targetIP' and \n");
    printf("               'targetPort' are the IP and port number of the target server you want\n"
           "               to send requests to, the format of <transfer,> could be as follows:\n"
           "               'sourceIP:sourcePort-targetIP:targetPort,...'. Most of the time,\n");
    printf("               sourceIP could be omitted and thus <transfer,> could also be:\n"
           "               'sourcePort-targetIP:targetPort,...'. As seen, the IP address and the\n"
           "               port number are segmented by ':' (colon), the sourcePort and the\n");
    printf("               targetIP are segmented by '-', and two 'transfer's are segmented by\n"
           "               ',' (comma).\n"); 
#else
    printf("-x <transfer,> use <transfer,> to specify the IPs, ports and MAC addresses of\n"
           "               the source and target. The format of <transfer,> could be as follow:\n");
    printf("               'sourceIP:sourcePort@sourceMac-targetIP:targetPort@targetMac,...'.\n"
           "               Most of the time, sourceIP could be omitted and thus <transfer,> could\n"
           "               also be: sourcePort@sourceMac-targetIP:targetPort@targetMac,...'.\n");
    printf("               Note that sourceMac is the MAC address of the interface where \n"
           "               packets are going out and targetMac is the next hop's MAC address.\n");
#endif
    printf("-f <file,>     set the pcap file list\n");
    printf("-F <filter>    user filter (same as pcap filter)\n");
#if (GRYPHON_PCAP_SEND)
    printf("-o <device,>   The name of the interface to send. This is usually a driver\n"
           "               name followed by a unit number, for example eth0 for the first\n"
           "               Ethernet interface.\n");
#endif
    printf("-M <num>       MTU value sent to backend (default 1500)\n");
    printf("-u <num>       concurrent users\n");
    printf("-c <ip,>       client ips\n");
    printf("-a <num>       throughput factor(default 1)\n");
    printf("-i <num>       connection init speed fact(default 1024 connectins per second)\n");
    printf("-S <num>       MSS value sent back(default 1460)\n");
    printf("-C <num>       parallel connections between gryphon and intercept.\n"
           "               The maximum value allowed is 16(default 3 connections since 0.8.0)\n");
    printf("-s <server,>   intercept server list\n"
           "               Format:\n"
           "               ip_addr1:port1, ip_addr2:port2, ...\n");
    printf("-t <num>       set the session timeout limit. If gryphon does not receive response\n"
           "               from the target server within the timeout limit, the session would \n"
           "               be dropped by gryphon. When the response from the target server is\n"
           "               slow or the application protocol is context based, the value should \n"
           "               be set larger. The default value is 120 seconds\n");
    printf("-l <file>      save the log information in <file>\n"
           "-p <num>       set the target server listening port. The default value is 36524.\n");
    printf("-e <num>       port seed\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n");
    printf("-h             print this help and exit\n"
           "-v             version\n"
           "-m             define how to simulate client properties(default 0).\n"
           "               0, ip prioritized; otherwise,port prioritized\n"
           "-d             run as a daemon\n");
}



static int
read_args(int argc, char **argv)
{
    int  c;

    opterr = 0;
    while (-1 != (c = getopt(argc, argv,
         "x:" /* <transfer,> */
         "f:" /* input pcap file list */
         "F:" 
         "c:" /* client ip list */
         "a:" /* throughput factor */
         "I:" /* threshold interval time for acceleratation */
         "i:" 
#if (GRYPHON_PCAP_SEND)
         "o:" /* <device,> */
#endif
         "m:" 
         "u:" 
         "C:" /* parallel connections between gryphon and intercept */
         "p:" /* target server port to listen on */
         "e:" /* port seed */
         "M:" /* MTU sent to backend */
         "S:" /* mss value sent to backend */
         "t:" /* set the session timeout limit */
         "s:" /* real servers running intercept*/
         "l:" /* error log file */
         "P:" /* save PID in file */
         "L"  /* lonely */
         "h"  /* help, licence info */
         "v"  /* version */
         "d"  /* daemon mode */
        ))) {
        switch (c) {
            case 'x':
                clt_settings.raw_transfer = optarg;
                break;
            case 'f':
                clt_settings.raw_pcap_files = optarg;
                break;
            case 'F':
                clt_settings.filter = optarg;
                break;
            case 'a':
                clt_settings.throughput_factor = atoi(optarg);
                break;
            case 'c':
                clt_settings.raw_clt_ips = optarg;
                break;
            case 'I':
                clt_settings.interval = atoi(optarg);
                break;
            case 'i':
                clt_settings.conn_init_sp_fact = atoi(optarg);
                break;
#if (GRYPHON_PCAP_SEND)
            case 'o':
                clt_settings.output_if_name = optarg;
                break;
#endif
            case 'm':
                clt_settings.client_mode = atoi(optarg);
                break;
            case 'C':
                clt_settings.par_connections = atoi(optarg);
                break;
            case 'l':
                clt_settings.log_path = optarg;
                break;
            case 'u':
                clt_settings.users = atoi(optarg);
                break;
            case 'M':
                clt_settings.mtu = atoi(optarg);
                break;
            case 'S':
                clt_settings.mss = atoi(optarg);
                break;
            case 's':
                clt_settings.raw_rs_list = optarg;
                break;
            case 't':
                clt_settings.session_timeout = atoi(optarg);
                break;
            case 'h':
                usage();
                return -1;
            case 'v':
                printf ("gryphon version:%s\n", VERSION);
                return -1;
            case 'd':
                clt_settings.do_daemonize = 1;
                break;
            case 'e':
                clt_settings.port_seed = (unsigned int) atoi(optarg);
                break;
            case 'p':
                clt_settings.srv_port = atoi(optarg);
                break;
            case 'P':
                clt_settings.pid_file = optarg;
                break;
            case '?':
                switch (optopt) {    
                    case 'x':
                        fprintf(stderr, "gryphon: option -%c require a string\n", 
                                optopt);
                        break;
                    case 'l':
                    case 'P':
                        fprintf(stderr, "gryphon: option -%c require a file name\n", 
                                optopt);
                        break;
#if (GRYPHON_PCAP_SEND)
                    case 'o':
                        fprintf(stderr, "gryphon: option -%c require a device name\n",
                                optopt);
                        break;
#endif
                    case 's':
                        fprintf(stderr, "gryphon: option -%c require an ip address list\n",
                                optopt);
                        break;

                    case 'C':
                    case 'm':
                    case 'M':
                    case 'S':
                    case 't':
                    case 'e':
                    case 'p':
                        fprintf(stderr, "gryphon: option -%c require a number\n",
                                optopt);
                        break;

                    default:
                        fprintf(stderr, "gryphon: illegal argument \"%c\"\n",
                                optopt);
                        break;
                }
                return -1;

            default:
                fprintf(stderr, "gryphon: illegal argument \"%c\"\n", optopt);
                return -1;
        }
    }

    return 0;
}

static void
output_for_debug(int argc, char **argv)
{
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "gryphon version:%s", VERSION);
    /* print out target info */
    tc_log_info(LOG_NOTICE, 0, "target:%s", clt_settings.raw_transfer);

#if (GRYPHON_DEBUG)
    tc_log_info(LOG_NOTICE, 0, "GRYPHON_DEBUG mode");
#endif
#if (GRYPHON_SINGLE)
    tc_log_info(LOG_NOTICE, 0, "GRYPHON_SINGLE mode");
#endif
#if (GRYPHON_COMET)
    tc_log_info(LOG_NOTICE, 0, "GRYPHON_COMET mode");
#endif
#if (GRYPHON_ADVANCED)
    tc_log_info(LOG_NOTICE, 0, "GRYPHON_ADVANCED mode");
#endif
#if (GRYPHON_PCAP_SEND)
    tc_log_info(LOG_NOTICE, 0, "GRYPHON_PCAP_SEND mode");
#endif


}


static unsigned char 
char_to_data(const char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 10;
    }

    return 0;
}

static int 
parse_ip_port_pair(char *addr, uint32_t *ip, uint16_t *port, 
        unsigned char *mac)
{
    int      i, len;
    char    *p, *seq, *before_mac, *ip_s, *port_s;
    uint16_t tmp_port;

    if ((before_mac = strchr(addr, '@')) != NULL) {
        *before_mac = '\0';
    }

    if ((seq = strchr(addr, ':')) == NULL) {
        tc_log_info(LOG_NOTICE, 0, "set global port for gryphon");
        *ip = 0;
        port_s = addr;
    } else {
        ip_s = addr;
        port_s = seq + 1;

        *seq = '\0';
        *ip = inet_addr(ip_s);
        *seq = ':';
    }

    tmp_port = atoi(port_s);
    *port = htons(tmp_port);

    if (before_mac != NULL) {
        p = before_mac + 1;
        len = strlen(p);
        
        if (len < ETHER_ADDR_STR_LEN) {
            tc_log_info(LOG_WARN, 0, "mac address is too short:%d", len);
            return -1;
        }

        for (i = 0; i < ETHER_ADDR_LEN; ++i) {
            mac[i]  = char_to_data(*p++) << 4;
            mac[i] += char_to_data(*p++);
            p++;
        }   

        *before_mac = '@';
    }

    return 0;
}

/*
 * two kinds of target formats:
 * 1) 192.168.0.1:80-192.168.0.2:8080
 * 2) 80-192.168.0.2:8080
 */
static int
parse_target(ip_port_pair_mapping_t *ip_port, char *addr)
{
    char   *seq, *addr1, *addr2;

    if ((seq = strchr(addr, '-')) == NULL) {
        tc_log_info(LOG_WARN, 0, "target \"%s\" is invalid", addr);
        return -1;
    } else {
        *seq = '\0';
    }

    addr1 = addr;
    addr2 = seq + 1;

    parse_ip_port_pair(addr1, &ip_port->online_ip, &ip_port->online_port,
            ip_port->src_mac);
    parse_ip_port_pair(addr2, &ip_port->target_ip, &ip_port->target_port,
            ip_port->dst_mac);

    if (ip_port->target_ip == LOCALHOST) {
        clt_settings.target_localhost = 1;
        tc_log_info(LOG_WARN, 0, "target host is 127.0.0.1");
        tc_log_info(LOG_WARN, 0, 
                "only client requests from localhost are valid");
    }

    *seq = '-';

    return 0;
}

/*
 * retrieve target addresses
 * format
 * 192.168.0.1:80-192.168.0.2:8080,192.168.0.1:8080-192.168.0.3:80
 */
static int
retrieve_target_addresses(char *raw_transfer,
        ip_port_pair_mappings_t *transfer)
{
    int   i;
    char *p, *seq;

    if (raw_transfer == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -x argument");
        fprintf(stderr, "no -x argument\n");
        return -1;
    }

    for (transfer->num = 1, p = raw_transfer; *p; p++) {
        if (*p == ',') {
            transfer->num++;
        }
    }

    transfer->mappings = malloc(transfer->num *
                                sizeof(ip_port_pair_mapping_t *));
    if (transfer->mappings == NULL) {
        return -1;
    }
    memset(transfer->mappings, 0 , 
            transfer->num * sizeof(ip_port_pair_mapping_t *));

    for (i = 0; i < transfer->num; i++) {
        transfer->mappings[i] = malloc(sizeof(ip_port_pair_mapping_t));
        if (transfer->mappings[i] == NULL) {
            return -1;
        }
        memset(transfer->mappings[i], 0, sizeof(ip_port_pair_mapping_t));
    }

    p = raw_transfer;
    i = 0;
    for ( ;; ) {
        if ((seq = strchr(p, ',')) == NULL) {
            parse_target(transfer->mappings[i++], p);
            break;
        } else {
            *seq = '\0';
            parse_target(transfer->mappings[i++], p);
            *seq = ',';

            p = seq + 1;
        }
    }

    return 0;
}


static int retrieve_real_servers() 
{
    int          count = 0;
    char        *split, *p, *seq, *port_s;
    uint16_t     port;
    uint32_t     ip;

    p = clt_settings.raw_rs_list;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            *split = '\0';
        }

        if ((seq = strchr(p, ':')) == NULL) {
            tc_log_info(LOG_NOTICE, 0, "set only ip for gryphon");
            port  = 0;
            ip = inet_addr(p);
        } else {
            port_s = seq + 1;
            *seq = '\0';
            ip = inet_addr(p);
            port = atoi(port_s);
            *seq = ':';
        }

        if (split != NULL) {
            *split = ',';
        }

        clt_settings.real_servers.ips[count] = ip;
        clt_settings.real_servers.ports[count++] = port;

        if (count == MAX_REAL_SERVERS) {
            tc_log_info(LOG_WARN, 0, "reach the limit for real servers");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }

    }

    clt_settings.real_servers.num = count;

    return 1;

}


static bool check_client_ip_valid(uint32_t ip)
{
    int   i;

    for (i = 0; i < clt_settings.transfer.num; i++) {
        if (ip == clt_settings.transfer.mappings[i]->target_ip) {
            return false;
        }
    }

    return true;
}


static int retrieve_client_ips() 
{
    int          count = 0, len, i;
    char        *split, *p, tmp_ip[32], *q;
    uint32_t     ip;

    p = clt_settings.raw_clt_ips;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            *split = '\0';
        }   

        len = strlen(p);
        if (len == 0) {
            tc_log_info(LOG_WARN, 0, "ip is empty");
            break;
        }

        if (p[len - 1] == '*') {
            strncpy(tmp_ip, p, len -1);
            q = tmp_ip + len - 1;
            for (i = 1; i < 255; i++) {
                sprintf(q, "%d", i);
                ip = inet_addr(tmp_ip);
                if (check_client_ip_valid(ip)) {
                    clt_settings.valid_ips[count++] = ip; 
                    if (count == M_CLIENT_IP_NUM) {
                        tc_log_info(LOG_WARN, 0, "reach limit for clt ips");
                        break;
                    }
                }
            }
        } else {
            ip = inet_addr(p);
            if (check_client_ip_valid(ip)) {
                clt_settings.valid_ips[count++] = ip; 
                if (count == M_CLIENT_IP_NUM) {
                    tc_log_info(LOG_WARN, 0, "reach limit for clt ips");
                    break;
                }   
            }
        }

        if (split != NULL) {
            *split = ',';
        }   

        if (count == M_CLIENT_IP_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for clt_tf_ip");
            break;
        }   

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }   

    }   

    clt_settings.valid_ip_num = count;

    return 1;

}

static int retrieve_pcap_files() 
{
    int          count = 0;
    char        *split, *p;

    p = clt_settings.raw_pcap_files;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            *split = '\0';
        }

        strcpy(clt_settings.pcap_files[count++].file, p);
        if (split != NULL) {
            *split = ',';
        }

        if (count == MAX_PCAP_FILES) {
            tc_log_info(LOG_WARN, 0, "reach the limit for pcap files");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }

    }

    clt_settings.num_pcap_files = count;

    return 1;

}


static int
set_details()
{

    clt_settings.session_keepalive_timeout = clt_settings.session_timeout;
    tc_log_info(LOG_NOTICE, 0, "keepalive timeout:%d", 
            clt_settings.session_keepalive_timeout);

    if (clt_settings.users <= 0) {
        tc_log_info(LOG_ERR, 0, "please set the -u parameter");
        return -1;
    }

    /* set the ip port pair mapping according to settings */
    if (retrieve_target_addresses(clt_settings.raw_transfer,
                              &clt_settings.transfer) == -1)
    {
        return -1;
    }

    if (clt_settings.raw_clt_ips == NULL) {
        tc_log_info(LOG_ERR, 0, "please set the -c parameter");
        return -1;
    }
    retrieve_client_ips();


    if (clt_settings.par_connections <= 0) {
        clt_settings.par_connections = 1;
    } else if (clt_settings.par_connections > MAX_CONNECTION_NUM) {
        clt_settings.par_connections = MAX_CONNECTION_NUM;
    }
    tc_log_info(LOG_NOTICE, 0, "parallel connections per target:%d",
            clt_settings.par_connections);

    if (clt_settings.raw_pcap_files == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -f argument for gryphon");
        fprintf(stderr, "no -f argument\n");
        return -1;
    }

    retrieve_pcap_files();

    if (clt_settings.throughput_factor < 1) {
        clt_settings.throughput_factor = 1;
    }

    tc_log_info(LOG_NOTICE, 0, "throughput factor: %d,interval:%llu ms",
            clt_settings.throughput_factor, clt_settings.interval);

    if (clt_settings.interval > 0) {
        clt_settings.interval = clt_settings.interval * 1000;
    }

    if (clt_settings.conn_init_sp_fact <= 0) {
        clt_settings.conn_init_sp_fact = DEFAULT_CONN_INIT_SP_FACT;
    }
    tc_log_info(LOG_NOTICE, 0, "init connections speed:%d", 
            clt_settings.conn_init_sp_fact);

#if (GRYPHON_PCAP_SEND)
    if (clt_settings.output_if_name != NULL) {
        tc_log_info(LOG_NOTICE, 0, "output device:%s", 
                clt_settings.output_if_name);
    } else {
        tc_log_info(LOG_ERR, 0, "output device is null");
        return -1;
    }
#endif

    /* retrieve real server ip addresses  */
    if (clt_settings.raw_rs_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "s parameter:%s", 
                clt_settings.raw_rs_list);
        retrieve_real_servers();
    } else {
        tc_log_info(LOG_WARN, 0, "no real server ip addresses");
        return -1;
    }

    /* daemonize */
    if (clt_settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "Failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemonize() in order to daemonize\n");
            return -1;
        }    
    }    

    return 0;
}

/* set default values for gryphon client */
static void
settings_init()
{
    /* init values */
    clt_settings.users = 0;
    clt_settings.mtu = DEFAULT_MTU;
    clt_settings.conn_init_sp_fact = DEFAULT_CONN_INIT_SP_FACT;
    clt_settings.mss = DEFAULT_MSS;
    clt_settings.srv_port = SERVER_PORT;
    clt_settings.port_seed = 0;
    clt_settings.par_connections = 2;
    clt_settings.client_mode = 0;
    clt_settings.session_timeout = DEFAULT_SESSION_TIMEOUT;
    
#if (GRYPHON_PCAP_SEND)
    clt_settings.output_if_name = NULL;
#endif

    tc_raw_socket_out = TC_INVALID_SOCKET;

}

static int 
set_timer()
{
    if (tc_time_set_timer(TIMER_INTERVAL) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    }

    return 0;
}

/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret, is_continue = 1;

    settings_init();

#if (GRYPHON_SIGACTION)
    if (set_signal_handler(signals) == -1) {
        return -1;
    }
#else
    signal(SIGALRM, tc_time_sig_alarm);
    signal(SIGINT,  gryphon_over);
    signal(SIGPIPE, gryphon_over);
    signal(SIGHUP,  gryphon_over);
    signal(SIGTERM, gryphon_over);
#endif

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }
    
    if (clt_settings.log_path == NULL) {
        clt_settings.log_path = "error_gryphon.log";
    }   

    if (tc_log_init(clt_settings.log_path) == -1) {
        return -1;
    }

    /* output debug info */
    output_for_debug(argc, argv);


    /* set details for running */
    if (set_details() == -1) {
        return -1;
    }

    if (set_timer() == -1) {
        return -1;
    }

    ret = tc_event_loop_init(&event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        is_continue = 0;
    } 

    if (is_continue) {
        ret = tc_build_session_table(65536);
        if (ret == TC_ERROR) {
            is_continue = 0;
        } else {
            ret = gryphon_init(&event_loop);
            if (ret == TC_ERROR) {
                is_continue = 0;
            } else {
                if (!tc_build_users(clt_settings.client_mode, 
                            clt_settings.users, clt_settings.valid_ips, 
                            clt_settings.valid_ip_num)) 
                {
                    is_continue = 0;
                }
            }
        }
    }

    if (is_continue) {
        /* run now */
        tc_event_process_cycle(&event_loop);
    }

    gryphon_release_resources();

    return 0;
}

