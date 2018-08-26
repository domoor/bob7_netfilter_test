#ifndef LIBNET_LIL_ENDIAN
#define LIBNET_LIL_ENDIAN 1		// Little Endian
#endif

#include <cstdint>			// uintN_t
#include <cstdio>			// printf()
#include <cstdlib>			// exit()
#include <cerrno>
#include <fstream>			// file in/out
#include <string>			// std::string
#include <regex>			// std::regex
#include <vector>			// std::vector
#include <unistd.h>
#include <arpa/inet.h>			// ntoh()
#include <netinet/in.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>	/* for IP/TCP header */
#include <iostream>

using namespace std;

#define PORT_HTTP       80
#define MAX_NUMBER	1000000
#define half(x, y)	((x)+(y))/2

vector<uint32_t> file_off;
ifstream in;

bool get_black_url_offset() {
    ifstream in_offset("Black_url_offset.txt");
    if(!in_offset.is_open()) {fprintf(stderr, "error: File not found\n"); return true;}
    string temp;

    puts("URL loading...");
    if(in_offset.is_open()) {
	for(uint32_t i=0; i<MAX_NUMBER; i++) {
	    getline(in_offset, temp);
	    file_off.push_back(stoi(temp));
	}
    }
    else { fprintf(stderr, "error: File not found\n"); return true; }
    in_offset.close();
    puts("URL load complete.");

    return false;
}

bool binarysearch(string URL) {
    uint32_t max_p = MAX_NUMBER;
    uint32_t min_p = 0;
    uint32_t now_p = half(max_p, min_p);

    while (1) {
        string black_url;
        in.seekg(file_off[now_p]);
        getline(in, black_url);
        int res = URL.compare(black_url);
        if(res == 0) {				// Matched.
            return true;
        }
        else if(max_p - min_p == 1) {		// Unmatched.
            return false;
        }
        else if(res < 0) {			// Front.
            max_p = now_p;
            now_p = half(max_p, min_p);
        }
        else if(res > 0) {			// Back.
            min_p = now_p;
            now_p = half(max_p, min_p);
        }
        else { fprintf(stderr, "error: occurred during search\n"); exit(1); }
    }
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb, uint8_t *nf_flag)
{
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if(ph) id = ntohl(ph->packet_id);
    nfq_get_payload(tb, &data);

    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)data;
    if(ip->ip_p == IPPROTO_TCP) {
	uint32_t ip_len = ip->ip_hl<<2;
        struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)((uint8_t*)ip + (ip->ip_hl<<2));
        if(ntohs(tcp->th_dport) == PORT_HTTP) {
	    uint32_t tcp_len = tcp->th_off<<2;
	    uint32_t http_len = ntohs(ip->ip_len) - ip_len - tcp_len;
	    uint8_t *http = (uint8_t*)tcp + tcp_len;
	    if(http_len) {
		string payload(http, http+http_len);
		if(strncmp(payload.c_str(), "GET", 3)) return id;

		static regex pattern("Host: ([^\n]+)");
		smatch m;
		if(regex_search(payload, m, pattern)) {
		    string URL = m[1].str();
		    if(binarysearch(URL)) {
			printf("\nBlocked URL : %s\n", URL.c_str());
            		*nf_flag = NF_DROP;
		    }
		}
	    }
        }
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    uint8_t nf_flag = NF_ACCEPT;
    uint32_t id = print_pkt(nfa, &nf_flag);
    return nfq_set_verdict(qh, id, nf_flag, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) { // open err
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    in.open("Black_url.txt");
    if(!in.is_open()) {fprintf(stderr, "error: File not found\n"); exit(1);}

    if(get_black_url_offset()) {fprintf(stderr, "error: program exit\n"); exit(1);}
    
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif
    printf("closing library handle\n");
    in.close();
    nfq_close(h);

    exit(0);
}
