#include <stdio.h>          // printf, puts
#include <string.h>         // memset
#include <stdlib.h>         // malloc, atoi
#include <unistd.h>         // close syscall
#include <sys/socket.h>     // socket APIs (bindtodevice is not present)
#include <arpa/inet.h>      // inet_ntoa is present
#include <netinet/tcp.h>    // TCP header = struct tcphdr
#include <netinet/udp.h>    // TCP header = struct tcphdr
#include <netinet/ip.h>     // IP header = struct ip
#include <openssl/evp.h>    // for PKCS5_PBKDF2_HMAC_SHA1

#define CODE "1.2.3.4"
#define IP_CUTE_ROUTER "127.0.0.1"
#define MAX_PACKET_SIZE 80
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define TCP_HDRLEN 20
#define HASHLEN 7
#define MSGLEN 10

unsigned int key_s[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
//	96 bit (12 bytes) pseudo header needed for transport layer checksum calculation 
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

// Generic checksum calculator
uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {                                                             // Sum up 2-byte values until none or only one byte left.
    sum += *(addr++);
    count -= 2;
  }
  
  if (count > 0)                                                                  // Add left-over byte, if any.
    sum += *(uint8_t *) addr;
  
  while (sum >> 16)                                                               // Fold 32-bit sum into 16 bits; we lose information by doing this, increasing the chances of a collision.
    sum = (sum & 0xffff) + (sum >> 16);                                           // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  
  answer = ~sum;                                                                  // Checksum is one's compliment of sum.
  return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum (struct ip *iphdr, struct udphdr *udphdr)
{
    char *pseudogram;
    struct pseudo_header psh;
    
    psh.source_address = iphdr->ip_src.s_addr;
	psh.dest_address = iphdr->ip_dst.s_addr;
	psh.placeholder = 0;
	psh.protocol = iphdr->ip_p;
	psh.udp_length = htons(sizeof(struct udphdr) + HASHLEN + TCP_HDRLEN + MSGLEN );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + HASHLEN + TCP_HDRLEN + MSGLEN;
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udphdr , sizeof(struct udphdr) + HASHLEN + TCP_HDRLEN + MSGLEN);
  
    return checksum ((uint16_t *) pseudogram, psize);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct ip *iphdr, struct tcphdr *tcphdr)
{
    char *pseudogram;
    struct pseudo_header psh;
    
    psh.source_address = iphdr->ip_src.s_addr;
	psh.dest_address = iphdr->ip_dst.s_addr;
	psh.placeholder = 0;
	psh.protocol = iphdr->ip_p;
	psh.udp_length = htons(sizeof(struct tcphdr) + HASHLEN + MSGLEN );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + HASHLEN + MSGLEN;
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcphdr , sizeof(struct tcphdr) + HASHLEN + MSGLEN);
  
    return checksum ((uint16_t *) pseudogram, psize);
}

// Allocate memory for an array of ints.
int *allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

#define ROTL(X, R) (X) = (unsigned char) (((X) << (R)) & 0xff) | ((X) >> (8 - (R)))
#define ROUNDS 50000

int change_key(unsigned char *key)
{
    const char *pwd = "Password";
    if(PKCS5_PBKDF2_HMAC_SHA1(pwd, strlen(pwd), (const unsigned char*)key, sizeof(key)-1, ROUNDS, sizeof(key), key) == 0 )
      fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
    
    return 0;
}

static inline void xor4(unsigned int *out, unsigned int *x, unsigned char *y)
{
    out[0] = (x[0] ^ y[0]) & 0xff;
    out[1] = (x[1] ^ y[1]) & 0xff;
    out[2] = (x[2] ^ y[2]) & 0xff;
    out[3] = (x[3] ^ y[3]) & 0xff;
}

static void arx_fwd(unsigned int *state)
{
    state[0] += state[1]; //b0 +=b1       
    state[2] += state[3]; //b2 +=b3
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b0 &=0xff
    ROTL(state[1], 2);    //rotl(b1,2)
    ROTL(state[3], 5);    //rotl(b3,5)
    state[1] ^= state[0]; //b1 ^= b0
    state[3] ^= state[2]; //b3 ^= b2
    ROTL(state[0], 4);    //rotl(b0,4)
    state[0] += state[3]; //b0 +=b3
    state[2] += state[1]; //b2 +=b1
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
    ROTL(state[1], 3);    //rotl(b1,3)
    ROTL(state[3], 7);    //rotl(b3,7)
    state[1] ^= state[2]; //b1 ^=b2
    state[3] ^= state[0]; //b3 ^=b0
    ROTL(state[2], 4);    //rotl(b2,4)
}

unsigned char *ip4crypt(unsigned char *ip, unsigned char *key)
{
    unsigned int state[4];
    unsigned int in[4] = {0,0,0,0};
    unsigned int out[4] = {0,0,0,0};
    unsigned char *output = (unsigned char*) malloc(sizeof(ip));
    if (4 == sscanf(ip,"%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]", &in[0], &in[1], &in[2], &in[3]))
    {
            xor4(state, in, key);
            arx_fwd(state);
            xor4(state, state, key + 4);
            arx_fwd(state);
            xor4(state, state, key + 8);
            arx_fwd(state);
            xor4(out, state, key + 12);
    }
    sprintf(output, "%d.%d.%d.%d", out[0], out[1], out[2], out[3]);
    return output;
}

void cook_packet(unsigned char *packet, unsigned char *ip_s, unsigned char *ip_d, unsigned char *code_, unsigned char *msg){
    // Cooking IP header

    struct ip iphdr;
    int status, *ip_flags;
    unsigned char *ip_enc;
    iphdr.ip_hl            = IP4_HDRLEN / sizeof (uint32_t);		                                            // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_v             = 4;					                                                                // Internet Protocol version (4 bits): IPv4
    iphdr.ip_tos           = 16;					                                                            // Type of service (8 bits) => 16 = low delay
    iphdr.ip_len           = htons (IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN);	                // Total length of datagram: IP header + IP data
    iphdr.ip_id            = htons (0);				                                                            // ID sequence number (16 bits): unused, since single datagram
    ip_flags               = allocate_intmem(4);                                                                // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
        ip_flags[0]        = 0;					                                                                // Zero (1 bit)
        ip_flags[1]        = 0;					                                                                // Do not fragment flag (1 bit)
        ip_flags[2]        = 0;					                                                                // More fragments following flag (1 bit)
        ip_flags[3]        = 0;					                                                                // Fragmentation offset (13 bits)
    iphdr.ip_off           = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) +  ip_flags[3]);
    iphdr.ip_ttl           = 55;   					                                                            // Time-to-Live (8 bits): default to maximum value of hops
    iphdr.ip_p             = IPPROTO_UDP;  				                                                        // Transport layer protocol (8 bits): 6 for TCP 17 for UDP
    iphdr.ip_sum           = 0;                                                                                 // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum           = checksum((uint16_t *) &iphdr, IP4_HDRLEN);
 
    ip_enc = ip4crypt(ip_s, key_s);
    inet_pton (AF_INET, ip_enc , &(iphdr.ip_src));	                                                            // Source IPv4 address (32 bits)
    inet_pton (AF_INET, ip_d , &(iphdr.ip_dst));	                                                            // Destination IPv4 address (32 bits) 
    
    // Cooking UDP header
    struct udphdr udp_head;
    udp_head.uh_sport      = htons (9296); 
    udp_head.uh_dport      = htons (5246);
    udp_head.uh_ulen       = htons (UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN);
    udp_head.uh_sum        = udp4_checksum (&iphdr, &udp_head);
    
    // Cooking TCP header
    struct tcphdr tcp_head;
    int *tcp_flags;
    tcp_head.th_sport      = htons (80);                                                                       // Source port number (16 bits)
    tcp_head.th_dport      = htons (23);                                                                       // Destination port number (16 bits)
    tcp_head.th_seq        = htonl (0);                                                                        // Sequence number (32 bits)
    tcp_head.th_ack        = htonl (0);                                                                        // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcp_head.th_x2         = 0;                                                                                // Reserved (4 bits): should be 0
    tcp_head.th_off        = TCP_HDRLEN / 4;                                                                   // Data offset (4 bits): size of TCP header in 32-bit words
    tcp_flags              = allocate_intmem(8);                                                               // Flags (8 bits)
        tcp_flags[0]       = 0;                                                                                // FIN flag (1 bit)
        tcp_flags[1]       = 1;                                                                                // SYN flag (1 bit): set to 1
        tcp_flags[2]       = 0;                                                                                // RST flag (1 bit)
        tcp_flags[3]       = 0;                                                                                // PSH flag (1 bit)
        tcp_flags[4]       = 0;                                                                                // ACK flag (1 bit)
        tcp_flags[5]       = 0;                                                                                // URG flag (1 bit)
        tcp_flags[6]       = 0;                                                                                // ECE flag (1 bit)
        tcp_flags[7]       = 0;                                                                                // CWR flag (1 bit)

    tcp_head.th_flags      = 0;
    for (int i=0; i<8; i++) {
        tcp_head.th_flags += (tcp_flags[i] << i);
    }
    tcp_head.th_win        = htons (65535);                                                                    // Window size (16 bits)
    tcp_head.th_urp        = htons (0);                                                                        // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcp_head.th_sum        = tcp4_checksum (&iphdr, &tcp_head);                                                // TCP checksum (16 bits)
    
    memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
  	memcpy (packet + IP4_HDRLEN, &udp_head, UDP_HDRLEN * sizeof (uint8_t));    
    memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, code_, HASHLEN * sizeof (uint8_t));
  	memcpy (packet + IP4_HDRLEN + UDP_HDRLEN + HASHLEN, &tcp_head, TCP_HDRLEN * sizeof (uint8_t));
    memcpy (packet + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN, msg, MSGLEN * sizeof (uint8_t));
    
}

int main(int argc, char *argv[])
{
    unsigned char *message = "hellohello";
    unsigned char *ip_4 = "192.168.43.12";
    unsigned char packet[MAX_PACKET_SIZE];
    
    printf(" Source IP: %s\n", ip_4);
    cook_packet(packet, ip_4, IP_CUTE_ROUTER , CODE , message);
    
    // Create socket    
    int sd =0; 
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0){
        perror("Error[01]: Unable to create socket");
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr (IP_CUTE_ROUTER);
    // Send packet
    if(sendto(sd, packet, MAX_PACKET_SIZE, 0,(struct sockaddr *) &sin, sizeof (sin)) < 0) {
           perror("Error[13]: Unable to send packet");
           return 1;
    }else{
    	    printf(" Packet Sent\n");
            if (change_key(key_s) !=0){
                perror("Error[14]: KEY_CHANGE FAILED");
                 return 1;
            }
    }    
    return 0;
}



    
    
    
    
    
    
    
         
    
    
    
    
