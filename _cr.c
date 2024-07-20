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

#include <net/if_arp.h>       				// ARPHRD_ETHER - Included by Reiki Yamhya on 25 Sept. 2019
#include <linux/if_ether.h>   				// ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD

#define IP_RP "127.0.0.1"
#define MAX_PACKET_SIZE 128
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define TCP_HDRLEN 20
#define HASHLEN 7
#define MSGLEN 10
#define IP4_ADDRLEN 4
#define ETH_HDRLEN 14  				    	// Ethernet header length

#define ROTL(X, R) (X) = (unsigned char) (((X) << (R)) & 0xff) | ((X) >> (8 - (R)))
#define ROUNDS 50000

unsigned int key_f[16] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

void print_content(unsigned char *buf, size_t length) {
    for(size_t i = 0; i < length; i++) {
        if(i != 0 && i % 16 == 0) {
            printf( "          ");
            for(size_t j = (i-16); j < i; j++) {
                if(buf[j] >= 32 && buf[j] <= 128) { // print "printable" characters
                    printf( "%c", (unsigned char)buf[j]);
                } else {
                    printf( "."); // Otherwise, add a dot
                }
            }
            printf( "\n");
        }

        if(i%16==0)
            printf( "    ");
        printf( " %02X", (unsigned int)buf[i]);

        if(i == (length-1)) {
            for(size_t j = 0; j < (15-1%16); j++)
                printf( "    ");
            printf( "          ");

            for(size_t j=(i-i%16); j <= 1; j++) {
                if(buf[j] >= 32 && buf[j] <= 128)
                    printf( "%c", (unsigned char)buf[j]);
                else
                    printf( ".");
            }
            printf( "\n");
        }
    }
}

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

int forward_packet(unsigned char *packet) {
    
    printf("PACKET RECEIVED\n");
                
                // Print IP header content
                printf( "IP header DATA\n");
                print_content(packet + ETH_HDRLEN, IP4_HDRLEN);
        
                // Print TCP header content
                printf( "UDP header DATA\n");
                print_content(packet+ ETH_HDRLEN + IP4_HDRLEN, UDP_HDRLEN);
        
                // Print PAYLOAD content
                printf( "Payload DATA\n");
                print_content(packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, HASHLEN + TCP_HDRLEN + MSGLEN);

                     
    // Extract source IP and encrypt it 
    struct ip *ip_head = (struct ip*)(packet + ETH_HDRLEN);
    struct udphdr *udp_head = (struct udphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN);
    unsigned char *code_ = packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN;
    struct tcphdr *tcp_head = (struct tcphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + HASHLEN);
    unsigned char *msg = packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN;

    printf( "Encrypted Ip source: %s\n", inet_ntoa(ip_head->ip_src));
 
    unsigned char packet_fwd[MAX_PACKET_SIZE];

    //
    unsigned char *ip_enc = inet_ntoa(ip_head->ip_src);
    int status = inet_pton (AF_INET, "32.24.1.2" , &(ip_head->ip_src));
    status = inet_pton (AF_INET, IP_RP, &(ip_head->ip_dst));    
    ip_head->ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN + IP4_ADDRLEN);   

    udp_head->uh_sport      = htons (5247); 
    udp_head->uh_dport      = htons (12222);
    udp_head->uh_ulen       = htons (UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN + IP4_ADDRLEN);

    unsigned char *code_enc = ip4crypt(code_, key_f);       
    
    //
    memcpy (packet_fwd, ip_head, IP4_HDRLEN * sizeof (uint8_t));
    memcpy (packet_fwd + IP4_HDRLEN, udp_head, UDP_HDRLEN * sizeof (uint8_t));    
    memcpy (packet_fwd + IP4_HDRLEN + UDP_HDRLEN, code_enc, HASHLEN * sizeof (uint8_t));
  	memcpy (packet_fwd + IP4_HDRLEN + UDP_HDRLEN + HASHLEN, tcp_head, TCP_HDRLEN * sizeof (uint8_t));
    memcpy (packet_fwd + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN, msg, MSGLEN * sizeof (uint8_t));    
    memcpy (packet_fwd + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN, ip_enc, IP4_ADDRLEN * sizeof (uint32_t));
      
    printf("PACKET SENT\n");
                
                // Print IP header content
                printf( "IP header DATA\n");
                print_content(packet_fwd, IP4_HDRLEN);
        
                // Print TCP header content
                printf( "UDP header DATA\n");
                print_content(packet_fwd + IP4_HDRLEN, UDP_HDRLEN);
        
                // Print PAYLOAD content
                printf( "Payload DATA\n");
                print_content(packet_fwd + IP4_HDRLEN + UDP_HDRLEN, HASHLEN + TCP_HDRLEN + MSGLEN + IP4_ADDRLEN);
                
    printf( " Encrypted ip: %s\n", packet_fwd + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN); 
    // Inject destination IP && Forward
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr (IP_RP);
	
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0){
        perror("Error[01]: Unable to create socket");
        return 1;
    }
    
    const char *opt = "lo";
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(sd);
        exit(1);
    }
    
    if(sendto(sd, packet_fwd, MAX_PACKET_SIZE, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
           perror("Error[11]: Unable to send packet");
           return 1;
    }else{    
        
        // Change rp_sync key
        if (change_key(key_f) !=0){
             perror("Error[12]: KEY_CHANGE FAILED");
             return 1;
        }
    }        
    
                          
    return 0; 
}

int main(int argc, char *argv[]){
    
    
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    // Open internal socket    
    int raw_ =0; 
    raw_ = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if(raw_ < 0){
        perror("Error[01]: Unable to create socket");
        return 1;
    }
        
    const char *opt;
    opt = "lo";
    if (setsockopt(raw_, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(raw_);
        exit(1);
    }
    
    
    // Hang the router
    while(1){
        // Receive packet    
        if(recvfrom(raw_, packet, MAX_PACKET_SIZE, 0, &saddr, (socklen_t *)&saddr_len) >= 0){
     
           struct udphdr *udp_head = (struct udphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN);
           if(ntohs(udp_head->uh_dport) == 5246){
                 
                if(forward_packet(packet) != 0){
                    perror("Error[07]: Unable to forward packet");
                    return 1;
                }
           }
        }else{
            perror("Error[06]: Unable to receive packet");
            return 1;
        }       
    }
    
    return(0);
}
