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

#define IP_SERVER "127.0.0.1"
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

static void arx_bwd(unsigned int *state)
{
    ROTL(state[2], 4);    //rotl(b2,4)
    state[1] ^= state[2]; //b1 ^=b2
    state[3] ^= state[0]; //b3 ^=b0
    ROTL(state[1], 5);    //rotl(b1,5)
    ROTL(state[3], 1);    //rotl(b3,1)
    state[0] -= state[3]; //b0 -=b3
    state[2] -= state[1]; //b2 -=b1
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
    ROTL(state[0], 4);    //rotl(b0,4)
    state[1] ^= state[0]; //b1 ^=b0
    state[3] ^= state[2]; //b3 ^=b2
    ROTL(state[1], 6);    //rotl(b1,6)
    ROTL(state[3], 3);    //rotl(b3,3)
    state[0] -= state[1]; //b0 -=b1
    state[2] -= state[3]; //b2 -=b3
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
}

unsigned char *ip4dcrypt(unsigned char *ip, unsigned char *key)
{
    unsigned int state[4];
    unsigned int in[4] = {0,0,0,0};
    unsigned int out[4] = {0,0,0,0};
    unsigned char *output = (unsigned char*) malloc(sizeof(ip));
    if (4 == sscanf(ip,"%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]", &in[0], &in[1], &in[2], &in[3]))
    {
        
            xor4(state, in, key + 12);
            arx_bwd(state);
            xor4(state, state, key + 8);
            arx_bwd(state);
            xor4(state, state, key + 4);
            arx_bwd(state);
            xor4(out, state, key);
        
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
                print_content(packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, HASHLEN + TCP_HDRLEN + MSGLEN + IP4_ADDRLEN);
    
    struct ip *ip_head = (struct ip*)(packet + ETH_HDRLEN);
    struct udphdr *udp_head = (struct udphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN);
    unsigned char *code_enc = packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN;
    struct tcphdr *tcp_head = (struct tcphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + HASHLEN);
    unsigned char *message = packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN;
    unsigned char *ip_enc = packet + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + HASHLEN + TCP_HDRLEN + MSGLEN;
    
    printf( " Encrypted source ip: %s\n", ip_enc);
    // Resolve and inject source and destination IP
    unsigned char packet_resolved[MAX_PACKET_SIZE];
    
    //

    
    unsigned char *code_dec = ip4dcrypt(code_enc, key_f);
    
    if( strcmp(code_dec, "1.2.3.4") == 0){
    
    int status = inet_pton (AF_INET, IP_SERVER , &(ip_head->ip_dst));
    }
    ip_head->ip_p = IPPROTO_TCP;
    int status = inet_pton (AF_INET, ip_enc, &(ip_head->ip_src));
    
    memcpy(packet_resolved, ip_head, IP4_HDRLEN * sizeof (uint8_t));
    memcpy(packet_resolved + IP4_HDRLEN, tcp_head, TCP_HDRLEN * sizeof (uint8_t));
    memcpy(packet_resolved + IP4_HDRLEN + TCP_HDRLEN, message, MSGLEN * sizeof (uint8_t));
    printf(" IP Encrypted source : %s\n", inet_ntoa(ip_head->ip_src));  
    printf("PACKET SENT\n");
                
                // Print IP header content
                printf( "IP header DATA\n");
                print_content(packet_resolved, IP4_HDRLEN);
        
                // Print TCP header content
                printf( "UDP header DATA\n");
                print_content(packet_resolved + IP4_HDRLEN, TCP_HDRLEN);
        
                // Print PAYLOAD content
                printf( "Payload DATA\n");
                print_content(packet_resolved + IP4_HDRLEN + TCP_HDRLEN, TCP_HDRLEN + MSGLEN);
                
    
    
    // Inject destination IP && Forward
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr (IP_SERVER);
	
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
    
    if(sendto(sd, packet_resolved, MAX_PACKET_SIZE, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
           perror("Error[11]: Unable to send packet");
           return 1;
    }    
    
                          
    return 0; 
}

int main(int argc, char *argv[]){
    
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    
    // Open internal socket    
    int raw_in =0; 
    raw_in = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if(raw_in < 0){
        perror("Error[01]: Unable to create socket");
        return 1;
    }
    
    const char *opt = "lo";
    if (setsockopt(raw_in, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(raw_in);
        exit(1);
    }
    // Hang the router
    while(1){
        if(recvfrom(raw_in, packet, MAX_PACKET_SIZE, 0, &saddr, (socklen_t *)&saddr_len) >= 0){
       
            
       
            struct udphdr *udp_head = (struct udphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN);
            if(ntohs(udp_head->uh_dport) == 12222){
                printf("received-1\n");
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
