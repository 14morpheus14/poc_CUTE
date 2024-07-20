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

#define MAX_PACKET_SIZE 80
#define IP4_HDRLEN 20
#define TCP_HDRLEN 20

#define ROTL(X, R) (X) = (unsigned char) (((X) << (R)) & 0xff) | ((X) >> (8 - (R)))
#define ROUNDS 50000

unsigned int key_s[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

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
#define ETH_HDRLEN 14
int main(int argc, char *argv[])
{
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr); 
    // Create socket    
    int sd =0; 
    sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if(sd < 0){
        perror("Error[01]: Unable to create socket");
        return 1;
    }
    const char *opt;
    opt = "lo";
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(sd);
        exit(1);
    }
    while(1){
        if(recvfrom(sd, packet, MAX_PACKET_SIZE , 0, &saddr, (socklen_t *)&saddr_len) >=0){
        struct ip *ip_head = (struct ip*)(packet+ ETH_HDRLEN);
        struct tcphdr *tcp_head = (struct tcphdr*)(packet + ETH_HDRLEN + IP4_HDRLEN);
        
        
             if(ntohs(tcp_head->th_dport) == 23){
            
              printf( "   Encrypted Source IP  : %s\n", inet_ntoa(ip_head->ip_src));
              printf( "   Decrypted Source IP  : %s\n", ip4dcrypt(inet_ntoa(ip_head->ip_src), key_s));
              printf( "   Destination IP       : %s\n", inet_ntoa(ip_head->ip_dst));
              
              printf( "\nTCP header\n");
              printf( "   Source port          : %u\n", ntohs(tcp_head->th_sport));
              printf( "   Destination port     : %u\n", ntohs(tcp_head->th_dport));
              printf( "   Sequence number      : %u\n", ntohl(tcp_head->th_seq));
              printf( "   Ack number           : %u\n", ntohl(tcp_head->th_ack));
              printf( "   Header length        : %u Bytes\n", (unsigned int)tcp_head->th_off*4);
              printf( "   FLAGS                : %u\n", (unsigned int)tcp_head->th_flags);
              printf( "   Window               : %u\n", htons(tcp_head->th_win));
              printf( "   Checksum             : %u\n", htons(tcp_head->th_sum));
              printf( "   urgent Pointer       : %u\n", htons(tcp_head->th_urp));
              unsigned char *data = packet + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN;
              printf( "   Data                 : %s\n", data);
             }
             }
        
    }
    return 0;
}



    
    
    
    
    
    
    
         
    
    
    
    
