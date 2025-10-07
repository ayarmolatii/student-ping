/*
 *  student_ping.c
 * 
 *  Побудова і відправка IPv4 пакету із IP прапорцями (DF/MF) і користувацьким розміром ICMP.
 * 
 *  Компіляція: gcc -o student_ping student_ping.c -Wall
 * 
 *  Запуск (під користувачем root):
 *    sudo ./student_ping -s 1472 -f DF 8.8.8.8
 * 
 *  Коментарі:
 *  - Розмір контенту (payload) = це розмір ICMP даних (не включаючи заголовки IP/ICMP).
 *  - Повний розмір ІР-пакету = 20 (IP Header) + 8 (ICMP Header) + payload.
 * - this example is to demonstrate students how to leverage IP Headers flags
 */

// CONNECT HEADERS (LIBRARIES):
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>      // struct iphdr
#include <netinet/ip_icmp.h> // struct icmphdr
#include <netinet/in.h>
#include <sys/types.h>

// CONSTANTS:
#define IP_HDRLEN 20
#define ICMP_HDRLEN 8

// КОНТРОЛЬНА СУМА (RFC 1071)
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *((unsigned char*)buf);
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

void usage(const char *p) {
    fprintf(stderr, "Usage: %s [-s payload_size] [-f flags] <dest_ip>\n", p);
    fprintf(stderr, "  -s <payload_size>  ICMP data bytes (default 56)\n");
    fprintf(stderr, "  -f <flags>         comma-separated IP flags: DF,MF (e.g. DF or DF,MF)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    int payload_size = 56; // default
    char *flags_arg = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "s:f:")) != -1) {
        switch (opt) {
            case 's': payload_size = atoi(optarg); break;
            case 'f': flags_arg = optarg; break;
            default: usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    char *dest_ip = argv[optind];

    if (payload_size < 0 || payload_size > 60000) {
        fprintf(stderr, "Invalid payload size\n");
        return 1;
    }

    // ПІДГОТОВКА ПРАПОРЦІВ
    unsigned short ip_frag = 0; // host order
    if (flags_arg) {
        char tmp[128];
        strncpy(tmp, flags_arg, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';

        char *tok = strtok(tmp, ",");
        while (tok) {
            if (strcasecmp(tok, "DF") == 0) {
                ip_frag |= 0x4000; // Don't Fragment
            } else if (strcasecmp(tok, "MF") == 0) {
                ip_frag |= 0x2000; // More Fragments
            } else {
                fprintf(stderr, "Unknown flag: %s\n", tok);
            }
            tok = strtok(NULL, ",");
        }
    }

    // СТВОРЮЄМО БУФЕР ПАКЕТУ
    int packet_len = IP_HDRLEN + ICMP_HDRLEN + payload_size;
    unsigned char *packet = malloc(packet_len);
    if (!packet) {
        perror("malloc");
        return 1;
    }
    memset(packet, 0, packet_len);

    // ВКАЗІВНИКИ ДО ЗАГОЛОВКІВ
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + IP_HDRLEN);
    unsigned char *data = packet + IP_HDRLEN + ICMP_HDRLEN;

    // ICMP ЗАГОЛОВОК
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(1);

    for (int i = 0; i < payload_size; ++i)
        data[i] = 'A' + (i % 26);

    icmp->checksum = 0;
    icmp->checksum = checksum((unsigned short *)icmp, ICMP_HDRLEN + payload_size);

    // IP ЗАГОЛОВОК
    ip->version = 4;
    ip->ihl = IP_HDRLEN / 4;
    ip->tos = 0;
    ip->tot_len = htons(packet_len);
    ip->id = htons(0x1234);
    ip->frag_off = htons(ip_frag & 0xE000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = inet_addr("0.0.0.0");
    ip->daddr = inet_addr(dest_ip);

    ip->check = checksum((unsigned short *)ip, IP_HDRLEN);

    // СОКЕТ
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket");
        free(packet);
        return 1;
    }

    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sd);
        free(packet);
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->daddr;

    ssize_t sent = sendto(sd, packet, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin));

    if (sent < 0) {
        perror("sendto");
        fprintf(stderr, "errno: %d (%s)\n", errno, strerror(errno));
    } else {
        printf("Sent %zd bytes to %s (payload=%d, flags=", sent, dest_ip, payload_size);
        if (ip_frag & 0x4000) printf("DF");
        if ((ip_frag & 0x4000) && (ip_frag & 0x2000)) printf(",");
        if (ip_frag & 0x2000) printf("MF");
        printf(")\n");
    }

    close(sd);
    free(packet);
    return 0;
}
