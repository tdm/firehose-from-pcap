/*
 * This program attempts to reassemble a "firehose" binary from a
 * packet capture file.
 *
 * If you do not know what that means, you probably shouldn't be
 * running this code...
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef unsigned char  byte;
typedef unsigned short u16;
typedef signed   short s16;
typedef unsigned int   u32;
typedef signed   int   s32;
typedef unsigned long  u64;
typedef signed   long  s64;

struct pcap_file_header
{
    u32         magic;
    u16         ver_major;
    u16         ver_minor;
    s32         tz_off;
    u32         sigfigs;
    u32         snaplen;
    u32         linktype;
} __attribute__((packed));

struct pkt_header
{
    u32         ts_sec;
    u32         ts_usec;
    u32         frame_len;
    u32         capture_len;
} __attribute__((packed));

struct usb_urb
{
    u16         pcap_urb_len;
    byte        irp_id[8];
    u32         status;
    u16         function;
    byte        irp_info;
    u16         bus_id;
    u16         device_addr;
    byte        endpoint;
    byte        xfer_type;
    u32         data_len;
} __attribute__((packed));

#define DIR_FROM_HOST 0
#define DIR_TO_HOST 1

struct sahara_pkt
{
    u32         cmd;
    u32         len;
    u32         param[1];
} __attribute__((packed));

enum sahara_state
{
    STATE_SCANNING,
    STATE_IDLE,
    STATE_DEVICE_CMD_SENT,
    STATE_HOST_CMD_SENT,
    STATE_END
};

#define CMD_HELLO_REQUEST       0x01
#define CMD_HELLO_RESPONSE      0x02
#define CMD_READ_DATA           0x03
#define CMD_END_IMAGE           0x04
#define CMD_READ_DATA_64        0x12

void fatal(const char* msg)
{
    fprintf(stderr, "%s", msg);
    exit(1);
}

int fhfd = -1;
u32 fhpos;

enum sahara_state g_ss = STATE_SCANNING;
u32 g_off;
u32 g_len;

void process_packet(u32 pktnum, const byte* data, u32 len)
{
    struct usb_urb* urb = (struct usb_urb*)data;
    byte* payload = (byte*)(urb + 1);
    struct sahara_pkt* spkt = (struct sahara_pkt*)payload;
    int dir = urb->irp_info & 0x1;

    if (urb->data_len == 0) {
        return;
    }
    if (g_ss == STATE_SCANNING && dir == DIR_TO_HOST) {
        if (urb->data_len == 0x30 &&
                spkt->cmd == CMD_HELLO_REQUEST && spkt->len == 0x30) {
            printf("[%8u] hello\n", pktnum);
            g_ss = STATE_IDLE;
        }
        return;
    }
    if (g_ss == STATE_IDLE && dir == DIR_TO_HOST) {
        if (spkt->cmd == CMD_HELLO_RESPONSE) {
            /* hello response */
            return;
        }
        if (spkt->cmd == CMD_END_IMAGE) {
            printf("[%8u] end\n", pktnum);
            g_ss = STATE_END;
            return;
        }
        if (spkt->cmd != CMD_READ_DATA && spkt->cmd != CMD_READ_DATA_64) {
            fatal("Unexpected command\n");
        }
        g_ss = STATE_DEVICE_CMD_SENT;
        if (spkt->cmd == 0x03) {
            g_off = spkt->param[1];
            g_len = spkt->param[2];
        }
        else {
            /* XXX: Assume max 32-bit requests for now */
            g_off = spkt->param[2];
            g_len = spkt->param[4];
        }
        printf("[%8u] read off=%08x len=%08x\n", pktnum, g_off, g_len);

        /* Write zero padding to areas not requested by device */
        byte pad[4096];
        memset(pad, 0, sizeof(pad));
        while (fhpos < g_off) {
            u32 wlen = min(sizeof(pad), g_off - fhpos);
            write(fhfd, pad, wlen);
            fhpos += wlen;
        }
        lseek(fhfd, g_off, SEEK_SET);
    }
    else if (g_ss == STATE_DEVICE_CMD_SENT && dir == DIR_FROM_HOST) {
        if (urb->data_len != g_len) {
            fatal("Unexpected data packet len\n");
        }
        write(fhfd, payload, urb->data_len);
        fhpos += urb->data_len;
        g_ss = STATE_IDLE;
    }
}

int main(int argc, char** argv)
{
    int pcapfd;

    ssize_t nread;
    u32 pktnum = 0;

    struct pcap_file_header filehdr;
    struct pkt_header pkthdr;
    byte pktbuf[64*1024];

    if (argc != 3) {
        char msg[256];
        sprintf(msg, "Usage: %s <pcap-file> <firehose-file>\n", argv[0]);
        fatal(msg);
    }

    pcapfd = open(argv[1], O_RDONLY);
    if (pcapfd < 0) {
        fatal("Failed to open pcap file\n");
    }

    fhfd = open(argv[2], O_RDWR | O_CREAT, 0644);
    if (fhfd < 0) {
        fatal("Failed to open firehose file\n");
    }

    nread = read(pcapfd, &filehdr, sizeof(filehdr));
    if (nread != sizeof(filehdr)) {
        fatal("Failed to read from capture file\n");
    }
    if (filehdr.magic != 0xa1b2c3d4) {
        fatal("Not a capture file\n");
    }

    g_ss = STATE_SCANNING;
    while (g_ss != STATE_END) {
        ++pktnum;
        read(pcapfd, &pkthdr, sizeof(pkthdr));
        read(pcapfd, pktbuf, pkthdr.capture_len);
        process_packet(pktnum, pktbuf, pkthdr.capture_len);
    }

    close(fhfd);
    close(pcapfd);

    return 0;
}
