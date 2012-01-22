/*
   setLTO4key: Set LTO4 Encryption Key

   Copyright (c) 2008  Andrew Schretter <schrett@math.duke.edu>
   Provided under GPL license

   added clear encryption,
     sense key and
     error printouts - Gerard J. Cerchio <gjpc@circlesoft.com>
*/

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SENSE_BUFF_LEN 	96			/* from lto spec */

/*
 * here is a sample key - create a file with these HEX digits:
   4418AFCD046F2535B2E996123CE7DE3D418A15915A091C4BA12BDC85D4069A77
 */

/*
 * A good sg_io_hdr_t reference: http://tldp.org/HOWTO/SCSI-Generic-HOWTO/sg_io_hdr_t.html
 */

/* Print a hexadecimal dump of a block of data */
void hexdump(void *data, int size)
{
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }

        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) {
            /* line completed */
            printf("  [%4.4s]  %-49.49s %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, " ", sizeof(hexstr)-strlen(hexstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("  [%4.4s]  %-49.49s %s\n", addrstr, hexstr, charstr);
    }
}

/* Send a SCSI command block and display the result. */
void do_read_command(int fd, char *desc, unsigned char *cmd, int len)
{
        unsigned char sense[SENSE_BUFF_LEN];
        memset( sense, 0, SENSE_BUFF_LEN );

	    sg_io_hdr_t io;
        unsigned char buf[512];

        memset(buf, 0, sizeof(buf));

        memset(&io, 0, sizeof(io));
        io.interface_id = 'S';
        io.cmd_len = len;
        io.mx_sb_len = 0;
        io.dxfer_direction = SG_DXFER_FROM_DEV;
        io.dxfer_len = sizeof(buf);
        io.dxferp = buf;
        io.cmdp = cmd;

        printf("Command: %s\n", desc);
        hexdump(cmd, len);

        if (ioctl(fd, SG_IO, &io) < 0) {
                printf("Error: %s\n", strerror(errno));
                return;
        }

        if ( io.sb_len_wr ){
			printf("Sense\n");
			hexdump( sense, SENSE_BUFF_LEN );
        }
        else
        	printf( "No Sense\n" );

        if ((io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        	printf("Failed with info 0x%02x  mask status 0x%02x  msg status 0x%02x  host status 0x%02x driver status 0x%02x\n", io.info, io.masked_status, io.msg_status, io.host_status, io.driver_status );
            return;
        }

        len = io.dxfer_len - io.resid;
        printf("Response: %d %s\n", len, (len == 1) ? "byte" : "bytes");
        hexdump(buf, len);
}

void do_write_command(int fd, char *desc, unsigned char *cmd, int len, char *data_desc, unsigned char *data, int datalen)
{
		unsigned char sense[SENSE_BUFF_LEN];
		memset( sense, 0, SENSE_BUFF_LEN );

        sg_io_hdr_t io;
        memset(&io, 0, sizeof(io));
        io.interface_id = 'S';
        io.cmd_len = len;
        io.mx_sb_len = SENSE_BUFF_LEN;
        io.dxfer_direction = SG_DXFER_TO_DEV;
        io.dxfer_len = datalen;
        io.dxferp = data;
        io.cmdp = cmd;
        io.sbp = sense;

        printf("Command: %s\n", desc);
        hexdump(cmd, len);
        printf("Data: %s\n", data_desc);
        hexdump(data, datalen);

        if (ioctl(fd, SG_IO, &io) < 0) {
                printf("Error: %s\n", strerror(errno));
                return;
        }

        if ( io.sb_len_wr ){
			printf("Sense\n");
			hexdump( sense, SENSE_BUFF_LEN );
        }
        else
        	printf( "No Sense\n" );

        if ((io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        	printf("Failed with info 0x%02x  mask status 0x%02x  msg status 0x%02x  host status 0x%02x driver status 0x%02x\n", io.info, io.masked_status, io.msg_status, io.host_status, io.driver_status );
                return;
        }

        len = io.dxfer_len - io.resid;
        printf("Response: %d %s\n", len, (len == 1) ? "byte" : "bytes");

        //hexdump(buf, len);
}

struct {
        char *description;
        int len;
        unsigned char cmd[16];
} commands[] = {
        { "SCSI Inquiry", 6,
          { 0x12, 0x00, 0x00, 0x00, 0xFF, 0x00 } },
        { "SCSI SPOUT Set Encryption Key", 12,
          { 0xb5, 0x20, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x34, 0x00, 0x00 } },
        { "SCSI SPIN Read Status", 12,
          { 0xa2, 0x20, 0x00, 0x20, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00 } },
        { NULL, 0, { 0 } },
};

struct {
        char *description;
        int len;
        unsigned char cmd[64];
} data[] = {
        { "SCSI SPOUT Send Encryption Key Page", 52,
          { 0x00, 0x10, 0x00, 0x30, 0x40, 0x00,
            0x02, 0x03, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20,
          } },
 	    { "SCSI SPOUT Clear Encryption Mode Page", 52,
		  { 0x00, 0x10, 0x00, 0x30, 0x40, 0x00,
		    0x00, 0x00, 0x01, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x20,
		  } },
        { NULL, 0, { 0 } },
};

int main(int argc, char **argv)
{
        FILE *fd2;
        int fd;
        int i = 0;

        if (argc < 2) {
                fprintf(stderr, "usage: %s /dev/sda < <keyfile.txt> | clear >\n", *argv);
                return 1;
        }

        if ((fd = open(argv[1], O_RDWR)) < 0) {
                perror(argv[1]);
                return 1;
        }

        if ((ioctl(fd, SG_GET_VERSION_NUM, &i) < 0) || (i < 30000)) {
                fprintf(stderr,"%s is not a sg device\n", argv[1]);
                close(fd);
                return 1;
        }

        printf("Opened %s\n", argv[1]);
        /* Send query command */
        do_read_command(fd, commands[0].description, commands[0].cmd, commands[0].len);

        if(argc > 2) {

        if ( strcasecmp( argv[2], "clear" ) == 0 ) {
			do_write_command(fd, commands[1].description, commands[1].cmd, commands[1].len, data[1].description, data[1].cmd, data[1].len);

        }
        else
        {
			if ((fd2 = fopen(argv[2], "r")) < 0) {
				perror(argv[2]);
				return 1;
				}

			for (i = 0; i < 32; i++) {
				if( fscanf(fd2, "%2x ", (unsigned int *) &data[0].cmd[i + 20]) != 1 ) {
					fprintf(stderr, "Keyfile Error reading %s\n", argv[2]);
					return 1;
					}
				}
			fclose(fd2);
			/* Set Encryption key*/
			do_write_command(fd, commands[1].description, commands[1].cmd, commands[1].len, data[0].description, data[0].cmd, data[0].len);
			}
        }

        /* Query encryption status */
        do_read_command(fd, commands[2].description, commands[2].cmd, commands[2].len);
        close(fd);
        return 0;
}

