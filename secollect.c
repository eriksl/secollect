#define _GNU_SOURCE

#include "crc16modbus.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <stdbool.h>

typedef enum
{
	sc_no_tag,
	sc_tag_0,
	sc_tag_1,
	sc_tag_2,
	sc_datalen_lo,
	sc_datalen_hi,
	sc_datalen_inv_lo,
	sc_datalen_inv_hi,
	sc_sequence_lo,
	sc_sequence_hi,
	sc_addr_from_0,
	sc_addr_from_1,
	sc_addr_from_2,
	sc_addr_from_3,
	sc_addr_to_0,
	sc_addr_to_1,
	sc_addr_to_2,
	sc_addr_to_3,
	sc_function_lo,
	sc_function_hi,
	sc_data_no_tag,
	sc_data_tag_0,
	sc_data_tag_1,
	sc_data_tag_2,
	sc_crc_lo,
	sc_crc_hi,
} state_collector_t;

typedef enum
{
	log_error = 0,		//	E
	log_warning = 1,	//	!
	log_notice = 2,		//	-
	log_info = 3,		//	+
	log_debug = 4,		//	%
} log_level_t;

typedef struct
{
	int fd;
	int time_offset;
	unsigned int ix;
	unsigned int sequence;
	struct
	{
		unsigned int from;
		unsigned int to;
	} address;
	unsigned int function;
	struct
	{
		unsigned int length;
		const uint8_t *data;
	} payload;
	struct
	{
		const char *inverter;
		const char *optimiser;
	} script;
} message_t;

typedef struct
{
	unsigned int function;
	void (*process_function)(const message_t *);
} jump_table_function_t;

static void process_function_500(const message_t *);
static void process_function_501(const message_t *);

static const jump_table_function_t jump_table_function[] =
{
	{	0x0500,	process_function_500	},
	{	0x0501,	process_function_501	},
	{	0x00,	(void(*))0				},
};

typedef struct
{
	const message_t *message;
	unsigned int order;
	unsigned int type;
	unsigned int id;
	unsigned int data_length;
	const uint8_t *data;
} function_500_data_t;

typedef struct
{
	unsigned int type;
	void (*process_function)(const function_500_data_t *);
} jump_table_function_500_t;

static void process_function_500_type_10(const function_500_data_t *);
static void process_function_500_type_17(const function_500_data_t *);
static void process_function_500_type_18(const function_500_data_t *);
static void process_function_500_type_22(const function_500_data_t *);
static void process_function_500_type_40(const function_500_data_t *);
static void process_function_500_type_41(const function_500_data_t *);
static void process_function_500_type_42(const function_500_data_t *);
static void process_function_500_type_43(const function_500_data_t *);
static void process_function_500_type_44(const function_500_data_t *);
static void process_function_500_type_47(const function_500_data_t *);
static void process_function_500_type_48(const function_500_data_t *);
static void process_function_500_type_4d(const function_500_data_t *);
static void process_function_500_type_50(const function_500_data_t *);
static void process_function_500_type_82(const function_500_data_t *); // s440 optimiser data
static void process_function_500_type_300(const function_500_data_t *);
static void process_function_500_type_1800(const function_500_data_t *);

static const jump_table_function_500_t jump_table_500[] =
{
	{	0x10,	process_function_500_type_10	},
	{	0x17,	process_function_500_type_17	},
	{	0x18,	process_function_500_type_18	},
	{	0x22,	process_function_500_type_22	},
	{	0x40,	process_function_500_type_40	},
	{	0x41,	process_function_500_type_41	},
	{	0x42,	process_function_500_type_42	},
	{	0x43,	process_function_500_type_43	},
	{	0x44,	process_function_500_type_44	},
	{	0x47,	process_function_500_type_47	},
	{	0x48,	process_function_500_type_48	},
	{	0x4d,	process_function_500_type_4d	},
	{	0x50,	process_function_500_type_50	},
	{	0x82,	process_function_500_type_82	},
	{	0x300,	process_function_500_type_300	},
	{	0x1800,	process_function_500_type_1800	},
	{	0x0,	(void(*))0						},
};

static log_level_t log_level = log_error;

static unsigned int uint2le_to_unsigned(const uint8_t *ptr)
{
	return( (ptr[0] << 0) |
			(ptr[1] << 8));
}

static unsigned int uint4le_to_unsigned(const uint8_t *ptr)
{
	return( (ptr[0] << 0) |
			(ptr[1] << 8) |
			(ptr[2] << 16) |
			(ptr[3] << 24));
}

static float float4_to_float(const uint8_t *ptr)
{
	float rv;

	rv = *(const float *)ptr;

	return(rv);
}

static void unsigned_to_uint2le(uint8_t *ptr, unsigned int value)
{
	*ptr++ = (value & 0x000000ff) >>  0;
	*ptr++ = (value & 0x0000ff00) >>  8;
}

static void unsigned_to_uint4le(uint8_t *ptr, unsigned int value)
{
	*ptr++ = (value & 0x000000ff) >>  0;
	*ptr++ = (value & 0x0000ff00) >>  8;
	*ptr++ = (value & 0x00ff0000) >> 16;
	*ptr++ = (value & 0xff000000) >> 24;
}

#if 0
static void unsigned_to_uint4be(uint8_t *ptr, unsigned int value)
{
	*ptr++ = (value & 0xff000000) >> 24;
	*ptr++ = (value & 0x00ff0000) >> 16;
	*ptr++ = (value & 0x0000ff00) >>  8;
	*ptr++ = (value & 0x000000ff) >>  0;
}
#endif

static void stamp_to_string(unsigned int datestring_size, char *datestring, unsigned int stamp)
{
	time_t ticks;
	const struct tm *tm;

	ticks = (time_t)stamp;
	tm = localtime(&ticks);
	strftime(datestring, datestring_size - 1, "%Y-%m-%d %H:%M", tm);
}

static void dump(unsigned int length, const uint8_t *data)
{
	unsigned int ix;

	fprintf(stderr, "    ");

	for(ix = 0; ix < length; ix++)
	{
		if((ix % 4) == 0)
		{
			if(ix != 0)
				fprintf(stderr, "\n    ");
			fprintf(stderr, "%2u: ", ix);
		}

		fprintf(stderr, "%02x'%c' ", data[ix], (data[ix] >= ' ' && data[ix] <= '~') ? data[ix] : '.');
	}

	fprintf(stderr, "\n");
}

static void send_packet(int fd,
		unsigned int sequence,
		unsigned int address_from, unsigned int address_to,
		unsigned int function,
		unsigned int payload_length, const uint8_t *payload)
{
	uint8_t packet[1024];
	uint8_t *packet_ptr;
	uint8_t header1[4 + 2 + 2];
	uint8_t header2[12];
	unsigned int message_length;
	unsigned int crc;
	struct pollfd pfd[1];

	message_length = payload_length;

	uint8_t *ptr = header1;
	*ptr++ = 0x12;
	*ptr++ = 0x34;
	*ptr++ = 0x56;
	*ptr++ = 0x79;
	*ptr++ = (message_length & 0x00ff) >> 0;
	*ptr++ = (message_length & 0xff00) >> 8;
	message_length ^= 0xffff;
	*ptr++ = (message_length & 0x00ff) >> 0;
	*ptr++ = (message_length & 0xff00) >> 8;

	ptr = header2;
	*ptr++ = (sequence & 0xff00) >> 8;
	*ptr++ = (sequence & 0x00ff) >> 0;
	*ptr++ = (address_from & 0xff000000) >> 24;
	*ptr++ = (address_from & 0x00ff0000) >> 16;
	*ptr++ = (address_from & 0x0000ff00) >>  8;
	*ptr++ = (address_from & 0x000000ff) >>  0;
	*ptr++ = (address_to & 0xff000000) >> 24;
	*ptr++ = (address_to & 0x00ff0000) >> 16;
	*ptr++ = (address_to & 0x0000ff00) >>  8;
	*ptr++ = (address_to & 0x000000ff) >>  0;
	*ptr++ = (function & 0xff00) >> 8;
	*ptr++ = (function & 0x00ff) >> 0;

	crc = crc16modbus_byte(0x5a5a, header2, sizeof(header2));
	crc = crc16modbus_byte(crc, payload, payload_length);

	ptr = header2;
	*ptr++ = (sequence & 0x00ff) >> 0;
	*ptr++ = (sequence & 0xff00) >> 8;
	*ptr++ = (address_from & 0x000000ff) >>  0;
	*ptr++ = (address_from & 0x0000ff00) >>  8;
	*ptr++ = (address_from & 0x00ff0000) >> 16;
	*ptr++ = (address_from & 0xff000000) >> 24;
	*ptr++ = (address_to & 0x000000ff) >>  0;
	*ptr++ = (address_to & 0x0000ff00) >>  8;
	*ptr++ = (address_to & 0x00ff0000) >> 16;
	*ptr++ = (address_to & 0xff000000) >> 24;
	*ptr++ = (function & 0x00ff) >> 0;
	*ptr++ = (function & 0xff00) >> 8;

	pfd->fd = fd;
	pfd->events = POLLOUT;
	pfd->revents = 0;

	if((sizeof(header1) + sizeof(header2) + payload_length + 2) >= sizeof(packet))
	{
		if(log_level >= log_error)
			fprintf(stderr, "E packet buffer too small\n");
		return;
	}

	packet_ptr = packet;
	memcpy(packet_ptr, header1, sizeof(header1));
	packet_ptr += sizeof(header1);
	memcpy(packet_ptr, header2, sizeof(header2));
	packet_ptr += sizeof(header2);
	memcpy(packet_ptr, payload, payload_length);
	packet_ptr += payload_length;
	unsigned_to_uint2le(packet_ptr, crc);
	packet_ptr += 2;

	if(log_level >= log_debug)
		dump(packet_ptr - packet, packet);

	switch(poll(pfd, 1, 1000))
	{
		case(0):
		{
			if(log_level >= log_warning)
				fprintf(stderr, "! send poll timeout\n");
			break;
		}

		case(1):
		{
			if(pfd->revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
			{
				if(log_level >= log_warning)
					fprintf(stderr, "! send poll event failed\n");
				break;
			}

			if(pfd->revents & POLLOUT)
			{
				if(send(fd, packet, packet_ptr - packet, 0) != (packet_ptr - packet))
				{
					if(log_level >= log_warning)
						fprintf(stderr, "! send failed\n");
					break;
				}
			}

			break;
		}

		default:
		{
			if(log_level >= log_warning)
				fprintf(stderr, "! send poll error\n");
			break;
		}
	}
}

static void send_ack(int fd, unsigned int sequence, unsigned int address_from, unsigned int address_to)
{
	if(log_level >= log_debug)
		fprintf(stderr, "# ack %04x %08x %08x\n", sequence, address_from, address_to);

	send_packet(fd, sequence, address_from, address_to, 0x80, 0, (const uint8_t *)"");
}

static void function_500_unknown_subfunction(const function_500_data_t *function_500_data)
{
	char datestring[64];
	unsigned int stamp;

	stamp = uint4le_to_unsigned(function_500_data->data) + function_500_data->message->time_offset;
	stamp_to_string(sizeof(datestring), datestring, stamp);

	if(log_level >= log_notice)
		fprintf(stderr, "- unknown function %x subfunction: %x: length: %x, stamp: %s\n",
				function_500_data->message->function, function_500_data->type, function_500_data->data_length, datestring);

	if(log_level >= log_info)
		dump(function_500_data->data_length, function_500_data->data);
}

static void process_function_500_type_10(const function_500_data_t *function_500_data)
{
	const uint8_t *data = function_500_data->data;
	unsigned int stamp;
	unsigned int uptime;
	char datestring[32];
	double temperature, acv, aci, acf, dcv, acp;
	char command[1024];

	stamp = uint4le_to_unsigned(&data[0]) + function_500_data->message->time_offset;
	uptime = uint4le_to_unsigned(&data[4]);
	temperature = float4_to_float(&data[12]);

	stamp_to_string(sizeof(datestring), datestring, stamp);

	acv = float4_to_float(&data[24]);
	aci = float4_to_float(&data[28]);
	acf = float4_to_float(&data[32]);
	dcv = float4_to_float(&data[44]);
	acp = float4_to_float(&data[92]);

	if(log_level >= log_info)
		fprintf(stderr, "+ inverter data:  seq:%04x             uptime:%s,%02u temp:%f acv:%f aci:%f acf:%f dcv:%f acp:%f\n",
				function_500_data->message->sequence, datestring, uptime / 3600, temperature, acv, aci, acf, dcv, acp);

	if(function_500_data->message->script.inverter)
	{
		snprintf(command, sizeof(command) - 1, "%s %x %x %u %s %u %f %f %f %f %f %f\n",
				function_500_data->message->script.inverter,
				function_500_data->message->sequence, function_500_data->id,
				stamp, datestring, uptime, temperature, acv, aci, acf, dcv, acp);

		if(log_level >= log_debug)
			fprintf(stderr, "# system(\"%s\")\n", command);

		system(command);
	}
}

static void process_function_500_type_17(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_18(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_22(const function_500_data_t *function_500_data)
{
	char datestring[64];
	unsigned int stamp;

	stamp = uint4le_to_unsigned(function_500_data->data) + function_500_data->message->time_offset;
	stamp_to_string(sizeof(datestring), datestring, stamp);

	if(log_level >= log_info)
		fprintf(stderr, "+ meter data:     seq:%04x             uptime:%s\n", function_500_data->message->sequence, datestring);
}

static void process_function_500_type_40(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_41(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_42(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_43(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_44(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_47(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_48(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_4d(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_50(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_82(const function_500_data_t *function_500_data) // s440 optimiser data
{
	const uint8_t *data;
	unsigned int stamp;
	unsigned int uptime;
	double vpanel, voptimiser, current;
	char datestring[32];
	char command[1024];

	data = function_500_data->data;

	if(function_500_data->data_length < 10)
	{
		if(log_level >= log_notice)
			fprintf(stderr, "- process 500/82: message too short\n");
		return;
	}

	stamp = uint4le_to_unsigned(&data[0]) + function_500_data->message->time_offset;
	uptime = uint2le_to_unsigned(&data[4]);

	stamp_to_string(sizeof(datestring), datestring, stamp);

	vpanel =		0.125 * (data[6] | (data[7] << 8 & 0x300));
	voptimiser =	0.125 * (data[7] >> 2 | (data[8] << 6 & 0x3c0));
	current =		0.00625 * (data[9] << 4 | (data[8] >> 4 & 0xf));

	if(log_level >= log_info)
		fprintf(stderr, "+ optimiser data: seq:%04x id:%08x uptime:%s,%02u vpanel:%.2f voptimiser:%.2f current:%.2f\n",
				function_500_data->message->sequence, function_500_data->id, datestring, uptime / 3600, vpanel, voptimiser, current);

	if(function_500_data->message->script.optimiser)
	{
		snprintf(command, sizeof(command) - 1, "%s %x %x %u %s %u %f %f %f",
				function_500_data->message->script.optimiser,
				function_500_data->message->sequence, function_500_data->id, stamp, datestring, uptime, vpanel, voptimiser, current);

		if(log_level >= log_debug)
			fprintf(stderr, "# system(\"%s\")\n", command);

		system(command);
	}
}

static void process_function_500_type_300(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500_type_1800(const function_500_data_t *function_500_data)
{
	return(function_500_unknown_subfunction(function_500_data));
}

static void process_function_500(const message_t *message)
{
	const jump_table_function_500_t *jump;
	function_500_data_t jump_data;
	unsigned int ix, order;
	unsigned int type, id, length;
	const uint8_t *data;

	data = message->payload.data;

	for(order = 0, ix = 0; ix < message->payload.length; order++)
	{
		type =	uint2le_to_unsigned(&data[ix + 0]);
		id = uint4le_to_unsigned(&data[ix + 2]) & 0xff7fffff;
		length = uint2le_to_unsigned(&data[ix + 6]);

		ix += 8;

		for(jump = jump_table_500; jump->process_function != (void(*)(const function_500_data_t *))0; jump++)
		{
			if(jump->type == type)
			{
				jump_data.order = order;
				jump_data.type = type;
				jump_data.id = id;
				jump_data.data_length = length;
				jump_data.data = &message->payload.data[ix];
				jump_data.message = message;

				jump->process_function(&jump_data);
				goto ok;
			}
		}

		if(log_level >= log_notice)
			fprintf(stderr, "- 500/post: unknown subtype: %04x\n", type);
ok:
		ix += length;
	}

	send_ack(message->fd, message->sequence, message->address.to, message->address.from);
}

static void send_datetime(int fd, unsigned int sequence, unsigned int address_to, unsigned int address_from)
{
	uint8_t payload[8];
	time_t clock;
	struct tm *tm;
	int tzoffset;
	char timestr[64];

	clock = time((time_t *)0);
	tm = gmtime(&clock);
	tm->tm_isdst = -1;
	tzoffset = (unsigned int)clock - mktime(tm);

	if(log_level >= log_info)
	{
		time_t clock_utc;
		clock_utc = mktime(tm);
		tm = localtime(&clock_utc);
		strftime(timestr, sizeof(timestr) - 1, "%Y/%m/%d %H:%M:%S", tm);
		fprintf(stderr, "+ send GMT: %u %2d\n", (unsigned int)clock, tzoffset);
	}

	unsigned_to_uint4le(&payload[0], (unsigned int)clock);
	unsigned_to_uint4le(&payload[4], (unsigned int)tzoffset);

	send_packet(fd, sequence, address_to, address_from, 0x580, sizeof(payload), payload);
}

static void process_function_501(const message_t *message)
{
	if(log_level >= log_info)
		fprintf(stderr, "+ function 501 GMT requested\n");
	send_datetime(message->fd, message->sequence, message->address.to, message->address.from);
}

int main(int argc, char *const *argv)
{
	uint8_t current;
	state_collector_t state = sc_no_tag;
	unsigned int skipped;
	unsigned int packet, short_packet, invalid_crc;
	unsigned int datalen, datalen_inv;
	unsigned int sequence, sequence_acking;
	unsigned int address_from, address_to;
	unsigned int function;
	time_t now, last_time_sent;
	unsigned int their_crc, our_crc;
	uint8_t payload[65536];
	unsigned int payload_length;
	int sockfd;
	struct addrinfo hints;
	struct addrinfo *res;
	struct sockaddr_in saddr;
	const char *inverter_update_script;
	const char *optimiser_update_script;
	const char *host;
	int time_offset;
	unsigned int log_level_value;
	int opt;

	inverter_update_script = (const char *)0;
	optimiser_update_script = (const char *)0;
	time_offset = 0;

	while((opt = getopt(argc, argv, "i:o:t:v:h?")) != EOF)
	{
		switch(opt)
		{
			case('i'):
			{
				inverter_update_script = optarg;
				break;
			}

			case('o'):
			{
				optimiser_update_script = optarg;
				break;
			}

			case('t'):
			{
				time_offset = strtol(optarg, (char **)0, 10);
				break;
			}

			case('v'):
			{
				log_level_value = strtoul(optarg, (char **)0, 10);
				log_level = (log_level_t)log_level_value;
				break;
			}

			case(EOF):
			{
				break;
			}

			default:
			{
				fprintf(stderr,
					"usage: secollect [-i inverter-data-update-script] [-o optimiser-data-update-script] [-t time-offset in seconds] [-v loglevel] <host>\n"
					"    log levels: 0 = error, 1 = warning, 2 = notice, 3 = info\n");
				return(1);
			}
		}
	}

	if((optind >= argc) || (!argv[optind]))
	{
		fprintf(stderr, "E missing hostname\n");
		return(-1);
	}

	host = argv[optind];

	address_from =		0xfffffffe;
	address_to =		0xfffffffe;
	sequence =			0xffff;
	sequence_acking =	0xffff;
	payload_length =	0;
	last_time_sent =	0;

	for(;;)
	{
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("socket");
			return(-1);
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV;

		res = (struct addrinfo *)0;

		if(getaddrinfo(host, "2424", &hints, &res))
		{
			if(res)
				freeaddrinfo(res);
			fprintf(stderr, "E unknown host: %s\n", host);
			return(-1);
		}

		if(!res || !res->ai_addr)
		{
			fprintf(stderr, "E unknown host: %s\n", host);
			return(-1);
		}

		saddr = *(struct sockaddr_in *)res->ai_addr;
		freeaddrinfo(res);

		if(connect(sockfd, (const struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		{
			perror("connect");
			return(-1);
		}

		function = 0;
		datalen = 0;
		skipped = 0;
		packet = 0;
		short_packet = 0;
		invalid_crc = 0;

		for(;;)
		{
			// every hour send an unsollicited "GMT" update

			if((address_from != 0xfffffffe) && (address_to != 0xfffffffe))
			{
				now = time((time_t *)0);

				if((now - last_time_sent) > 3600)
				{
					send_datetime(sockfd, sequence, address_from, address_to);
					last_time_sent = now;
				}
			}

			struct pollfd pfd[1];

			pfd->fd = sockfd;
			pfd->events = POLLIN | POLLRDHUP;
			pfd->revents = 0;

			switch(poll(pfd, 1, 1000))
			{
				case(0):
				{
					if(log_level >= log_debug)
						fprintf(stderr, "# poll timeout\n");

					if(sequence_acking != 0xffff)
						send_ack(sockfd, sequence_acking, address_to, address_from);

					continue;
				}

				case(1):
				{
					if(pfd->revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
					{
						if(log_level >= log_warning)
							fprintf(stderr, "! poll event error\n");
						goto reconnect;
					}

					if(pfd->revents & POLLIN)
					{
						switch(recv(sockfd, &current, sizeof(current), 0))
						{
							case(0):
							{
								if(log_level >= log_warning)
									fprintf(stderr, "! EOF during recv\n");
								goto reconnect;
							}

							case(1):
							{
								break;
							}

							default:
							{
								if(log_level >= log_warning)
									fprintf(stderr, "! recv error\n");
								goto reconnect;
							}
						}
					}

					break;
				}

				default:
				{
					if(log_level >= log_warning)
						fprintf(stderr, "! poll error\n");
					goto reconnect;
				}
			}

			switch(state)
			{
				case(sc_no_tag):
				{
					state = sc_no_tag;

					if(current == 0x12)
						state = sc_tag_0;
					else
						skipped++;

					break;
				}

				case(sc_tag_0):
				{
					state = sc_no_tag;

					if(current == 0x12)
						state = sc_tag_0;

					if(current == 0x34)
						state = sc_tag_1;

					break;
				}

				case(sc_tag_1):
				{
					state = sc_no_tag;

					if(current == 0x12)
						state = sc_tag_0;

					if(current == 0x56)
						state = sc_tag_2;

					break;
				}

				case(sc_tag_2):
				{
					state = sc_no_tag;

					if(current == 0x12)
						state = sc_tag_0;

					if(current == 0x79)
						state = sc_datalen_lo;

					break;
				}

				case(sc_datalen_lo):
				{
					datalen = (unsigned int)current;

					state = sc_datalen_hi;

					break;
				}

				case(sc_datalen_hi):
				{
					datalen |= (unsigned int)current << 8;

					state = sc_datalen_inv_lo;

					break;
				}

				case(sc_datalen_inv_lo):
				{
					datalen_inv = (unsigned int)current;

					state = sc_datalen_inv_hi;

					break;
				}

				case(sc_datalen_inv_hi):
				{
					datalen_inv |= (unsigned int)current << 8;
					datalen_inv = (1 << 16) - 1 - datalen_inv;

					state = sc_sequence_lo;

					break;
				}

				case(sc_sequence_lo):
				{
					sequence = (unsigned int)current;

					state = sc_sequence_hi;

					break;
				}

				case(sc_sequence_hi):
				{
					sequence |= (unsigned int)current << 8;

					if(sequence != 0xffff)
						sequence_acking = sequence;

					state = sc_addr_from_0;

					break;
				}

				case(sc_addr_from_0):
				{
					address_from = (unsigned int)current << 0;

					state = sc_addr_from_1;

					break;
				}

				case(sc_addr_from_1):
				{
					address_from |= (unsigned int)current << 8;

					state = sc_addr_from_2;

					break;
				}

				case(sc_addr_from_2):
				{
					address_from |= (unsigned int)current << 16;

					state = sc_addr_from_3;

					break;
				}

				case(sc_addr_from_3):
				{
					address_from |= (unsigned int)current << 24;

					state = sc_addr_to_0;

					break;
				}

				case(sc_addr_to_0):
				{
					address_to = (unsigned int)current << 0;

					state = sc_addr_to_1;

					break;
				}

				case(sc_addr_to_1):
				{
					address_to |= (unsigned int)current << 8;

					state = sc_addr_to_2;

					break;
				}

				case(sc_addr_to_2):
				{
					address_to |= (unsigned int)current << 16;

					state = sc_addr_to_3;

					break;
				}

				case(sc_addr_to_3):
				{
					address_to |= (unsigned int)current << 24;

					state = sc_function_lo;

					break;
				}

				case(sc_function_lo):
				{
					function = (unsigned int)current;

					state = sc_function_hi;

					break;
				}

				case(sc_function_hi):
				{
					function |= (unsigned int)current << 8;

					payload_length = 0;

					if(datalen >= sizeof(payload))
					{
						if(log_level >= log_warning)
							fprintf(stderr, "! payload > buffer\n");
						datalen = sizeof(payload) - 1;
					}

					state = sc_data_no_tag;

					if(datalen == 0)
						state = sc_crc_lo;

					break;
				}

				case(sc_data_no_tag):
				{
					payload[payload_length++] = current;

					if(payload_length >= datalen)
					{
						state = sc_crc_lo;
						break;
					}

					state = sc_data_no_tag;

					if(current == 0x12)
						state = sc_data_tag_0;

					break;
				}

				case(sc_data_tag_0):
				{
					payload[payload_length++] = current;

					if(payload_length >= datalen)
					{
						state = sc_crc_lo;
						break;
					}

					state = sc_data_no_tag;

					if(current == 0x12)
						state = sc_data_tag_0;

					if(current == 0x34)
						state = sc_data_tag_1;

					break;
				}

				case(sc_data_tag_1):
				{
					payload[payload_length++] = current;

					if(payload_length >= datalen)
					{
						state = sc_crc_lo;
						break;
					}

					state = sc_data_no_tag;

					if(current == 0x12)
						state = sc_data_tag_0;

					if(current == 0x56)
						state = sc_data_tag_2;

					break;
				}

				case(sc_data_tag_2):
				{
					payload[payload_length++] = current;

					if(payload_length >= datalen)
					{
						state = sc_crc_lo;
						break;
					}

					state = sc_data_no_tag;

					if(current == 0x12)
						state = sc_data_tag_0;

					if(current == 0x79)
					{
						short_packet++;
						state = sc_datalen_lo;
					}

					break;
				}

				case(sc_crc_lo):
				{
					their_crc = current;

					state = sc_crc_hi;

					break;
				}

				case(sc_crc_hi):
				{
					uint8_t header[12];
					uint8_t *ptr = header;
					const jump_table_function_t *jump;
					message_t message;

					their_crc |= current << 8;

					*ptr++ = (sequence & 0xff00) >> 8;
					*ptr++ = (sequence & 0x00ff) >> 0;
					*ptr++ = (address_from & 0xff000000) >> 24;
					*ptr++ = (address_from & 0x00ff0000) >> 16;
					*ptr++ = (address_from & 0x0000ff00) >>  8;
					*ptr++ = (address_from & 0x000000ff) >>  0;
					*ptr++ = (address_to & 0xff000000) >> 24;
					*ptr++ = (address_to & 0x00ff0000) >> 16;
					*ptr++ = (address_to & 0x0000ff00) >>  8;
					*ptr++ = (address_to & 0x000000ff) >>  0;
					*ptr++ = (function & 0xff00) >> 8;
					*ptr++ = (function & 0x00ff) >> 0;
					our_crc = crc16modbus_byte(0x5a5a, header, sizeof(header));
					our_crc = crc16modbus_byte(our_crc, payload, payload_length);

					if(log_level >= log_info)
						fprintf(stderr, "+ packet:%u short:%u invalid crc:%3u packet length:%u/%u sequence:%4x from:%08x to:%08x "
								"function:%04x, their_crc:%04x,our_crc:%04x skipped:%u\n",
								packet++, short_packet, invalid_crc, payload_length, datalen_inv, sequence, address_from, address_to, function,
								their_crc, our_crc, skipped);

					if(our_crc != their_crc)
					{
						invalid_crc++;
						if(log_level >= log_notice)
							fprintf(stderr, "- packet skipped due to invalid CRC\n");
					}
					else
					{
						for(jump = jump_table_function; jump->process_function != (void(*))0; jump++)
						{
							if(jump->function == function)
							{
								message.fd = sockfd;
								message.time_offset = time_offset;
								message.ix = packet;
								message.sequence = sequence;
								message.address.from = address_from;
								message.address.to = address_to;
								message.function = function;
								message.payload.length = payload_length;
								message.payload.data = payload;
								message.script.inverter = inverter_update_script;
								message.script.optimiser = optimiser_update_script;

								jump->process_function(&message);

								goto ok;
							}
						}
					}

					if(log_level >= log_notice)
						fprintf(stderr, "- skip unknown packet with function %04x\n", function);
ok:
					skipped = 0;
					state = sc_no_tag;

					break;
				}
			}
		}
reconnect:
		sleep(10);
		close(sockfd);
	}
}
