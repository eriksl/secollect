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
#include <stdarg.h>

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
	sc_address_slave_0,
	sc_address_slave_1,
	sc_address_slave_2,
	sc_address_slave_3,
	sc_address_master_0,
	sc_address_master_1,
	sc_address_master_2,
	sc_address_master_3,
	sc_function_lo,
	sc_function_hi,
	sc_data_no_tag,
	sc_data_tag_0,
	sc_data_tag_1,
	sc_data_tag_2,
	sc_crc_lo,
	sc_crc_hi,
} state_collector_t;

typedef struct
{
	unsigned int size;
	char *data;
} string_t;

typedef struct
{
	unsigned int socket_fd;
	unsigned int sequence;
	unsigned int sequence_exception;
	unsigned int function;
	struct
	{
		unsigned int from;
		unsigned int to;
	} address;
	struct
	{
		unsigned int length;
		uint8_t data[1024];
	} payload;
} packet_t;

typedef struct
{
	packet_t packet;

	unsigned int ix;

	struct
	{
		const char *inverter;
		const char *optimiser;
	} script;
} process_function_data_t;

enum { packet_queue_size = 32 };
static packet_t packet_queue[packet_queue_size];
static unsigned int packet_queue_in;
static unsigned int packet_queue_out;
static unsigned int packet_queue_length;

typedef struct
{
	unsigned int function;
	const char *name;
	void (*process_function)(const process_function_data_t *);
} jump_table_function_t;

static void process_function_500(const process_function_data_t *);
static void process_function_501(const process_function_data_t *);
static void process_function_308(const process_function_data_t *);
static void process_function_309(const process_function_data_t *);
static void process_function_368(const process_function_data_t *);
static void process_function_36a(const process_function_data_t *);
static void process_function_39a(const process_function_data_t *);
static void process_function_3c2(const process_function_data_t *);
static void process_function_4288(const process_function_data_t *);
static void process_function_428a(const process_function_data_t *);

static const jump_table_function_t jump_table_function[] =
{
	{	0x0500,	"post data",		process_function_500	},
	{	0x0501,	"get GMT time",		process_function_501	},
	{	0x039a,	"master grant ack",	process_function_39a	},
	{	0x0308,	"detect init",		process_function_308	},
	{	0x0309,	"detect get id",	process_function_309	},
	{	0x0368,	"unknown 368",		process_function_368	},
	{	0x036a,	"unknown 36a",		process_function_36a	},
	{	0x03c2,	"unknown 3c2",		process_function_3c2	},
	{	0x4288,	"unknown 4288",		process_function_4288	},
	{	0x428a,	"unknown 428a",		process_function_428a	},
	{	0x00,	"",					(void(*))0				},
};

typedef struct
{
	const process_function_data_t *process_function_data;
	unsigned int sub_sequence;
	unsigned int sub_packet_type;
	unsigned int id;
	struct
	{
		unsigned int length;
		const uint8_t *data;
	} sub_packet_payload;
	string_t output;
} function_500_subpacket_t;

static void process_function_500_type_10(function_500_subpacket_t *);
static void process_function_500_type_17(function_500_subpacket_t *);
static void process_function_500_type_18(function_500_subpacket_t *);
static void process_function_500_type_22(function_500_subpacket_t *);
static void process_function_500_type_40(function_500_subpacket_t *);
static void process_function_500_type_41(function_500_subpacket_t *);
static void process_function_500_type_42(function_500_subpacket_t *);
static void process_function_500_type_43(function_500_subpacket_t *);
static void process_function_500_type_44(function_500_subpacket_t *);
static void process_function_500_type_47(function_500_subpacket_t *);
static void process_function_500_type_48(function_500_subpacket_t *);
static void process_function_500_type_4d(function_500_subpacket_t *);
static void process_function_500_type_50(function_500_subpacket_t *);
static void process_function_500_type_82(function_500_subpacket_t *); // s440 optimiser data
static void process_function_500_type_300(function_500_subpacket_t *);
static void process_function_500_type_1800(function_500_subpacket_t *);

typedef struct
{
	unsigned int sub_packet_type;
	const char *name;
	unsigned int minimal_data_length;
	bool has_stamp;
	void (*process_function)(function_500_subpacket_t *);
} jump_table_function_500_t;

static const jump_table_function_500_t jump_table_500[] =
{
	{	0x10,	"inverter data",	96,	true,	process_function_500_type_10	},
	{	0x17,	"identification",	4,	true,	process_function_500_type_17	},
	{	0x18,	"region data",		6,	true,	process_function_500_type_18	},
	{	0x22,	"meter data",		4,	true,	process_function_500_type_22	},
	{	0x40,	"unknown",			4,	true,	process_function_500_type_40	},
	{	0x41,	"unknown",			4,	true,	process_function_500_type_41	},
	{	0x42,	"unknown",			4,	true,	process_function_500_type_42	},
	{	0x43,	"optimiser id",		12,	true,	process_function_500_type_43	},
	{	0x44,	"unknown",			4,	true,	process_function_500_type_44	},
	{	0x47,	"unknown",			4,	true,	process_function_500_type_47	},
	{	0x48,	"unknown",			4,	true,	process_function_500_type_48	},
	{	0x4d,	"inverter id",		8,	true,	process_function_500_type_4d	},
	{	0x50,	"statistics",		22,	true,	process_function_500_type_50	},
	{	0x82,	"optimiser data",	10,	true,	process_function_500_type_82	},
	{	0x300,	"unknown",			4,	true,	process_function_500_type_300	},
	{	0x1800,	"unknown",			4,	true,	process_function_500_type_1800	},
	{	0x0,	"",					0,	true,	(void(*))0						},
};

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

static void stamp_to_string(unsigned int datestring_size, char *datestring, unsigned int stamp)
{
	time_t ticks;
	const struct tm *tm;

	ticks = (time_t)stamp;
	tm = localtime(&ticks);
	strftime(datestring, datestring_size - 1, "%Y-%m-%d %H:%M", tm);
}

typedef enum
{
	log_error = 0,	//	E
	log_warning,	//	!
	log_alert,		//	-
	log_notice,		//	%
	log_info,		//	+
	log_debug,		//	#
	log_debug2,		//	>
	log_size,
	log_append = 1 << 7,
} log_level_t;

__attribute__ ((format (printf, 2, 3) )) static void snprintfcat(const string_t *string, const char *format, ...)
{
	va_list valist;
	char *data;
	int size;
	unsigned int length;

	data = string->data;
	length = strlen(data);
	size = string->size - length;

	if(size <= 0)
	{
		string->data[string->size - 1] = '\0';
		return;
	}

	data += length;

	va_start(valist, format);
	vsnprintf(data, size, format, valist);
	va_end(valist);
}

static FILE *log_file_fp = (FILE *)0;
static log_level_t log_level = log_info;

__attribute__ ((format (printf, 2, 3) )) static void printlog(log_level_t level, const char *format, ...)
{
	static const char *prefix[log_size] = {
			"E",
			"!",
			"-",
			"%",
			"+",
			"#",
			">",
	};
	char timedatestr[64];
	time_t ticks;
	struct tm *tm;

	if((log_level < 0) || (log_level > log_size))
	{
		fprintf(stderr, "E invalid log level %u\n", log_level);
		return;
	}

	if(format[0] != '\0')
	{
		ticks = time((time_t *)0);
		tm = localtime(&ticks);
		strftime(timedatestr, sizeof(timedatestr), "%H:%M:%S", tm);

		if((level <= log_debug) && log_file_fp)
		{
			fprintf(log_file_fp, "%s %s ", prefix[level], timedatestr);
			va_list valist;
			va_start(valist, format);
			vfprintf(log_file_fp, format, valist);
			va_end(valist);
		}

		if(level <= log_level)
		{
			fprintf(stderr, "%s %s ", prefix[level], timedatestr); // use systemd journal via stderr
			va_list valist;
			va_start(valist, format);
			vfprintf(stderr, format, valist);
			va_end(valist);
		}
	}

	if((level <= log_debug) && log_file_fp)
		fprintf(log_file_fp, "%s", "\n");

	if(log_file_fp)
		fflush(log_file_fp);

	if(level <= log_level)
		fprintf(stderr, "%s", "\n");
}

static void dump(unsigned int length, const uint8_t *data, unsigned int size, char *buffer)
{
	unsigned int ix, ascii_ix;
	char entry[64];

	strncpy(buffer, "    ", size - 1);

	for(ix = 0, ascii_ix = 0; ix < length; ix++)
	{
		if((ix % 4) == 0)
		{
			if(ix > 0)
			{
				strncat(buffer, " ", size - 1);

				for(; ascii_ix < ix; ascii_ix++)
				{
					snprintf(entry, sizeof(entry), "%c", (data[ascii_ix] >= ' ' && data[ascii_ix] <= '~') ? data[ascii_ix] : '.');
					strncat(buffer, entry, size -1);
				}

				strncat(buffer, "\n    ", size - 1);
			}

			snprintf(entry, sizeof(entry), "%2u: ", ix);
			strncat(buffer, entry, size - 1);
		}

		snprintf(entry, sizeof(entry), "%02x ", data[ix]);
		strncat(buffer, entry, size - 1);
	}

	strncat(buffer, "\n", size - 1);
}

static void send_packet(const packet_t *packet_in)
{
	uint8_t packet_out[1024];
	uint8_t *packet_ptr;
	uint8_t header1[4 + 2 + 2];
	uint8_t header2[12];
	uint8_t *ptr;
	unsigned int crc;
	unsigned int message_length_inverted;
	struct pollfd pfd[1];

	message_length_inverted = packet_in->payload.length ^ 0xffff;

	ptr = header1;
	*ptr++ = 0x12;
	*ptr++ = 0x34;
	*ptr++ = 0x56;
	*ptr++ = 0x79;
	*ptr++ = (packet_in->payload.length & 0x00ff) >> 0;
	*ptr++ = (packet_in->payload.length & 0xff00) >> 8;
	*ptr++ = (message_length_inverted & 0x00ff) >> 0;
	*ptr++ = (message_length_inverted & 0xff00) >> 8;

	ptr = header2;
	*ptr++ = (packet_in->sequence & 0xff00) >> 8;
	*ptr++ = (packet_in->sequence & 0x00ff) >> 0;
	*ptr++ = (packet_in->address.from & 0xff000000) >> 24;
	*ptr++ = (packet_in->address.from & 0x00ff0000) >> 16;
	*ptr++ = (packet_in->address.from & 0x0000ff00) >>  8;
	*ptr++ = (packet_in->address.from & 0x000000ff) >>  0;
	*ptr++ = (packet_in->address.to & 0xff000000) >> 24;
	*ptr++ = (packet_in->address.to & 0x00ff0000) >> 16;
	*ptr++ = (packet_in->address.to & 0x0000ff00) >>  8;
	*ptr++ = (packet_in->address.to & 0x000000ff) >>  0;
	*ptr++ = (packet_in->function & 0xff00) >> 8;
	*ptr++ = (packet_in->function & 0x00ff) >> 0;

	crc = crc16modbus_byte(0x5a5a, header2, sizeof(header2));
	crc = crc16modbus_byte(crc, packet_in->payload.data, packet_in->payload.length);

	ptr = header2;
	*ptr++ = (packet_in->sequence & 0x00ff) >> 0;
	*ptr++ = (packet_in->sequence & 0xff00) >> 8;
	*ptr++ = (packet_in->address.from & 0x000000ff) >>  0;
	*ptr++ = (packet_in->address.from & 0x0000ff00) >>  8;
	*ptr++ = (packet_in->address.from & 0x00ff0000) >> 16;
	*ptr++ = (packet_in->address.from & 0xff000000) >> 24;
	*ptr++ = (packet_in->address.to & 0x000000ff) >>  0;
	*ptr++ = (packet_in->address.to & 0x0000ff00) >>  8;
	*ptr++ = (packet_in->address.to & 0x00ff0000) >> 16;
	*ptr++ = (packet_in->address.to & 0xff000000) >> 24;
	*ptr++ = (packet_in->function & 0x00ff) >> 0;
	*ptr++ = (packet_in->function & 0xff00) >> 8;

	pfd->fd = packet_in->socket_fd;
	pfd->events = POLLOUT;
	pfd->revents = 0;

	if((sizeof(header1) + sizeof(header2) + packet_in->payload.length + 2) >= sizeof(packet_out))
	{
		printlog(log_error, "packet buffer too small");
		return;
	}

	packet_ptr = packet_out;
	memcpy(packet_ptr, header1, sizeof(header1));
	packet_ptr += sizeof(header1);
	memcpy(packet_ptr, header2, sizeof(header2));
	packet_ptr += sizeof(header2);
	memcpy(packet_ptr, packet_in->payload.data, packet_in->payload.length);
	packet_ptr += packet_in->payload.length;
	unsigned_to_uint2le(packet_ptr, crc);
	packet_ptr += 2;

	if(log_level >= log_debug2)
	{
		char buffer[65536];
		dump(packet_ptr - packet_out, packet_out, sizeof(buffer), buffer);
		printlog(log_debug2, "send packet:\n%s", buffer);
	}

	switch(poll(pfd, 1, 1000))
	{
		case(0):
		{
			printlog(log_warning, "send poll timeout");
			break;
		}

		case(1):
		{
			if(pfd->revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
			{
				printlog(log_warning, "send poll event failed");
				break;
			}

			if(pfd->revents & POLLOUT)
			{
				if(send(packet_in->socket_fd, packet_out, packet_ptr - packet_out, 0) != (packet_ptr - packet_out))
				{
					printlog(log_warning, "send failed");
					break;
				}
			}

			break;
		}

		default:
		{
			printlog(log_warning, "send poll error");
			break;
		}
	}
}

static bool enqueue_packet(const packet_t *packet)
{
	packet_t *packet_queue_entry;

	if(packet_queue_length >= packet_queue_size)
	{
		printlog(log_warning, "queue overrun: %u %u/%u", packet_queue_length, packet_queue_in, packet_queue_out);
		return(false);
	}

	packet_queue_entry = &packet_queue[packet_queue_in];

	printlog(log_debug, "enqueue packet [%u/%u/%u/%d] seq:%04x func:%04x from:%08x to:%08x payload:%u",
		packet_queue_in, packet_queue_out, packet_queue_length, packet_queue_size,
		packet->sequence, packet->function,
		packet->address.from, packet->address.to,
		packet->payload.length);

	*packet_queue_entry = *packet;

	packet_queue_in = (packet_queue_in + 1) % packet_queue_size;
	packet_queue_length++;

	return(true);
}

static bool dequeue_packet(void)
{
	const packet_t *packet_queue_entry;

	if(packet_queue_length == 0)
		return(false);

	packet_queue_entry = &packet_queue[packet_queue_out];

	printlog(log_debug, "dequeue packet [%u/%u/%u/%d] seq:%04x func:%04x from:%08x to:%08x payload:%u", 
			packet_queue_in, packet_queue_out, packet_queue_length, packet_queue_size,
			packet_queue_entry->sequence,
			packet_queue_entry->function,
			packet_queue_entry->address.from,
			packet_queue_entry->address.to,
			packet_queue_entry->payload.length);

	send_packet(packet_queue_entry);

	packet_queue_out = (packet_queue_out + 1) % packet_queue_size;

	if(--packet_queue_length == 0)
		return(false);

	return(true);
}

__attribute__ ((used)) static void send_ack(int fd, unsigned int sequence, unsigned int address_from, unsigned int address_to)
{
	packet_t packet;

	printlog(log_debug, "send ack seq:%04x from:%08x to:%08x", sequence, address_from, address_to);

	packet.socket_fd = fd;
	packet.sequence = sequence;
	packet.function = 0x80;
	packet.address.from = address_from;
	packet.address.to = address_to;
	packet.payload.length = 0;

	send_packet(&packet);
}

static void send_busgrant(int fd, unsigned int address_from, unsigned int address_to)
{
	packet_t packet;

	printlog(log_debug, "send busgrant from:%08x to:%08x", address_from, address_to);

	packet.socket_fd = fd;
	packet.sequence = 0xffff;
	packet.function = 0x302;
	packet.address.from = address_from;
	packet.address.to = address_to;
	packet.payload.length = 0;

	send_packet(&packet);
}

static bool enqueue_ack(int fd, unsigned int sequence, unsigned int address_from, unsigned int address_to)
{
	packet_t packet;

	printlog(log_debug, "enqueue ack seq:%04x from:%08x to:%08x", sequence, address_from, address_to);

	packet.socket_fd = fd;
	packet.sequence = sequence;
	packet.function = 0x80;
	packet.address.from = address_from;
	packet.address.to = address_to;
	packet.payload.length = 0;

	return(enqueue_packet(&packet));
}

static void process_function_500_type_10(function_500_subpacket_t *subpacket)
{
	const uint8_t *data = subpacket->sub_packet_payload.data;
	unsigned int stamp;
	unsigned int uptime;
	char datestring[32];
	double temperature, acv, aci, acf, dcv, acp;
	char command[1024];

	stamp = uint4le_to_unsigned(&data[0]);
	stamp_to_string(sizeof(datestring), datestring, stamp);
	uptime = uint4le_to_unsigned(&data[4]);
	temperature = float4_to_float(&data[12]);

	acv = float4_to_float(&data[24]);
	aci = float4_to_float(&data[28]);
	acf = float4_to_float(&data[32]);
	dcv = float4_to_float(&data[44]);
	acp = float4_to_float(&data[92]);

	snprintfcat(&subpacket->output, " uptime:%u temp:%f acv:%f aci:%f acf:%f dcv:%f acp:%f",
			uptime / 3600, temperature, acv, aci, acf, dcv, acp);

	if(subpacket->process_function_data->script.inverter)
	{
		snprintf(command, sizeof(command) - 1, "%s %x %x %u %s %u %f %f %f %f %f %f\n",
				subpacket->process_function_data->script.inverter,
				subpacket->process_function_data->packet.sequence, subpacket->id,
				stamp, datestring, uptime, temperature, acv, aci, acf, dcv, acp);

		printlog(log_debug2, "inverter data: system(\"%s\")", command);
		system(command);
	}
}

static void process_function_500_type_17(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_18(function_500_subpacket_t *subpacket)
{
	const uint8_t *data;
	unsigned int data_length;
	char value[64];
	unsigned int value_length;

	data = subpacket->sub_packet_payload.data;
	data_length = subpacket->sub_packet_payload.length;
	value_length = uint2le_to_unsigned(&data[4]);

	if((value_length + 6) >= data_length)
	{
		printlog(log_notice, "process 500/18: payload length too long: %u/%u", value_length, data_length);
		return;
	}

	if(value_length >= sizeof(value))
	{
		printlog(log_notice, "process 500/18: payload too long: %u/%lu", value_length, sizeof(value));
		return;
	}

	memcpy(value, &data[6], value_length);
	value[sizeof(value) - 1] = '\0';
	value[value_length] = '\0';

	snprintfcat(&subpacket->output, " value:%s", value);
}

static void process_function_500_type_22(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_40(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_41(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_42(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_43(function_500_subpacket_t *subpacket)
{
	const uint8_t *data;
	unsigned int data_length;
	unsigned int current;
	unsigned int unknown[3];
	unsigned int optimiser;
	unsigned int optimiser_count;
	unsigned int optimiser_id;
	unsigned int optimiser_id_index;

	data = subpacket->sub_packet_payload.data;
	data_length = subpacket->sub_packet_payload.length;

	unknown[0] = uint2le_to_unsigned(&data[4]);
	unknown[1] = uint2le_to_unsigned(&data[6]);
	unknown[2] = uint2le_to_unsigned(&data[8]);
	optimiser_count = uint2le_to_unsigned(&data[10]);

	snprintfcat(&subpacket->output, " count:%u unknown[0]:%x unknown[1]:%x unknown[2]:%x",
			optimiser_count,
			unknown[0], unknown[1], unknown[2]);

	for(current = 12, optimiser = 0, optimiser_id = 0, optimiser_id_index = 0;
			(current < data_length) && (optimiser < optimiser_count) && (optimiser_id_index < 5);
			current++)
	{
		if(optimiser_id_index < 4)
			optimiser_id |= data[current] << (optimiser_id_index++ << 3);
		else
		{
			optimiser_id ^= 0x00800000;
			snprintfcat(&subpacket->output, " %02u:%08x=%02x", optimiser, optimiser_id, data[current]);

			optimiser++;
			optimiser_id = 0;
			optimiser_id_index = 0;
		}
	}
}

static void process_function_500_type_44(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_47(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_48(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_4d(function_500_subpacket_t *subpacket)
{
	unsigned int id;

	id = uint4le_to_unsigned(&subpacket->sub_packet_payload.data[4]);

	snprintfcat(&subpacket->output, " id:%08x", id);
}

static void process_function_500_type_50(function_500_subpacket_t *subpacket)
{
	const uint8_t *data;
	unsigned int current;
	unsigned int length;
	unsigned int source_address;
	unsigned int unknown[8];
	unsigned int elements;
	unsigned int current_element;
	unsigned int type;
	unsigned int type_data_length;
	char id[64];
	unsigned int id_length;
	uint8_t byte;
	unsigned int value;
	unsigned int value_index;

	length = subpacket->sub_packet_payload.length;
	data = subpacket->sub_packet_payload.data;

	source_address = uint4le_to_unsigned(&data[4]);
	unknown[0] = uint2le_to_unsigned(&data[8]);
	unknown[1] = uint2le_to_unsigned(&data[10]);
	unknown[2] = uint2le_to_unsigned(&data[12]);
	unknown[3] = uint2le_to_unsigned(&data[14]);
	unknown[4] = uint2le_to_unsigned(&data[16]);
	unknown[5] = uint2le_to_unsigned(&data[18]);
	elements = uint2le_to_unsigned(&data[20]);

	snprintfcat(&subpacket->output, " source_address:%08x unknown[0]:%x unknown[1]:%x unknown[2]:%x unknown[3]:%x unknown[4]:%x unknown[5]:%x",
				source_address,
				unknown[0],
				unknown[1],
				unknown[2],
				unknown[3],
				unknown[4],
				unknown[5]);

	current = 22;
	current_element = 0;

	while((current < length) && (current_element < elements))
	{
		type = data[current];

		switch(type)
		{
			case(0x00):
			{
				type_data_length = 4;
				break;
			}

			case(0x01):
			{
				type_data_length = 4;
				break;
			}

			case(0x02):
			{
				type_data_length = 3;
				break;
			}

			//case(0x15):
			//{
				//// FIXME
				//type_data_length = 2;
				//break;
			//}

			//case(0x21):
			//{
				//// FIXME
				//type_data_length = 2;
				//continue;
			//}

			default:
			{
				printlog(log_notice, "unknown type %u in function 500/50 message, element %u", type, current_element);
				return;
			}
		}

		current++;
		id_length = 0;

		while((current < length) && (current_element < elements) && ((id_length + 1) < sizeof(id)))
		{
			byte = data[current++];

			if(!byte)
				goto done;

			id[id_length++] = byte;
		}

		printlog(log_notice, "id name too long");
		return;

done:
		id[id_length] = '\0';

		if((length - current) < type_data_length)
		{
			printlog(log_notice, "no input byte for value of element %u/%u, %u left, needs %u", current_element, elements, length - current, type_data_length);
			return;
		}

		for(value = 0, value_index = 0; value_index < type_data_length; value_index++)
			value |= data[current++] << (value_index << 3);

		snprintfcat(&subpacket->output, "%s:%u[0x%x]", id, value, value);

		current_element++;
	}
}

static void process_function_500_type_82(function_500_subpacket_t *subpacket) // s440 optimiser data
{
	const uint8_t *data;
	unsigned int stamp;
	unsigned int uptime;
	double vpanel, voptimiser, current;
	char datestring[32];
	char command[1024];

	data = subpacket->sub_packet_payload.data;

	stamp = uint4le_to_unsigned(&data[0]);
	stamp_to_string(sizeof(datestring), datestring, stamp);
	uptime = uint2le_to_unsigned(&data[4]);

	vpanel =		0.125 * (data[6] | (data[7] << 8 & 0x300));
	voptimiser =	0.125 * (data[7] >> 2 | (data[8] << 6 & 0x3c0));
	current =		0.00625 * (data[9] << 4 | (data[8] >> 4 & 0xf));

	snprintfcat(&subpacket->output, " id:%08x uptime:%u vpanel:%.2f voptimiser:%.2f current:%.2f",
			subpacket->id, uptime / 3600, vpanel, voptimiser, current);

	if(subpacket->process_function_data->script.optimiser)
	{
		snprintf(command, sizeof(command) - 1, "%s %x %x %u %s %u %f %f %f",
				subpacket->process_function_data->script.optimiser,
				subpacket->process_function_data->packet.sequence, subpacket->id, stamp, datestring, uptime, vpanel, voptimiser, current);

		printlog(log_debug2, "optimiser data: system(\"%s\")", command);

		system(command);
	}
}

static void process_function_500_type_300(function_500_subpacket_t *subpacket)
{
}

static void process_function_500_type_1800(function_500_subpacket_t *subpacket)
{
}

static void send_datetime(int fd, unsigned int sequence, unsigned int address_from, unsigned int address_to)
{
	time_t clock;
	struct tm *tm;
	int tzoffset;
	char timestr[64];
	packet_t packet;

	packet.socket_fd = fd;
	packet.sequence = sequence;
	packet.function = 0x580;
	packet.address.from = address_from;
	packet.address.to = address_to;
	packet.payload.length = 8;

	_Static_assert(sizeof(packet.payload.data) >= 8);

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
		printlog(log_info, "send time, sequence:%04x, from:%08x to:%08x %u %2d", sequence, address_from, address_to, (unsigned int)clock, tzoffset);
	}

	unsigned_to_uint4le(&packet.payload.data[0], (unsigned int)clock);
	unsigned_to_uint4le(&packet.payload.data[4], (unsigned int)tzoffset);

	enqueue_packet(&packet);
}

static void process_function_368(const process_function_data_t *process_function_data)
{
}

static void process_function_36a(const process_function_data_t *process_function_data)
{
}

static void process_function_39a(const process_function_data_t *process_function_data)
{
	printlog(log_debug, "received master grant ack, sequence:%04x/%04x from:%08x to:%08x",
		process_function_data->packet.sequence_exception, process_function_data->packet.sequence,
				process_function_data->packet.address.from, process_function_data->packet.address.to);

	do
		usleep(50000);
	while(dequeue_packet());
}

static void process_function_308(const process_function_data_t *process_function_data)
{
}

static void process_function_309(const process_function_data_t *process_function_data)
{
}

static void process_function_3c2(const process_function_data_t *process_function_data)
{
}

static void process_function_500(const process_function_data_t *process_function_data)
{
	const jump_table_function_500_t *jump;
	char output[4096];
	function_500_subpacket_t subpacket;
	unsigned int current, sub_sequence, sub_packet_type, sub_packet_length, id;
	const uint8_t *data;
	unsigned int stamp;
	char datestring[32];

	data = process_function_data->packet.payload.data;

	for(current = 0, sub_sequence = 0; (current + 8) < process_function_data->packet.payload.length; sub_sequence++)
	{
		sub_packet_type = uint2le_to_unsigned(&data[current + 0]);
		id = uint4le_to_unsigned(&data[current + 2]) & 0xff7fffff;
		sub_packet_length = uint2le_to_unsigned(&data[current + 6]);

		printlog(log_info, "process_function_500 current:%u, payload_length: %u, sub_sequence:%u, sub_packet_type:%u sub_packet_length:%u id:%08x",
				current, process_function_data->packet.payload.length, sub_sequence, sub_packet_type, sub_packet_length, id);

		current += 8;

		for(jump = jump_table_500; jump->process_function != (void(*)(function_500_subpacket_t *))0; jump++)
			if(jump->sub_packet_type == sub_packet_type)
				goto found;

		printlog(log_notice, "500/post: unknown subtype: %04x", sub_packet_type);
		current += sub_packet_length;
		continue;

found:
		subpacket.sub_sequence = sub_sequence;
		subpacket.sub_packet_type = sub_packet_type;
		subpacket.id = id;
		subpacket.sub_packet_payload.length = sub_packet_length;
		subpacket.sub_packet_payload.data = &data[current];
		subpacket.process_function_data = process_function_data;
		subpacket.output.size = sizeof(output);
		subpacket.output.data = output;
		subpacket.output.data[0] = '\0';

		if(sub_packet_length < jump->minimal_data_length)
		{
			printlog(log_notice, "function %x/%x (%s) payload too small: %u/%u\n",
					process_function_data->packet.function, sub_packet_type, jump->name, sub_packet_length, jump->minimal_data_length);
			return;
		}

		if(jump->has_stamp)
		{
			stamp = uint4le_to_unsigned(&subpacket.sub_packet_payload.data[0]);
			stamp_to_string(sizeof(datestring), datestring, stamp);
		}
		else
			strncpy(datestring, "<no stamp>", sizeof(datestring) - 1);

		jump->process_function(&subpacket);

		printlog(log_info, "function %x/%x (%s) %s: sequence:%04x%s ",
				process_function_data->packet.function, sub_packet_type, jump->name, datestring, process_function_data->packet.sequence, subpacket.output.data);

		current += sub_packet_length;
	}

	enqueue_ack(process_function_data->packet.socket_fd, process_function_data->packet.sequence, process_function_data->packet.address.to, process_function_data->packet.address.from);
}

static void process_function_501(const process_function_data_t *process_function_data)
{
	printlog(log_info, "received request for time, sequence:%04x", process_function_data->packet.sequence);
	send_datetime(process_function_data->packet.socket_fd, process_function_data->packet.sequence,
				process_function_data->packet.address.to, process_function_data->packet.address.from);
}


static void process_function_4288(const process_function_data_t *process_function_data)
{
	enqueue_ack(process_function_data->packet.socket_fd, process_function_data->packet.sequence_exception,
			process_function_data->packet.address.to, process_function_data->packet.address.from);
}

static void process_function_428a(const process_function_data_t *process_function_data)
{
	static bool once = true;

	if(once)
	{
		once = false;
		char output[65536];
		dump(process_function_data->packet.payload.length, process_function_data->packet.payload.data, sizeof(output), output);
		printlog(log_debug, "debug function 428a packet dump: %s\n", output);
	}

	enqueue_ack(process_function_data->packet.socket_fd, process_function_data->packet.sequence_exception,
			process_function_data->packet.address.to, process_function_data->packet.address.from);
}

static void state_save(const char *filename, unsigned int sequence, unsigned int address_master, unsigned int address_slave)
{
	FILE *fp;

	if(filename == (const char *)0)
	{
		printlog(log_notice, "no sequence save file");
		return;
	}

	if((fp = fopen(filename, "w")) == (FILE *)0)
	{
		printlog(log_notice, "sequence save file cannot be opened");
		return;
	}

	if(fprintf(fp, "0x%04x\n0x%08x\n0x%08x\n", sequence, address_master, address_slave) <= 0)
	{
		printlog(log_notice, "sequence save file cannot be written");
		fclose(fp);
		return;
	}

	fclose(fp);
}

static void state_load(const char *filename, unsigned int *sequence, unsigned int *address_master, unsigned int *address_slave)
{
	FILE *fp;

	if(filename == (const char *)0)
	{
		printlog(log_notice, "no sequence save file");
		return;
	}

	if((fp = fopen(filename, "r")) == (FILE *)0)
	{
		printlog(log_notice, "sequence save file cannot be opened");
		return;
	}

	if(fscanf(fp, "%x\n%x\n%x\n", sequence, address_master, address_slave) != 3)
	{
		printlog(log_notice, "sequence save file cannot be read");
		fclose(fp);
		return;
	}

	fclose(fp);
}

int main(int argc, char *const *argv)
{
	uint8_t current;
	state_collector_t state = sc_no_tag;
	unsigned int skipped;
	unsigned int packet, short_packet, invalid_crc;
	unsigned int datalen, datalen_inv;
	unsigned int new_sequence, sequence;
	unsigned int address_master, address_slave;
	unsigned int function;
	unsigned int their_crc, our_crc;
	uint8_t payload[65536];
	unsigned int payload_length;
	int socket_fd;
	struct addrinfo hints;
	struct addrinfo *res;
	struct sockaddr_in saddr;
	const char *inverter_update_script;
	const char *optimiser_update_script;
	const char *state_save_path_file;
	const char *log_file;
	const char *host;
	unsigned int log_level_value;
	int opt;

	inverter_update_script = (const char *)0;
	optimiser_update_script = (const char *)0;
	state_save_path_file = "/var/lib/secollect/state";
	log_file = (const char *)0;

	address_master = 0xfffffffe;
	address_slave =  0x00000001;
	new_sequence = sequence = 0xffff;

	packet_queue_in = packet_queue_out = packet_queue_length = 0;

	while((opt = getopt(argc, argv, "d:i:l:o:s:v:h?")) != EOF)
	{
		switch(opt)
		{
			case('d'):
			{
				address_slave = strtoul(optarg, (char **)0, 0);
				break;
			}

			case('i'):
			{
				inverter_update_script = optarg;
				break;
			}

			case('l'):
			{
				log_file = optarg;
				break;
			}

			case('o'):
			{
				optimiser_update_script = optarg;
				break;
			}

			case('s'):
			{
				state_save_path_file = optarg;
				break;
			}

			case('v'):
			{
				log_level_value = strtoul(optarg, (char **)0, 10);

				if(log_level_value >= log_size)
				{
					printlog(log_error, "invalid log level: %u", log_level_value);
					return(-1);
				}

				log_level = (log_level_t)log_level_value;
				break;
			}

			case(EOF):
			{
				break;
			}

			default:
			{
				printlog(log_error,
					"usage: secollect [-d default slave address ] [-i inverter-data-update-script] [-o optimiser-data-update-script] [-v loglevel] <host>\n"
					"    log levels: 0 = error, 1 = warning, 2 = notice, 3 = info, 4 = debug");
				return(1);
			}
		}
	}

	if((optind >= argc) || (!argv[optind]))
	{
		printlog(log_error, "missing hostname");
		return(-1);
	}

	host = argv[optind];

	log_file_fp = fopen(log_file, "a");

	state_load(state_save_path_file, &sequence, &address_master, &address_slave);
	payload_length = 0;

	for(;;)
	{
		if((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
			printlog(log_error, "unknown host: %s", host);
			return(-1);
		}

		if(!res || !res->ai_addr)
		{
			printlog(log_error, "unknown host: %s", host);
			return(-1);
		}

		saddr = *(struct sockaddr_in *)res->ai_addr;
		freeaddrinfo(res);

		if(connect(socket_fd, (const struct sockaddr *)&saddr, sizeof(saddr)) < 0)
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

		send_busgrant(socket_fd, address_master, address_slave);

		for(;;)
		{
			struct pollfd pfd[1];
			int status;

			pfd->fd = socket_fd;
			pfd->events = POLLIN | POLLRDHUP;
			pfd->revents = 0;

			switch((status = poll(pfd, 1, 5000)))
			{
				case(0):
				{
					printlog(log_debug, "");
					printlog(log_debug, "");
					printlog(log_debug, "receive poll timeout");

					if(!enqueue_ack(socket_fd, sequence, address_master, address_slave))
						send_ack(socket_fd, sequence, address_master, address_slave);

					send_busgrant(socket_fd, address_master, address_slave);

					continue;
				}

				case(1):
				{
					if(pfd->revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
					{
						if(log_level >= log_warning)
							printlog(log_warning, "poll event error");
						goto reconnect;
					}

					if(pfd->revents & POLLIN)
					{
						switch(recv(socket_fd, &current, sizeof(current), 0))
						{
							case(0):
							{
								printlog(log_warning, "EOF during recv");
								goto reconnect;
							}

							case(1):
							{
								break;
							}

							default:
							{
								printlog(log_warning, "recv error");
								goto reconnect;
							}
						}
					}

					break;
				}

				default:
				{
					printlog(log_warning, "poll error: %m (%d)", status);
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
					{
						skipped++;
						printlog(log_debug2, "skip: %02x", current);
					}

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
					new_sequence = (unsigned int)current;

					state = sc_sequence_hi;

					break;
				}

				case(sc_sequence_hi):
				{
					new_sequence |= (unsigned int)current << 8;

					state = sc_address_slave_0;

					break;
				}

				case(sc_address_slave_0):
				{
					address_slave = (unsigned int)current << 0;

					state = sc_address_slave_1;

					break;
				}

				case(sc_address_slave_1):
				{
					address_slave |= (unsigned int)current << 8;

					state = sc_address_slave_2;

					break;
				}

				case(sc_address_slave_2):
				{
					address_slave |= (unsigned int)current << 16;

					state = sc_address_slave_3;

					break;
				}

				case(sc_address_slave_3):
				{
					address_slave |= (unsigned int)current << 24;

					state = sc_address_master_0;

					break;
				}

				case(sc_address_master_0):
				{
					address_master = (unsigned int)current << 0;

					state = sc_address_master_1;

					break;
				}

				case(sc_address_master_1):
				{
					address_master |= (unsigned int)current << 8;

					state = sc_address_master_2;

					break;
				}

				case(sc_address_master_2):
				{
					address_master |= (unsigned int)current << 16;

					state = sc_address_master_3;

					break;
				}

				case(sc_address_master_3):
				{
					address_master |= (unsigned int)current << 24;

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
						printlog(log_warning, "payload > buffer");
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
					process_function_data_t process_function_data;

					their_crc |= current << 8;

					*ptr++ = (new_sequence & 0xff00) >> 8;
					*ptr++ = (new_sequence & 0x00ff) >> 0;
					*ptr++ = (address_slave & 0xff000000) >> 24;
					*ptr++ = (address_slave & 0x00ff0000) >> 16;
					*ptr++ = (address_slave & 0x0000ff00) >>  8;
					*ptr++ = (address_slave & 0x000000ff) >>  0;
					*ptr++ = (address_master & 0xff000000) >> 24;
					*ptr++ = (address_master & 0x00ff0000) >> 16;
					*ptr++ = (address_master & 0x0000ff00) >>  8;
					*ptr++ = (address_master & 0x000000ff) >>  0;
					*ptr++ = (function & 0xff00) >> 8;
					*ptr++ = (function & 0x00ff) >> 0;
					our_crc = crc16modbus_byte(0x5a5a, header, sizeof(header));
					our_crc = crc16modbus_byte(our_crc, payload, payload_length);

					printlog(log_debug, "packet:%u short:%u invalid crc:%u packet length:%u/%u sequence:%04x/%04x from/slave:%08x to/master:%08x "
							"function:%04x, their_crc:%04x,our_crc:%04x skipped:%u",
							packet++, short_packet, invalid_crc, payload_length, datalen_inv, new_sequence, sequence, address_slave, address_master, function,
							their_crc, our_crc, skipped);

					if((function >= 0x500) && (function < 0x600))
						sequence = new_sequence;

					state_save(state_save_path_file, sequence, address_master, address_slave);

					if(our_crc != their_crc)
					{
						invalid_crc++;
						printlog(log_notice, "packet skipped due to invalid CRC");
						goto next;
					}

					if(payload_length >= sizeof(process_function_data.packet.payload.data))
					{
						printlog(log_warning, "message payload too big");
						goto next;
					}

					for(jump = jump_table_function; jump->process_function != (void(*))0; jump++)
					{
						if(jump->function == function)
						{
							process_function_data.ix = packet;
							process_function_data.packet.function = function;
							process_function_data.packet.socket_fd = socket_fd;
							process_function_data.packet.sequence = sequence;
							process_function_data.packet.sequence_exception = new_sequence;
							process_function_data.packet.address.from = address_slave;
							process_function_data.packet.address.to = address_master;
							process_function_data.script.inverter = inverter_update_script;
							process_function_data.script.optimiser = optimiser_update_script;
							process_function_data.packet.payload.length = payload_length;
							memcpy(process_function_data.packet.payload.data, payload, payload_length);

							jump->process_function(&process_function_data);

							goto next;
						}
					}

					printlog(log_notice, "- skip unknown packet with function %04x", function);
next:
					skipped = 0;
					state = sc_no_tag;

					break;
				}
			}
		}
reconnect:
		sleep(10);
		close(socket_fd);
	}
}
