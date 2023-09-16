#include "crc16modbus.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

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

typedef struct
{
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
	} message;
} process_data_t;

typedef struct
{
	const process_data_t *process_data;
	unsigned int type;
	unsigned int id;
	unsigned int data_length;
	const uint8_t *data;
} jump_table_500_data_t;

typedef struct
{
	unsigned int data_type;
	void (*process)(const jump_table_500_data_t *);
} jump_table_500_t;

static void process_500_10(const jump_table_500_data_t *);
static void process_500_17(const jump_table_500_data_t *);
static void process_500_18(const jump_table_500_data_t *);
static void process_500_22(const jump_table_500_data_t *);
static void process_500_40(const jump_table_500_data_t *);
static void process_500_41(const jump_table_500_data_t *);
static void process_500_42(const jump_table_500_data_t *);
static void process_500_43(const jump_table_500_data_t *);
static void process_500_44(const jump_table_500_data_t *);
static void process_500_47(const jump_table_500_data_t *);
static void process_500_48(const jump_table_500_data_t *);
static void process_500_4d(const jump_table_500_data_t *);
static void process_500_50(const jump_table_500_data_t *);
static void process_500_82(const jump_table_500_data_t *);
static void process_500_300(const jump_table_500_data_t *);
static void process_500_1800(const jump_table_500_data_t *);

static const jump_table_500_t jump_table_500[] =
{
	{	0x10,	process_500_10		},
	{	0x17,	process_500_17		},
	{	0x18,	process_500_18		},
	{	0x22,	process_500_22		},
	{	0x40,	process_500_40		},
	{	0x41,	process_500_41		},
	{	0x42,	process_500_42		},
	{	0x43,	process_500_43		},
	{	0x44,	process_500_44		},
	{	0x47,	process_500_47		},
	{	0x48,	process_500_48		},
	{	0x4d,	process_500_4d		},
	{	0x50,	process_500_50		},
	{	0x82,	process_500_82		},
	{	0x300,	process_500_300		},
	{	0x1800,	process_500_1800	},
	{	0x0,	(void(*))0			},
};

static unsigned int short_to_unsigned(const uint8_t *ptr)
{
	return( (ptr[0] << 0) |
			(ptr[1] << 8));
}

static unsigned int long_to_unsigned(const uint8_t *ptr)
{
	return( (ptr[0] << 0) |
			(ptr[1] << 8) |
			(ptr[2] << 16) |
			(ptr[3] << 24));
}

static float long_to_float(const uint8_t *ptr)
{
	float rv;

	rv = *(const float *)ptr;

	return(rv);
}

static void long_to_stamp(const uint8_t *ptr, unsigned int datestring_size, char *datestring)
{
	time_t ticks;
	const struct tm *tm;

	ticks = (time_t)long_to_unsigned(ptr);
	tm = localtime(&ticks);
	strftime(datestring, datestring_size - 1, "%Y-%m-%d %H:%M", tm);
}

static void dump(unsigned int type, unsigned int id, unsigned int length, const uint8_t *data)
{
	unsigned int ix;

	printf("- %x: %x -\n", type, id);

	for(ix = 0; ix < length; ix++)
	{
		if((ix % 4) == 0)
		{
			if(ix != 0)
				printf("\n");
			printf("%2u ", ix);
		}

		printf("%02x ", data[ix]);
	}

	printf("\n");
}

static void process_80(const process_data_t *process_data)
{
	printf("# ack:            seq:%04x\n", process_data->sequence);
}

static void process_3c2(const process_data_t *process_data)
{
#if 0
	unsigned int field_0_3;
	unsigned int field_4_7; // timestamp unix epoch
	unsigned int field_8_11;
	unsigned int field_12_15;
	static unsigned int field_12_15_prev = 0;
	static unsigned int field_12_15_min = ~0;
	static unsigned int field_12_15_max = 0;
	char datestring[32];
	//unsigned int vpanel, voptimiser, current;

	field_0_3 = long_to_unsigned(&message[0]));
	field_4_7 = long_to_unsigned(&message[4]));
	field_8_11 = long_to_unsigned(&message[8]));
	field_12_15 = long_to_unsigned(&message[12]));

	//field_12_15 &= 0x0fffffff;

	long_to_stamp(&message[4], sizeof(datestring), datestring);

	if(field_12_15 < field_12_15_min)
		field_12_15_min = field_12_15;

	if(field_12_15 > field_12_15_max)
		field_12_15_max = field_12_15;

	//vpanel =		0.125 * (data[6] | (data[7] << 8 & 0x300));
	//voptimiser =	0.125 * (data[7] >> 2 | (data[8] << 6 & 0x3c0));
	//current =		0.00625 * (data[9] << 4 | (data[8] >> 4 & 0xf));

	printf("field 0-3:   %08x %12u\n", field_0_3, field_0_3);
	printf("field 4-7:   %08x %12u [%s]\n", field_4_7, field_4_7, datestring);
	printf("field 8-11:  %08x %12u\n", field_8_11, field_8_11);
	printf("field 12-15: %08x %12u [delta %6d] <min: %6u, max: %6u> [%.3f]\n", field_12_15, field_12_15, (int)(field_12_15 - field_12_15_prev), field_12_15_min, field_12_15_max, field_12_15 / 125000000.0);

	field_12_15_prev = field_12_15;
	dump(0x3c2, 0, length, message);
#endif
}

static void dump_500(const jump_table_500_data_t *data)
{
	return(dump(data->type, data->id, data->data_length, data->data));
}

static void process_500_10(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data = jump_data->data;
	unsigned int uptime;
	char datestring[32];
	float temperature, acv, aci, acf, dcv, acp;

	long_to_stamp(&data[0], sizeof(datestring), datestring);
	uptime = long_to_unsigned(&data[4]);
	temperature = long_to_float(&data[12]);

	acv = long_to_float(&data[24]);
	aci = long_to_float(&data[28]);
	acf = long_to_float(&data[32]);
	dcv = long_to_float(&data[44]);
	acp = long_to_float(&data[92]);

	printf("# inverter data:  seq:%04x             uptime:%s,%u temp:%f acv:%f aci:%f acf:%f dcv:%f acp:%f\n",
			jump_data->process_data->sequence, datestring, uptime / 3600, temperature, acv, aci, acf, dcv, acp);
}

static void process_500_17(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 17: %s\n", datestring);

	(void)dump_500;
	//return(dump_500(jump_data));
}

static void process_500_18(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 18: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_22(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[32];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# meter data:     seq:%04x             uptime:%s\n", jump_data->process_data->sequence, datestring);
}

static void process_500_40(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 40: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_41(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 41: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_42(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 42: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_43(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 43: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_44(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 44: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_47(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 47: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_48(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 48: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_4d(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 4d: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500_50(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[32];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 50: %s\n", datestring);
}

static void process_500_82(const jump_table_500_data_t *jump_data) // s440 optimiser data
{
	unsigned int length;
	const uint8_t *data;
	unsigned int uptime;
	unsigned int vpanel, voptimiser, current;
	char datestring[32];

	length = jump_data->data_length;
	data = jump_data->data;

	if(length < 10)
		return; // FIXME

	long_to_stamp(&data[0], sizeof(datestring), datestring);
	uptime = short_to_unsigned(&data[4]);

	vpanel =		0.125 * (data[6] | (data[7] << 8 & 0x300));
	voptimiser =	0.125 * (data[7] >> 2 | (data[8] << 6 & 0x3c0));
	current =		0.00625 * (data[9] << 4 | (data[8] >> 4 & 0xf));

	printf("# optimiser data: seq:%04x id:%08x uptime:%s,%u vpanel:%u voptimiser:%u current:%u\n",
			jump_data->process_data->sequence, jump_data->id, datestring, uptime / 3600, vpanel, voptimiser, current);
}

static void process_500_300(const jump_table_500_data_t *jump_data)
{
#if 0
	const uint8_t *data;
	char datestring1[32];
	char datestring2[32];
	char datestring3[32];
	unsigned int type;

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring1), datestring1);
	type = long_to_unsigned(&data[4]);
	long_to_stamp(&data[8], sizeof(datestring2), datestring2);

	switch(type)
	{
		case(0):
		{
			long_to_stamp(&data[12], sizeof(datestring3), datestring3);
			printf("# event: %u: %s,%s,%s\n", type, datestring1, datestring2, datestring3);
			break;
		}

		case(1):
		{
			long_to_stamp(&data[16], sizeof(datestring3), datestring3);
			printf("# event: %u: %s,%s,%s\n", type, datestring1, datestring2, datestring3);
			break;
		}

		default:
		{
			printf("# event: %u: unknown\n", type);
			break;
		}
	}

	return(dump_500(jump_data));
#endif
}

static void process_500_1800(const jump_table_500_data_t *jump_data)
{
	const uint8_t *data;
	char datestring[64];

	data = jump_data->data;

	long_to_stamp(&data[0], sizeof(datestring), datestring);

	printf("# unknown type 1800: %s\n", datestring);

	//return(dump_500(jump_data));
}

static void process_500(const process_data_t *process_data)
{
	unsigned int ix, seq;
	unsigned int data_type, data_id, data_length;
	const jump_table_500_t *jump;
	jump_table_500_data_t jump_data;

	for(seq = 0, ix = 0; (ix + 8) < process_data->message.length; seq++)
	{
		data_type =	short_to_unsigned(&process_data->message.data[ix + 0]);
		data_id = long_to_unsigned(&process_data->message.data[ix + 2]);
		data_id &= 0xff7fffff;
		data_length = short_to_unsigned(&process_data->message.data[ix + 6]);

		//printf("500 %02u type:%04x id:%08x len:%u\n", seq, data_type, data_id, data_length);

		ix += 8;

		for(jump = jump_table_500; jump->process != (void(*)(const jump_table_500_data_t *))0; jump++)
		{
			if(jump->data_type == data_type)
			{
				jump_data.type = data_type;
				jump_data.id = data_id;
				jump_data.data_length = data_length;
				jump_data.data = &process_data->message.data[ix];
				jump_data.process_data = process_data;

				jump->process(&jump_data);
				goto ok;
			}
		}

		printf("* 500: unknown subtype: %04x\n", data_type);
ok:
		ix += data_length;
	}
}

int main(int argc, const char * const *argv)
{
	int current;
	state_collector_t state = sc_no_tag;
	unsigned int skipped;
	unsigned int packet, short_packet;
	unsigned int datalen, datalen_inv;
	unsigned int sequence;
	unsigned int address_from, address_to;
	unsigned int function;
	unsigned int message_length;
	unsigned int their_crc, our_crc;
	uint8_t message[65536];

	function = 0;
	datalen = 0;
	skipped = 0;
	packet = 0;
	short_packet = 0;
	sequence = 0;

	while((current = fgetc(stdin)) != EOF)
	{
		printf("[%u]: %02x\n", state, (unsigned int)current);

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

				message_length = 0;

				if(datalen >= sizeof(message))
				{
					printf("message > buffer\n");
					datalen = sizeof(message) - 1;
				}

				state = sc_data_no_tag;

				if(datalen == 0)
					state = sc_crc_lo;

				break;
			}

			case(sc_data_no_tag):
			{
				message[message_length++] = current;

				if(message_length >= datalen)
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
				message[message_length++] = current;

				if(message_length >= datalen)
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
				message[message_length++] = current;

				if(message_length >= datalen)
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
				message[message_length++] = current;

				if(message_length >= datalen)
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
				process_data_t process_data;

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
				our_crc = crc16modbus_byte(our_crc, message, datalen);

				printf("  packet:%03u short:%03u, packet length:%3u/%3u sequence:%4x from:%08x to:%08x function:%04x, their crc:%04x our crc:%04x, skipped:%03u\n",
						packet++, short_packet, datalen, datalen_inv, sequence, address_from, address_to, function, their_crc, our_crc, skipped);

				process_data.ix = packet;
				process_data.sequence = sequence;
				process_data.address.from = address_from;
				process_data.address.to = address_to;
				process_data.function = function;
				process_data.message.length = datalen;
				process_data.message.data = message;

				if(our_crc != their_crc)
					printf("* packet skipped due to invalid CRC\n");
				else
				{
					switch(function)
					{
						case(0x80):
						{
							process_80(&process_data);
							break;
						}
						case(0x3c2):
						{
							process_3c2(&process_data);
							break;
						}
						case(0x500):
						{
							process_500(&process_data);
							break;
						}

						default:
						{
							printf("* unknown function %x\n", function);
						}
					}
				}

				skipped = 0;
				state = sc_no_tag;

				break;
			}
		}
	}
}
