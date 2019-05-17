#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DNS_PORT 53

#define MAX_NAME_LEN  255
#define MAX_LABEL_LEN 63

#define TYPE_A 1 // address record

#define CLASS_IN 1 // Internet

#define HEADER_LEN 12
#define QUESTION_FIXED_LEN 4

#define OP_QUERY  0
#define OP_IQUERY 1
#define OP_STATUS 2

#define RCODE_MASK 0xF

#define QR         (1 << 15)
#define OPCODE(op) ((op) << 11)
#define RD         (1 << 8)

#define NUM_RCODES 6

typedef struct Buffer {
  unsigned char* data;
  size_t pos;
  size_t len;
} Buffer;

const char* rcode_messages[NUM_RCODES] = {
  "No error",
  "Format error",
  "Server failure",
  "Name error",
  "Not implemented",
  "Refused",
};

noreturn void FatalError(const char* format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  exit(EXIT_FAILURE);
}

void CheckReadBufferOverflowAt(Buffer* buffer, size_t pos, size_t count)
{
  size_t len = buffer->len;
  size_t new_pos = pos + count;
  if (new_pos > len || new_pos < pos)
    FatalError("Buffer overflow when reading %zu bytes\n", count);
}

void CheckReadBufferOverflow(Buffer* buffer, size_t count)
{
  CheckReadBufferOverflowAt(buffer, buffer->pos, count);
}

void CheckWriteBufferOverflowAt(Buffer* buffer, size_t pos, size_t count)
{
  size_t len = buffer->len;
  size_t new_pos = pos + count;
  if (new_pos > len || new_pos < pos)
    FatalError("Buffer overflow when writing %zu bytes\n", count);
}

void CheckWriteBufferOverflow(Buffer* buffer, size_t count)
{
  CheckWriteBufferOverflowAt(buffer, buffer->pos, count);
}

uint8_t GetU8At(Buffer* buffer, size_t* pos)
{
  CheckReadBufferOverflowAt(buffer, *pos, 1);
  uint8_t value = buffer->data[*pos];
  *pos += 1;
  return value;
}

uint16_t GetU16(Buffer* buffer)
{
  CheckReadBufferOverflow(buffer, 2);
  unsigned char* data = buffer->data + buffer->pos;
  uint16_t value = ((uint16_t)data[0] << 8)
                 | ((uint16_t)data[1] << 0);
  buffer->pos += 2;
  return value;
}

uint32_t GetU32(Buffer* buffer)
{
  CheckReadBufferOverflow(buffer, 4);
  unsigned char* data = buffer->data + buffer->pos;
  uint32_t value = ((uint32_t)data[0] << 24)
                 | ((uint32_t)data[1] << 16)
                 | ((uint32_t)data[2] << 8)
                 | ((uint32_t)data[3] << 0);
  buffer->pos += 4;
  return value;
}

void GetBytesAt(Buffer* buffer, size_t* pos, void* bytes, size_t count)
{
  CheckReadBufferOverflowAt(buffer, *pos, count);
  memcpy(bytes, buffer->data + *pos, count);
  *pos += count;
}

void PutU16(Buffer* buffer, uint16_t value)
{
  CheckWriteBufferOverflow(buffer, 2);
  unsigned char* data = buffer->data + buffer->pos;
  data[0] = (value >> 8) & 0xFF;
  data[1] = (value >> 0) & 0xFF;
  buffer->pos += 2;
}

void PutU32(Buffer* buffer, uint16_t value)
{
  CheckWriteBufferOverflow(buffer, 4);
  unsigned char* data = buffer->data + buffer->pos;
  data[0] = (value >> 24) & 0xFF;
  data[1] = (value >> 16) & 0xFF;
  data[2] = (value >> 8) & 0xFF;
  data[3] = (value >> 0) & 0xFF;
  buffer->pos += 4;
}

void PutBytes(Buffer* buffer, void* bytes, size_t count)
{
  CheckWriteBufferOverflow(buffer, count);
  memcpy(buffer->data + buffer->pos, bytes, count);
  buffer->pos += count;
}

int Connect(char* addr_str)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);

  if (sock == -1)
    FatalError("Failed to create socket: %s\n", strerror(errno));

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(DNS_PORT),
    .sin_addr = {0}
  };

  if (!inet_pton(AF_INET, addr_str, &addr.sin_addr))
    FatalError("\"%s\" is not a valid IPv4 address\n", addr_str);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    FatalError("Failed to connect: %s\n", strerror(errno));

  return sock;
}

bool IsValidCharacter(unsigned char c)
{
  return ((c >= 'a' && c <= 'z')
       || (c >= 'A' && c <= 'Z')
       || (c >= '0' && c <= '9')
       || c == '-');
}

unsigned char* EncodeHostname(char* hostname, size_t* len)
{
  *len = strlen(hostname) + 2;

  if (*len > MAX_NAME_LEN)
    FatalError("Hostname in query is too long\n");

  unsigned char* encoded_hostname = malloc(*len);

  if (!encoded_hostname)
    FatalError("Failed to allocate memory for encoded hostname\n");

  int label_start = 0;
  int label_len = 0;
  int out = 0;

#define COPY_LABEL()                                                 \
do {                                                                 \
  if (label_len == 0)                                                \
    FatalError("Empty label in hostname\n");                         \
  if (label_len > MAX_LABEL_LEN)                                     \
    FatalError("Label is too long\n");                               \
  encoded_hostname[out++] = label_len;                               \
  memcpy(encoded_hostname + out, hostname + label_start, label_len); \
  out += label_len;                                                  \
} while (0)

  for (int i = 0; hostname[i]; i++) {
    unsigned char c = hostname[i];
    if (c == '.') {
      COPY_LABEL();
      label_start = i + 1;
      label_len = 0;
    } else if (!IsValidCharacter(c)) {
      FatalError("Hostname contains invalid character: 0x%X\n", c);
    } else {
      label_len++;
    }
  }

  // Copy the final label at the end.
  COPY_LABEL();

#undef COPY_LABEL

  encoded_hostname[out++] = 0;

  return encoded_hostname;
}

// Don't use the standard tolower() function because of potential
// undefined behavior and sensitivity to locale.
unsigned char ToLower(unsigned char c)
{
  return (c >= 'A' && c <= 'Z') ? c + 'a' - 'A' : c;
}

bool EncodedHostnamesEqual(unsigned char* name1, unsigned char* name2)
{
  int i;

  for (i = 0; i < MAX_NAME_LEN; i++) {
    int c1 = ToLower(name1[i]);
    int c2 = ToLower(name2[i]);

    if (c1 != c2)
      return false;

    if (!c1)
      break;
  }

  if (i == MAX_NAME_LEN)
    FatalError("Hostnames are too long\n");

  return true;
}

void DecompressEncodedHostname(Buffer* buffer, unsigned char* dest)
{
  uint8_t label_len;
  size_t total_len = 0;
  size_t compressed_end_pos = 0;
  size_t pos = buffer->pos;

  do {
    label_len = GetU8At(buffer, &pos);
    if (total_len >= MAX_NAME_LEN)
      FatalError("Hostname in response is too long\n");
    dest[total_len] = label_len;
    total_len++;
    if (label_len & 0xC0) {
      // pointer
      if ((label_len & 0xC0) != 0xC0)
        FatalError("Reserved upper bits were used\n");
      if (compressed_end_pos != 0)
        FatalError("Multiple pointers in name\n");
      size_t offset = ((label_len & 0x3F) << 8);
      offset |= GetU8At(buffer, &pos);
      compressed_end_pos = pos;
      pos = offset;
      total_len--; // remove pointer byte from dest
    } else {
      if (total_len + label_len > MAX_NAME_LEN)
        FatalError("Hostname in response is too long\n");
      GetBytesAt(buffer, &pos, dest + total_len, label_len);
      total_len += label_len;
    }
  } while (label_len != 0);

  buffer->pos = compressed_end_pos ? compressed_end_pos : pos;
}

void FullSend(int sock, unsigned char* data, size_t count)
{
  size_t bytes_left = count;

  while (bytes_left != 0) {
    ssize_t bytes_written = write(sock, data, bytes_left);
    if (bytes_written == -1)
      FatalError("Failed to write to socket: %s\n", strerror(errno));
    data += bytes_written;
    bytes_left -= bytes_written;
  }
}

void SendQuery(
  int sock,
  uint16_t id,
  unsigned char* encoded_hostname,
  size_t encoded_hostname_len)
{
  uint16_t len = HEADER_LEN + encoded_hostname_len + QUESTION_FIXED_LEN;
  size_t total_len = len + 2;

  Buffer buffer = {
    .data = malloc(total_len),
    .pos = 0,
    .len = total_len
  };

  if (!buffer.data)
    FatalError("Failed to allocate memory for query buffer\n");

  // Fill in the length.
  PutU16(&buffer, len);

  // Fill in header.
  PutU16(&buffer, id);
  PutU16(&buffer, OPCODE(OP_QUERY) | RD); // flags
  PutU16(&buffer, 1); // question count
  PutU16(&buffer, 0); // answer count
  PutU16(&buffer, 0); // authority count
  PutU16(&buffer, 0); // additional count

  // Fill in question.
  PutBytes(&buffer, encoded_hostname, encoded_hostname_len);
  PutU16(&buffer, TYPE_A);
  PutU16(&buffer, CLASS_IN);

  FullSend(sock, buffer.data, buffer.len);

  free(buffer.data);
}

void FullRecv(int sock, unsigned char* data, size_t count)
{
  size_t total_bytes_read = 0;

  while (total_bytes_read < count) {
    ssize_t bytes_read = read(
      sock,
      data + total_bytes_read,
      count - total_bytes_read);
    if (bytes_read == 0)
      FatalError("Unexpected EOF when reading from server\n");
    if (bytes_read == -1)
      FatalError("Failed to read from socket: %s\n", strerror(errno));
    total_bytes_read += bytes_read;
  }
}

void ReceiveResponse(
  int sock,
  uint16_t expected_id,
  unsigned char* expected_encoded_hostname,
  struct in_addr* addr,
  uint32_t* ttl)
{
  unsigned char encoded_hostname[MAX_NAME_LEN];
  unsigned char len_data[2];
  Buffer len_buffer = {
    .data = len_data,
    .pos = 0,
    .len = sizeof(len_data)
  };

  FullRecv(sock, len_buffer.data, len_buffer.len);

  uint16_t len = GetU16(&len_buffer);

  if (len < HEADER_LEN)
    FatalError("Response doesn't have header\n");

  Buffer buffer = {
    .data = malloc(len),
    .pos = 0,
    .len = len
  };

  if (!buffer.data)
    FatalError("Failed to allocate memory for response buffer\n");

  FullRecv(sock, buffer.data, buffer.len);

  // Extract header.
  uint16_t id = GetU16(&buffer);
  uint16_t flags = GetU16(&buffer);
  uint16_t question_count = GetU16(&buffer);
  uint16_t answer_count = GetU16(&buffer);

  if (id != expected_id)
    FatalError("Expected ID 0x%X but received ID 0x%X\n", expected_id, id);

  if (!(flags & QR))
    FatalError("QR bit is not set in response\n");

  uint8_t rcode = flags & RCODE_MASK;

  if (rcode != 0) {
    if (rcode >= NUM_RCODES)
      FatalError("Unknown response code %u\n", rcode);
    FatalError("Response code %u: %s\n", rcode, rcode_messages[rcode]);
  }

  buffer.pos = HEADER_LEN;

  // Skip questions.
  for (uint16_t i = 0; i < question_count; i++) {
    DecompressEncodedHostname(&buffer, encoded_hostname);
    buffer.pos += QUESTION_FIXED_LEN;
  }

  for (uint16_t i = 0; i < answer_count; i++) {
    DecompressEncodedHostname(&buffer, encoded_hostname);
    uint16_t type = GetU16(&buffer);
    uint16_t class = GetU16(&buffer);
    *ttl = GetU32(&buffer);
    uint16_t rdata_len = GetU16(&buffer);
    if (type == TYPE_A && class == CLASS_IN) {
      if (rdata_len != 4)
        FatalError("Invalid RDLENGTH for IPv4 address\n");
      addr->s_addr = htonl(GetU32(&buffer));
      if (EncodedHostnamesEqual(expected_encoded_hostname, encoded_hostname)) {
        free(buffer.data);
        return;
      }
    } else {
      buffer.pos += rdata_len;
    }
  }

  FatalError("No matching answer in response\n");
}

int main(int argc, char** argv)
{
  if (argc != 3)
    FatalError("Usage: dns_lookup DNS_SERVER_ADDR HOSTNAME\n");

  srand(time(NULL));

  char* dns_server_addr_str = argv[1];
  char* hostname = argv[2];

  size_t encoded_hostname_len = 0;
  unsigned char* encoded_hostname = EncodeHostname(
    hostname,
    &encoded_hostname_len);

  int sock = Connect(dns_server_addr_str);

  uint16_t id = rand();

  SendQuery(sock, id, encoded_hostname, encoded_hostname_len);

  struct in_addr host_addr;
  uint32_t ttl;

  ReceiveResponse(sock, id, encoded_hostname, &host_addr, &ttl);

  close(sock);
  free(encoded_hostname);

  char host_addr_str[INET_ADDRSTRLEN];

  if (!inet_ntop(AF_INET, &host_addr, host_addr_str, INET_ADDRSTRLEN))
    FatalError(
      "Failed to convert host address to text: %s\n",
      strerror(errno));

  printf("IP Address: %s\n", host_addr_str);
  printf("TTL: %lu\n", (unsigned long)ttl);

  return 0;
}
