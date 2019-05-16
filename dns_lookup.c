#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
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

const char *rcode_messages[NUM_RCODES] = {
  "No error",
  "Format error",
  "Server failure",
  "Name error",
  "Not implemented",
  "Refused",
};

void FatalError(const char* format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  exit(EXIT_FAILURE);
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

size_t DecompressEncodedHostname(
  unsigned char* buffer,
  size_t pos,
  unsigned char* dest)
{
  uint8_t label_len;
  size_t total_len = 0;
  size_t compressed_len = 0;

  do {
    label_len = buffer[pos];
    if (total_len >= MAX_NAME_LEN)
      FatalError("Hostname in response is too long\n");
    dest[total_len] = label_len;
    pos++;
    total_len++;
    if (label_len & 0xC0) {
      // pointer
      if ((label_len & 0xC0) != 0xC0)
        FatalError("Reserved upper bits were used\n");
      if (compressed_len != 0)
        FatalError("Multiple pointers in name\n");
      pos = ((label_len & 0x3F) << 8) | buffer[pos];
      compressed_len = total_len + 1;
      total_len--; // remove pointer byte from dest
    } else {
      if (total_len + label_len > MAX_NAME_LEN)
        FatalError("Hostname in response is too long\n");
      memcpy(dest + total_len, buffer + pos, label_len);
      pos += label_len;
      total_len += label_len;
    }
  } while (label_len != 0);

  return compressed_len ? compressed_len : total_len;
}

uint16_t GetU16(unsigned char* buffer)
{
  return ((uint16_t)buffer[0] << 8)
       | ((uint16_t)buffer[1] << 0);
}

uint32_t GetU32(unsigned char* buffer)
{
  return ((uint32_t)buffer[0] << 24)
       | ((uint32_t)buffer[1] << 16)
       | ((uint32_t)buffer[2] << 8)
       | ((uint32_t)buffer[3] << 0);
}

void PutU16(unsigned char* buffer, uint16_t value)
{
  buffer[0] = (value >> 8) & 0xFF;
  buffer[1] = (value >> 0) & 0xFF;
}

void PutU32(unsigned char* buffer, uint16_t value)
{
  buffer[0] = (value >> 24) & 0xFF;
  buffer[1] = (value >> 16) & 0xFF;
  buffer[2] = (value >> 8) & 0xFF;
  buffer[3] = (value >> 0) & 0xFF;
}

void FullSend(int sock, unsigned char* buffer, size_t count)
{
  size_t bytes_left = count;

  while (bytes_left != 0) {
    ssize_t bytes_written = write(sock, buffer, bytes_left);
    if (bytes_written == -1)
      FatalError("Failed to write to socket: %s\n", strerror(errno));
    buffer += bytes_written;
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
  unsigned char* buffer = malloc(len + 2);

  if (!buffer)
    FatalError("Failed to allocate memory for query buffer\n");

  // Fill in the length.
  PutU16(buffer, len);

  // Fill in header.
  PutU16(buffer + 2, id);
  PutU16(buffer + 4, OPCODE(OP_QUERY) | RD); // flags
  PutU16(buffer + 6, 1); // question count
  PutU16(buffer + 8, 0); // answer count
  PutU16(buffer + 10, 0); // authority count
  PutU16(buffer + 12, 0); // additional count

  // Fill in question.
  memcpy(buffer + 2 + HEADER_LEN, encoded_hostname, encoded_hostname_len);
  PutU16(buffer + 2 + HEADER_LEN + encoded_hostname_len, TYPE_A);
  PutU16(buffer + 2 + HEADER_LEN + encoded_hostname_len + 2, CLASS_IN);

  FullSend(sock, buffer, len + 2);

  free(buffer);
}

void FullRecv(int sock, unsigned char* buffer, size_t count)
{
  size_t total_bytes_read = 0;

  while (total_bytes_read < count) {
    ssize_t bytes_read = read(
      sock,
      buffer + total_bytes_read,
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
  unsigned char len_buffer[2];
  unsigned char encoded_hostname[MAX_NAME_LEN];

  FullRecv(sock, len_buffer, sizeof(len_buffer));

  uint16_t len = GetU16(len_buffer);

  if (len < HEADER_LEN)
    FatalError("Response doesn't have header\n");

  unsigned char* buffer = malloc(len);

  if (!buffer)
    FatalError("Failed to allocate memory for response buffer\n");

  FullRecv(sock, buffer, len);

  // Extract header.
  uint16_t id = GetU16(buffer);
  uint16_t flags = GetU16(buffer + 2);
  uint16_t question_count = GetU16(buffer + 4);
  uint16_t answer_count = GetU16(buffer + 6);

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

  size_t pos = HEADER_LEN;

  // Skip questions.
  for (uint16_t i = 0; i < question_count; i++) {
    pos += DecompressEncodedHostname(buffer, pos, encoded_hostname);
    pos += QUESTION_FIXED_LEN;
  }

  for (uint16_t i = 0; i < answer_count; i++) {
    pos += DecompressEncodedHostname(buffer, pos, encoded_hostname);
    uint16_t type = GetU16(buffer + pos);
    pos += 2;
    uint16_t class = GetU16(buffer + pos);
    pos += 2;
    *ttl = GetU32(buffer + pos);
    pos += 4;
    uint16_t rdata_len = GetU16(buffer + pos);
    pos += 2;
    if (type == TYPE_A && class == CLASS_IN) {
      if (rdata_len != 4)
        FatalError("Invalid RDLENGTH for IPv4 address\n");
      addr->s_addr = htonl(GetU32(buffer + pos));
      if (EncodedHostnamesEqual(expected_encoded_hostname, encoded_hostname)) {
        free(buffer);
        return;
      }
    }
    pos += rdata_len;
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
