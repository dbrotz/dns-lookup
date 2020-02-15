// Copyright 2019 David Brotz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DNS_PORT 53

#define MAX_NAME_LEN  255
#define MAX_LABEL_LEN  63

#define TYPE_A      1 // IPv4 address record
#define TYPE_CNAME  5 // canonical name record
#define TYPE_AAAA  28 // IPv6 address record

#define CLASS_IN 1 // Internet

#define HEADER_LEN 12
#define QUESTION_FIXED_LEN 4

#define OP_QUERY  0
#define OP_IQUERY 1
#define OP_STATUS 2

#define RCODE_MASK 0xF

#define QR         (1 << 15)
#define OPCODE(op) ((op) << 11)
#define AA         (1 << 10)
#define RD         (1 << 8)

#define NUM_RCODES 6

typedef struct Buffer {
  unsigned char* data;
  size_t pos;
  size_t len;
} Buffer;

typedef struct EncodedName {
  unsigned char name[MAX_NAME_LEN];
  size_t len;
} EncodedName;

typedef enum Result {
  RES_FOUND,
  RES_CNAME,
  RES_FAILED,
} Result;

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

void GetBytes(Buffer* buffer, void* bytes, size_t count)
{
  GetBytesAt(buffer, &buffer->pos, bytes, count);
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

int Connect(const char* addr_str)
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

void EncodeName(const char* name, EncodedName* encoded_name)
{
  encoded_name->len = strlen(name) + 2;

  if (encoded_name->len > MAX_NAME_LEN)
    FatalError("Name is too long\n");

  int label_start = 0;
  int label_len = 0;
  int in_pos = 0;
  int out_pos = 0;

  while (1) {
    unsigned char c = name[in_pos];
    if (c == '.' || c == 0) {
      if (label_len == 0)
        FatalError("Empty label in name\n");
      if (label_len > MAX_LABEL_LEN)
        FatalError("Label is too long\n");
      encoded_name->name[out_pos++] = label_len;
      memcpy(encoded_name->name + out_pos, name + label_start, label_len);
      out_pos += label_len;
      if (c == 0)
        break;
      label_start = in_pos + 1;
      label_len = 0;
    } else {
      label_len++;
    }
    in_pos++;
  }

  encoded_name->name[out_pos] = 0;
}

bool IsPrintableCharacter(unsigned char c)
{
  return (c >= 0x20 && c < 0x7F);
}

// encoded_name can't be compressed and name has to be
// able to hold at least MAX_NAME_LEN - 1 bytes.
// Also, this function doesn't attempt to validate encoded_name,
// so it has to be validated before calling this.
void DecodeName(char* name, const EncodedName* encoded_name)
{
  uint8_t label_len;
  size_t in_pos = 0;
  size_t out_pos = 0;

  while ((label_len = encoded_name->name[in_pos++]) != 0) {
    memcpy(name + out_pos, encoded_name->name + in_pos, label_len);
    in_pos += label_len;
    out_pos += label_len;
    name[out_pos++] = '.';
  }

  out_pos--;
  name[out_pos] = 0;

  // Replace unprintable chars with '?'.
  for (size_t i = 0; i < out_pos; i++)
    if (!IsPrintableCharacter(name[i]))
      name[i] = '?';
}

// Don't use the standard tolower() function because of potential
// undefined behavior and sensitivity to locale.
unsigned char ToLower(unsigned char c)
{
  return (c >= 'A' && c <= 'Z') ? c + 'a' - 'A' : c;
}

bool EncodedNamesEqual(const EncodedName* name1, const EncodedName* name2)
{
  if (name1->len != name2->len)
    return false;

  if (name1->len > MAX_NAME_LEN)
    FatalError("Name is too long\n");

  int len = name1->len;

  for (int i = 0; i < len; i++) {
    unsigned char c1 = ToLower(name1->name[i]);
    unsigned char c2 = ToLower(name2->name[i]);

    if (c1 != c2)
      return false;
  }

  return true;
}

size_t DecompressEncodedName(Buffer* buffer, EncodedName* dest)
{
  uint8_t label_len;
  size_t total_len = 0;
  size_t compressed_end_pos = 0;
  size_t pos = buffer->pos;
  size_t last_offset = buffer->len;

  do {
    label_len = GetU8At(buffer, &pos);
    if (total_len >= MAX_NAME_LEN)
      FatalError("Compressed name is too long\n");
    dest->name[total_len] = label_len;
    total_len++;
    if (label_len & 0xC0) {
      // pointer
      if ((label_len & 0xC0) != 0xC0)
        FatalError("Reserved upper bits were used\n");
      size_t offset = ((label_len & 0x3F) << 8);
      offset |= GetU8At(buffer, &pos);
      if (offset >= last_offset)
        FatalError("Possible infinite loop in compressed name\n");
      last_offset = offset;
      if (!compressed_end_pos)
        compressed_end_pos = pos;
      pos = offset;
      total_len--; // remove pointer byte from dest
    } else {
      if (total_len + label_len > MAX_NAME_LEN)
        FatalError("Compressed name is too long\n");
      GetBytesAt(buffer, &pos, dest->name + total_len, label_len);
      total_len += label_len;
    }
  } while (label_len != 0);

  dest->len = total_len;

  return compressed_end_pos ? compressed_end_pos : pos;
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
  EncodedName* encoded_name,
  bool v6)
{
  uint16_t len = HEADER_LEN + encoded_name->len + QUESTION_FIXED_LEN;
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
  PutBytes(&buffer, encoded_name->name, encoded_name->len);
  PutU16(&buffer, v6 ? TYPE_AAAA : TYPE_A);
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

Result ReceiveResponse(
  int sock,
  uint16_t expected_id,
  EncodedName* expected_encoded_name,
  void* addr,
  uint32_t* ttl,
  bool* is_authoritative,
  bool v6)
{
  Result res = RES_FAILED;
  EncodedName encoded_name;
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

  *is_authoritative = ((flags & AA) != 0);

  uint8_t rcode = flags & RCODE_MASK;

  if (rcode != 0) {
    if (rcode >= NUM_RCODES)
      FatalError("Unknown response code %u\n", rcode);
    FatalError("Response code %u: %s\n", rcode, rcode_messages[rcode]);
  }

  buffer.pos = HEADER_LEN;

  // Skip questions.
  for (uint16_t i = 0; i < question_count; i++) {
    buffer.pos = DecompressEncodedName(&buffer, &encoded_name);
    buffer.pos += QUESTION_FIXED_LEN;
  }

  uint16_t expected_type = v6 ? TYPE_AAAA : TYPE_A;
  uint16_t expected_rdata_len = v6 ? 16 : 4;

  for (uint16_t i = 0; i < answer_count; i++) {
    buffer.pos = DecompressEncodedName(&buffer, &encoded_name);
    uint16_t type = GetU16(&buffer);
    uint16_t class = GetU16(&buffer);
    *ttl = GetU32(&buffer);
    uint16_t rdata_len = GetU16(&buffer);
    if (EncodedNamesEqual(expected_encoded_name, &encoded_name)
        && class == CLASS_IN) {
      // names match and it's Internet class
      if (type == TYPE_CNAME) {
        // We hope to find the address for the canonical name in a following
        // record.
        size_t end = DecompressEncodedName(&buffer, expected_encoded_name);
        if (end != buffer.pos + rdata_len)
          FatalError("Invalid name in CNAME RDATA\n");
        char name[MAX_NAME_LEN - 1];
        DecodeName(name, expected_encoded_name);
        printf("Switching to CNAME \"%s\"...\n", name);
        res = RES_CNAME;
      } else if (type == expected_type) {
        if (rdata_len != expected_rdata_len)
          FatalError("Invalid RDLENGTH for IPv%c address\n", v6 ? '6' : '4');
        GetBytes(&buffer, addr, rdata_len);
        res = RES_FOUND;
        break;
      }
    }
    buffer.pos += rdata_len;
  }

  free(buffer.data);
  return res;
}

void PrintUsage(void)
{
  FatalError("Usage: dns_lookup [-v6] DNS_SERVER_ADDR HOSTNAME\n");
}

int main(int argc, char** argv)
{
  srand(time(NULL));

  bool v6 = false;

  // Check for "-v6" and remove from argv.
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-v6")) {
      v6 = true;
      argc--;
      for (int j = i; j < argc; j++)
        argv[j] = argv[j + 1];
    }
  }

  if (argc < 3)
    PrintUsage();

  char* dns_server_addr_str = argv[1];
  char* hostname = argv[2];

  EncodedName encoded_name;

  EncodeName(hostname, &encoded_name);

  int sock = Connect(dns_server_addr_str);

  uint16_t id = rand();

  struct in_addr host_addr_v4;
  struct in6_addr host_addr_v6;
  void* host_addr = v6 ? (void*)&host_addr_v6 : (void*)&host_addr_v4;
  uint32_t ttl;
  bool is_authoritative;

  int tries = 0;
  Result res;

  do {
    if (tries > 0)
      printf("Retrying...\n");
    SendQuery(sock, id, &encoded_name, v6);
    res = ReceiveResponse(
      sock,
      id,
      &encoded_name,
      host_addr,
      &ttl,
      &is_authoritative,
      v6);
    tries++;
    id++;
  } while (res == RES_CNAME && tries < 2);

  close(sock);

  if (res != RES_FOUND)
    FatalError("No matching answer with address record in response\n");

  static_assert(
    INET6_ADDRSTRLEN >= INET_ADDRSTRLEN,
    "IPv6 buffer not as big as IPv4 buffer");
  char host_addr_str[INET6_ADDRSTRLEN];

  int af = v6 ? AF_INET6 : AF_INET;
  socklen_t size = v6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
  if (!inet_ntop(af, host_addr, host_addr_str, size))
    FatalError(
      "Failed to convert host address to text: %s\n",
      strerror(errno));

  printf("IP Address: %s\n", host_addr_str);
  printf("TTL: %lu\n", (unsigned long)ttl);
  printf("Authoritative: %s\n", is_authoritative ? "yes" : "no");

  return 0;
}
