#include "StunMessage.h"

#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <numeric>
#include <algorithm>

using namespace std;


StunMessage::StunMessage()
{
  header_.type = StunMessageType::Unknown;
}

StunMessage::StunMessage(const string& server, const size_t port, const StunMessageType type)
{
  header_.type = htons(type);
  header_.length = 0;
  header_.magic = htonl(MAGIC_COOKIE);
  header_.transaction_id = generate_transaction_id();

  server_ = server;
  port_ = port;
}

TransactionId StunMessage::generate_transaction_id()
{
  TransactionId transaction_id;

  int rndfd=open("/dev/urandom", 0);
  read(rndfd, reinterpret_cast<char*>(&transaction_id[0]), sizeof(uint32_t)*transaction_id.size());
  close(rndfd);

  return transaction_id;
}

void StunMessage::add_string_attribute(StunAttributeType type, const string& value)
{
  size_t length = value.length();
  length += (value.length() % 4 == 0 ? 0 : 4 - value.length() % 4);
  vector<byte> buffer(length, byte {0});
  memcpy(buffer.data(), value.data(), value.length());

  StunAttribute attribute(type, length, buffer);
  attributes_.push_back(attribute);

  header_.length = htons(ntohs(header_.length) + sizeof(StunAttributeHeader) + length);
}

void StunMessage::add_int_attribute(StunAttributeType type, uint32_t value)
{
  vector<byte> buffer(sizeof(uint32_t), byte {0});
  uint32_t v = htonl(value);
  memcpy(buffer.data(), &v, sizeof(uint32_t));

  StunAttribute attribute(type, buffer.size(), buffer);
  attributes_.push_back(attribute);

  header_.length = htons(ntohs(header_.length) + sizeof(StunAttributeHeader) + buffer.size());
}

vector<byte> StunMessage::get_data() const
{
  auto sum_functor = [](size_t result, const StunAttribute& attribute)
  {
    return result + sizeof(StunAttributeHeader) + attribute.get_value().size();
  };
  size_t attributes_size = accumulate(begin(attributes_), end(attributes_), 0, sum_functor);

  vector<byte> data(sizeof(StunMessageHeader) + attributes_size, byte {0});
  size_t offset = 0;
  memcpy(data.data() + offset, &header_, sizeof(header_));
  offset += sizeof(header_);

  for (auto attribute : attributes_)
  {
    memcpy(data.data() + offset, &attribute.get_header(), sizeof(StunAttributeHeader));
    offset += sizeof(StunAttributeHeader);
    memcpy(data.data() + offset, attribute.get_value().data(), attribute.get_length());
    offset += attribute.get_length();
  }

  return data;
}

const TransactionId& StunMessage::get_transaction_id() const
{
  return header_.transaction_id;
}

uint32_t StunMessage::get_magic() const
{
  return ntohl(header_.magic);
}

uint16_t StunMessage::get_type() const
{
  return ntohs(header_.type);
}

uint16_t StunMessage::get_length() const
{
  return ntohs(header_.length);
}

const string& StunMessage::get_server() const
{
  return server_;
}

size_t StunMessage::get_port() const
{
  return port_;
}

void StunMessage::set_header(const StunMessageHeader& header)
{
  header_ = header;
}

void StunMessage::set_attributes(const vector<StunAttribute>& attributes)
{
  attributes_ = attributes;
}

const vector<StunAttribute>& StunMessage::get_attributes() const
{
  return attributes_;
}

const StunAttribute* StunMessage::get_attribute(StunAttributeType type) const
{
  auto find_functor = [type](const StunAttribute& attribute)
  {
    return attribute.get_type() == type;
  };
  auto found = find_if(begin(attributes_), end(attributes_), find_functor);
  if (end(attributes_) == found)
    return nullptr;

  return &(*found);
}
