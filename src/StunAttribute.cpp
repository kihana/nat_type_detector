#include "StunAttribute.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

#include "StunMessage.h"


using namespace std;


/***************************** Helper functions *******************************/

bool is_comprehension_required_attribute(uint16_t attribute)
{
  return attribute >= 0x0000 && attribute <= 0x7FFF;
}

bool is_comprehension_optional_attribute(uint16_t attribute)
{
  return attribute >= 0x8000 && attribute <= 0xFFFF;
}

bool is_supported_required_attribute(uint16_t attribute)
{
  if (attribute >= StunAttributeType::Reserved && attribute <= StunAttributeType::ReflectedFrom)
    return true;
  else if (StunAttributeType::Realm == attribute || StunAttributeType::Nonce == attribute)
    return true;
  else if (StunAttributeType::XorMappedAddress1 == attribute || StunAttributeType::XorMappedAddress2 == attribute)
    return true;

  return false;
}


/****************************** StunAttribute *********************************/

StunAttribute::StunAttribute(const StunAttributeHeader& header)
{
  header_ = header;
}

StunAttribute::StunAttribute(const StunAttributeHeader& header, const std::vector<std::byte>& value)
{
  header_ = header;
  value_ = value;
}

StunAttribute::StunAttribute(uint16_t type, uint16_t length, const std::vector<std::byte>& value)
{
  header_.type = htons(type);
  header_.length = htons(length);
  value_ = value;
}

const StunAttributeHeader& StunAttribute::get_header() const
{
  return header_;
}

uint16_t StunAttribute::get_type() const
{
  return ntohs(header_.type);
}

uint16_t StunAttribute::get_length() const
{
  return ntohs(header_.length);
}

const vector<byte>& StunAttribute::get_value() const
{
  return value_;
}


/*********************** StunXorMappedAddressAttribute ************************/

StunXorMappedAddressAdapter::StunXorMappedAddressAdapter(const StunAttribute* attribute)
{
  attribute_ = attribute;
}

uint16_t StunXorMappedAddressAdapter::get_family() const
{
  uint16_t family;
  memcpy(&family, attribute_->get_value().data(), sizeof(family));
  family = ntohs(family);

  return family;
}

string StunXorMappedAddressAdapter::get_address(const TransactionId& transaction_id) const
{
  uint16_t family = get_family();

  string address;
  if (AddressFamily::IPv4 == family)
  {
    uint32_t uint_address;
    memcpy(&uint_address, attribute_->get_value().data() + 2 * sizeof(uint16_t), sizeof(uint_address));
    uint_address = htonl(ntohl(uint_address)^MAGIC_COOKIE);

    struct in_addr ip_address;
    ip_address.s_addr = uint_address;

    char ip[INET_ADDRSTRLEN];
    address= inet_ntop(AF_INET, &ip_address, ip, INET_ADDRSTRLEN);
  }
  else if (AddressFamily::IPv6 == family)
  {
    array<uint32_t, 4> magic = { MAGIC_COOKIE, transaction_id[0], transaction_id[1], transaction_id[2] };

    array<uint32_t, 4> uint_address;
    memcpy(uint_address.data(), attribute_->get_value().data() + 2 * sizeof(uint16_t), sizeof(uint32_t) * uint_address.size());

    for (size_t i = 0; i < uint_address.size(); ++i)
      uint_address[i] = htonl(ntohl(uint_address[i])^magic[i]);

    struct in6_addr ip_address;
    memcpy(&ip_address.s6_addr, uint_address.data(), sizeof(uint32_t) * uint_address.size());

    char ip[INET6_ADDRSTRLEN];
    address = inet_ntop(AF_INET6, &ip_address, ip, INET6_ADDRSTRLEN);
  }
  else
    address = "IP address family is not supported";

  return address;
}

#include <iostream>

size_t StunXorMappedAddressAdapter::get_port() const
{
  uint16_t port;
  memcpy(&port, attribute_->get_value().data() + sizeof(uint16_t), sizeof(port));
  port = (ntohs(port)^(MAGIC_COOKIE >> 16));

  return port;
}

/*********************** StunMappedAddressAdapter ************************/

StunMappedAddressAdapter::StunMappedAddressAdapter(const StunAttribute* attribute)
{
  attribute_ = attribute;
}

uint16_t StunMappedAddressAdapter::get_family() const
{
  uint16_t family;
  memcpy(&family, attribute_->get_value().data(), sizeof(family));
  family = ntohs(family);

  return family;
}

string StunMappedAddressAdapter::get_address() const
{
  uint16_t family = get_family();

  string address;
  if (AddressFamily::IPv4 == family)
  {
    struct in_addr ip_address;
    char ip[INET_ADDRSTRLEN];
    memcpy(&ip_address.s_addr, attribute_->get_value().data() + 2 * sizeof(uint16_t), sizeof(ip_address.s_addr));

    address= inet_ntop(AF_INET, &ip_address, ip, INET_ADDRSTRLEN);
  }
  else if (AddressFamily::IPv6 == family)
  {
    struct in6_addr ip_address;
    char ip[INET6_ADDRSTRLEN];
    memcpy(&ip_address.s6_addr, attribute_->get_value().data() + 2 * sizeof(uint16_t), sizeof(ip_address.s6_addr));

    address = inet_ntop(AF_INET6, &ip_address, ip, INET6_ADDRSTRLEN);
  }
  else
    address = "IP address family is not supported";

  return address;
}

size_t StunMappedAddressAdapter::get_port() const
{
  uint16_t port;
  memcpy(&port, attribute_->get_value().data() + sizeof(uint16_t), sizeof(port));
  port = ntohs(port);

  return port;
}
