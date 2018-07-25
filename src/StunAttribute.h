#ifndef STUN_ATTRIBUTE_H
#define STUN_ATTRIBUTE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
#include <vector>


using TransactionId = std::array<uint32_t, 3>;

enum AddressFamily : uint16_t
{
  IPv4 = 0x01,
  IPv6 = 0x02
};

enum StunAttributeType : uint16_t
{
  // Comprehension-required attributes
  Reserved = 0x0000,
  MappedAddress = 0x0001,
  ResponseAddress = 0x0002,
  ChangeAddress = 0x0003,
  SourceAddress = 0x0004,
  ChangedAddress = 0x0005,
  Username = 0x0006,
  Password = 0x0007,
  MessageIntegrity = 0x0008,
  ErrorCode = 0x0009,
  UnknownAttributes = 0x000A,
  ReflectedFrom = 0x000B,
  Realm = 0x0014,
  Nonce = 0x0015,
  XorMappedAddress1 = 0x0020,
  XorMappedAddress2 = 0x8020,

  // Comprehension-optional attributes
  Software = 0x8022,
  AlternateServer = 0x8023,
  Fingerprint = 0x8028
};

bool is_comprehension_required_attribute(uint16_t attribute);
bool is_comprehension_optional_attribute(uint16_t attribute);
bool is_supported_required_attribute(uint16_t attribute);

struct StunAttributeHeader
{
  uint16_t type;
  uint16_t length;
};

class StunAttribute
{
public:
  StunAttribute(const StunAttributeHeader& header);
  StunAttribute(const StunAttributeHeader& header, const std::vector<std::byte>& value);
  StunAttribute(uint16_t type, uint16_t length, const std::vector<std::byte>& value);

  const StunAttributeHeader& get_header() const;
  uint16_t get_type() const;
  uint16_t get_length() const;
  const std::vector<std::byte>& get_value() const;

protected:
  StunAttributeHeader header_;
  std::vector<std::byte> value_;
};

class StunMappedAddressAdapter
{
public:
  StunMappedAddressAdapter(const StunAttribute* attribute);

  uint16_t get_family() const;
  std::string get_address() const;
  size_t get_port() const;

protected:
  const StunAttribute* attribute_;
};

class StunXorMappedAddressAdapter
{
public:
  StunXorMappedAddressAdapter(const StunAttribute* attribute);

  uint16_t get_family() const;
  std::string get_address(const TransactionId& transaction_id) const;
  size_t get_port() const;

protected:
  const StunAttribute* attribute_;
};

#endif /* end of include guard: STUN_ATTRIBUTE_H */
