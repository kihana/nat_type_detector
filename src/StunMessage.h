#ifndef STUN_MESSAGE_H
#define STUN_MESSAGE_H

#include <cstdint>
#include <cstddef>
#include <vector>

#include "StunAttribute.h"


const size_t MAGIC_COOKIE = 0x2112A442;
const size_t DEFAULT_PORT = 3478;

enum StunMessageType : uint16_t
{
  Unknown = 0x0000,
  BindingRequest = 0x0001,
  BindingSuccessResponse = 0x0101,
  BindingErrorResponse = 0x0111,
  BindingIndication = 0x0011
};

struct StunMessageHeader
{
  uint16_t type;
  uint16_t length;
  uint32_t magic;
  TransactionId transaction_id;
};

class StunMessage
{
public:
  StunMessage();
  StunMessage(const std::string& server, const size_t port, const StunMessageType type);

  std::vector<std::byte> get_data() const;
  void add_string_attribute(StunAttributeType type, const std::string& value);
  void add_int_attribute(StunAttributeType type, uint32_t value);

  const TransactionId& get_transaction_id() const;
  uint32_t get_magic() const;
  uint16_t get_type() const;
  uint16_t get_length() const;

  const std::string& get_server() const;
  size_t get_port() const;

  void set_header(const StunMessageHeader& header);

  void set_attributes(const std::vector<StunAttribute>& attributes);
  const std::vector<StunAttribute>& get_attributes() const;

  const StunAttribute* get_attribute(StunAttributeType type) const;

private:
  static TransactionId generate_transaction_id();

private:
  std::vector<StunAttribute> attributes_;
  std::string server_;
  size_t port_;
  StunMessageHeader header_;
};

#endif
