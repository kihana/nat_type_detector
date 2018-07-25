#include "StunController.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include <sstream>

#include "StunMessage.h"
#include "Exception.h"

using namespace std;

StunController::StunController()
{
  socket_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_ == -1)
    throw Exception("Failed to create socket.");

  if (-1 == fcntl(socket_, F_SETFL, O_NONBLOCK))
    throw Exception("Failed to set non-blocking mode for socket.");
}

StunController::~StunController()
{
  if (socket_ != -1)
    close(socket_);
}

StunController& StunController::instance()
{
  static StunController controller;

  return controller;
}

void StunController::send_message(const StunMessage& message) const
{
  addrinfo* address_info = get_server_address(message.get_server(), message.get_port());
  auto data = message.get_data();

  for (auto ai = address_info; nullptr != ai; ai = ai->ai_next)
  {
    if (-1 != sendto(socket_, data.data(), data.size(), 0, address_info->ai_addr, address_info->ai_addrlen))
      return;
  }

  throw Exception("Failed to send message.");
}

bool StunController::recieve_message(StunMessage& message, const TransactionId& transaction_id) const
{
  vector<byte> buffer(65535, byte {0});

  struct timeval time_out = {1, 0};
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(socket_, &readfds);

  int result = select(socket_ + 1, &readfds, nullptr, nullptr, &time_out);

  if (-1 == result)
    return false;

  if (result > 0 && FD_ISSET(socket_, &readfds))
  {
    if (-1 == recvfrom(socket_, buffer.data(), buffer.size(), 0, nullptr, nullptr))
      return false;

    parse_data(buffer, message);

    return validate_message(message, transaction_id);
  }

  return true;
}

void StunController::parse_data(const vector<byte>& data, StunMessage& message) const
{
  size_t offset = 0;
  StunMessageHeader header;
  memcpy(&header, data.data(), sizeof(StunMessageHeader));
  offset += sizeof(StunMessageHeader);

  uint16_t message_length = ntohs(header.length);

  vector<byte> buffer(message_length, byte {0});
  memcpy(buffer.data(), data.data() + offset, buffer.size());

  size_t buffer_offset = 0;
  vector<StunAttribute> attributes;

  while (buffer_offset < buffer.size() - 1)
  {
    StunAttributeHeader attribute_header;
    memcpy(&attribute_header, buffer.data() + buffer_offset, sizeof(StunAttributeHeader));
    buffer_offset += sizeof(StunAttributeHeader);

    uint16_t attribute_length = ntohs(attribute_header.length);

    if (attribute_length <= 0)
      continue;

    vector<byte> attribute_value(attribute_length, byte {0});
    memcpy(attribute_value.data(), buffer.data() + buffer_offset, attribute_value.size());
    buffer_offset += attribute_value.size();

    attributes.emplace_back(attribute_header, attribute_value);
  }

  message.set_header(header);
  message.set_attributes(attributes);
}

bool StunController::validate_message(const StunMessage& message, const TransactionId& transaction_id) const
{
  if (!is_supported_message_type(message.get_type()))
    throw Exception("Failed to validate message: message type is not supported.");

  if (message.get_magic() != MAGIC_COOKIE)
    throw Exception("Failed to validate message: magic cookei is not valid.");

  if (message.get_length() <= 0)
    throw Exception("Failed to validate message: message length is not valid.");

  if ((StunMessageType::BindingSuccessResponse == message.get_type() ||
        StunMessageType::BindingIndication == message.get_type()) &&
      message.get_transaction_id() != transaction_id)
    throw Exception("Failed to validate message: transaction ID is not valid.");

  if (StunMessageType::BindingSuccessResponse == message.get_type())
  {
    if (nullptr == message.get_attribute(StunAttributeType::XorMappedAddress1) &&
        nullptr == message.get_attribute(StunAttributeType::XorMappedAddress2) &&
        nullptr == message.get_attribute(StunAttributeType::MappedAddress))
      throw Exception("Failed to validate message: (xor) mapped address attributes don't exist.");
  }
  else if (StunMessageType::BindingErrorResponse == message.get_type())
  {
    if (nullptr == message.get_attribute(StunAttributeType::ErrorCode))
      throw Exception("Failed to validate message: error code attribute doesn't exist.");
  }

  auto& attributes = message.get_attributes();
  for (auto attribute : attributes)
  {
    if ((StunMessageType::BindingErrorResponse == message.get_type() ||
          StunMessageType::BindingSuccessResponse == message.get_type()) &&
        is_comprehension_required_attribute(attribute.get_type()))
    {
      if (!is_supported_required_attribute(attribute.get_type()))
        throw Exception("Failed to validate message: unknown comprehension-required attribute.");
      // handler should be added and in case 500 - 599 return false else throw exception
    }
  }

  return true;
}

bool StunController::is_supported_message_type(uint16_t type) const
{
  return StunMessageType::BindingSuccessResponse == type ||
    StunMessageType::BindingErrorResponse == type;
}

addrinfo* StunController::get_server_address(const string& server, const size_t port) const
{
  struct addrinfo hints;
  struct addrinfo* result;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  auto ret = getaddrinfo(server.c_str(), to_string(port).c_str(), &hints, &result);
  if (0 != ret)
  {
    stringstream stream;
    stream << "Failed to get information about " << server << " server. Error: " << gai_strerror(ret);
    throw Exception(stream.str());
  }

  return result;
}
