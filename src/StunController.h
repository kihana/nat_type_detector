#ifndef STUN_CONTROLLER_H
#define STUN_CONTROLLER_H

#include <netdb.h>
#include <cstddef>
#include <string>
#include <vector>

#include "StunMessage.h"


class StunController
{
public:
  StunController(const StunController& controller) = delete;
  StunController& operator=(const StunController& controller) = delete;
  ~StunController();

  static StunController& instance();

  void send_message(const StunMessage& message) const;
  bool recieve_message(StunMessage& message, const TransactionId& transaction_id) const;

  bool validate_message(const StunMessage& message, const TransactionId& transaction_id) const;

private:
  StunController();

  void parse_data(const std::vector<std::byte>& data, StunMessage& message) const;
  addrinfo* get_server_address(const std::string& server, const size_t port) const;

  bool is_supported_message_type(uint16_t type) const;

private:
  int socket_;
};

#endif /* end of include guard: STUN_CONTROLLER_H */
