#ifndef NAT_TYPE_DETECTOR_H
#define NAT_TYPE_DETECTOR_H

#include <cstddef>
#include <string>


class StunMessage;


class NatTypeDetector
{
public:
  void execute(const std::string& server1, const std::string& server2);
  void print_result() const;

private:
  bool test_1(const std::string& server);
  bool test_2(const std::string& server);
  bool test_3(const std::string& server);

  StunMessage make_request(const StunMessage& message) const;

  bool is_public_address(const std::string& address) const;

private:
  static const size_t attempts_number_ = 7;
  static const size_t rto_ = 500;

  bool is_nat_present_ = false;
  bool is_firewall_present_ = false;
  std::string nat_type_;
  std::string ip_address_from_test1_;
};

#endif
