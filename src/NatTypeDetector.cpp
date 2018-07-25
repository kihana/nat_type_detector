#include "NatTypeDetector.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include <thread>
#include <sstream>

#include "Exception.h"
#include "StunController.h"
#include "StunMessage.h"


using namespace std;


StunMessage NatTypeDetector::make_request(const StunMessage& request) const
{
  int rto = rto_;
  StunController& stun_controller = StunController::instance();
  StunMessage response;

  for (size_t i = 0; i < attempts_number_; ++i)
  {
    stun_controller.send_message(request);
    if (stun_controller.recieve_message(response, request.get_transaction_id()))
      break;

    this_thread::sleep_for(chrono::milliseconds(rto));
    rto *= 2;
  }

  return response;
}

bool NatTypeDetector::test_1(const string& server)
{
  StunMessage request(server, DEFAULT_PORT, StunMessageType::BindingRequest);
  request.add_string_attribute(StunAttributeType::Software, "HELLo");

  StunMessage response = make_request(request);
  if (StunMessageType::Unknown == response.get_type())
  {
    stringstream stream;
    stream << "UDP is blocked or check access to " << server << " server";
    throw Exception(stream.str());
  }

  auto attribute = response.get_attribute(StunAttributeType::XorMappedAddress1);
  if (nullptr == attribute)
    attribute = response.get_attribute(StunAttributeType::XorMappedAddress2);

  if (nullptr != attribute)
  {
    StunXorMappedAddressAdapter mapped_ip_address(attribute);
    ip_address_from_test1_ = mapped_ip_address.get_address(response.get_transaction_id());
    is_nat_present_ = !is_public_address(ip_address_from_test1_);
  }
  else
  {
    auto attribute = response.get_attribute(StunAttributeType::MappedAddress);
    if (nullptr != attribute)
    {
      StunMappedAddressAdapter mapped_ip_address(attribute);
      ip_address_from_test1_ = mapped_ip_address.get_address();
      is_nat_present_ = !is_public_address(ip_address_from_test1_);
    }
  }

  return true;
}

bool NatTypeDetector::test_2(const string& server)
{
  StunMessage request(server, DEFAULT_PORT, StunMessageType::BindingRequest);
  request.add_int_attribute(StunAttributeType::ChangeAddress, 6);

  StunMessage response = make_request(request);
  if (StunMessageType::Unknown == response.get_type())
    return false;

  return true;
}

bool NatTypeDetector::test_3(const string& server)
{
  StunMessage request(server, DEFAULT_PORT, StunMessageType::BindingRequest);
  request.add_int_attribute(StunAttributeType::ChangeAddress, 2);

  StunMessage response = make_request(request);
  if (StunMessageType::Unknown == response.get_type())
    return false;

  return true;
}

bool NatTypeDetector::is_public_address(const string& address) const
{
  int s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

  struct sockaddr_in ip_address;
  if (1 != inet_pton(AF_INET, address.c_str(), &ip_address.sin_addr))
  {
    cerr << "Failed to create sockaddr_in structure from IP address: " << address << endl;

    return false;
  }

  struct sockaddr_in local_address;
  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons(0);
  local_address.sin_addr.s_addr = ip_address.sin_addr.s_addr;

  bool is_public_address = false;
  if (bind(s, (struct sockaddr *) &local_address, sizeof(local_address)) == 0)
    is_public_address = true;

  close(s);

  return is_public_address;
}

void NatTypeDetector::execute(const string& server1, const string& server2)
{
  if (!test_1(server1))
    return;

  if (is_nat_present_)
  {
    if (!test_2(server1))
    {
      string previous_public_ip_address = ip_address_from_test1_;
      if (test_1(server2))
      {
        if (previous_public_ip_address == ip_address_from_test1_)
        {
          if (test_3(server1))
            nat_type_ = "Address-restricted-cone NAT";
          else
            nat_type_ = "Port-restricted-cone NAT";
        }
        else
          nat_type_ = "Symmetric NAT";
      }
      else
        cout << "Failed to run test 1 for server 2" << endl;
    }
    else
      nat_type_ = "Full-cone NAT";
  }
  else
    is_firewall_present_ = !test_2(server1);
}

void NatTypeDetector::print_result() const
{
  cout << "NAT detected: " << (is_nat_present_ ? "YES" : "NO") << endl;
  if (is_nat_present_)
    cout << "NAT type: " << nat_type_ << endl;
  else
    cout << (is_firewall_present_ ? "Symmetric Firewall" : "Open Internet") << endl;

  cout << "Public IP: " << ip_address_from_test1_ << endl;
}
