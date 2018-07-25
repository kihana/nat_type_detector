#include <stdexcept>

class Exception : public std::runtime_error
{
public:
  Exception(const std::string& message) : std::runtime_error(message)
  {}
};
