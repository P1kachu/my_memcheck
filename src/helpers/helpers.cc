#include "helpers.hh"

bool binary_exists(const std::string& name)
{
  return (access(name.c_str(), F_OK) != -1);
}
