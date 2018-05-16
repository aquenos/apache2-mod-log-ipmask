/**
 * Copyright 2018 aquenos GmbH.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// Minimal optional implementation, similar to, but not as sophisticated as the
// one from C++ 17.
template <typename T>
class Optional {

public:

  Optional() : has_value(false) {
  }

  Optional(T const &value) : has_value(true), val(value) {
  }

  Optional(T &&value) : has_value(true), val(value) {
  }

  T &operator*() {
    return val;
  }

  T const &operator*() const {
    return val;
  }

  T *operator->() {
    return &val;
  }

  T const *operator->() const {
    return &val;
  }

  operator bool() const {
    return has_value;
  }

  T &value() {
    check_has_value();
    return val;
  }

  T const &value() const {
    check_has_value();
    return val;
  }

  T const &value_or(T const &default_value) const {
    if (has_value) {
      return val;
    } else {
      return default_value;
    }
  }

private:

  bool has_value;
  T val;

  inline void check_has_value() {
    if (!has_value) {
      throw std::runtime_error("Attempt to dereference an empty optional.");
    }
  }

};

class Parser {

protected:

  std::string const input;
  std::size_t position;

  Parser(std::string const &input) : input(input), position(0) {
  }

  bool accept(char c) {
    if (is_end_of_string() || input[position] != c) {
      return false;
    } else {
      ++position;
      return true;
    }
  }

  Optional<char> accept_any_of(std::string const &chars) {
    if (is_end_of_string()
        || chars.find(input[position]) == std::string::npos) {
      return Optional<char>();
    } else {
      char c = input[position];
      ++position;
      return Optional<char>(c);
    }
  }

  void expect(char c) {
    if (!accept(c)) {
      throw std::invalid_argument("Did not find expected character.");
    }
  }

  char expect_any_of(std::string const &chars) {
    auto result = accept_any_of(chars);
    if (!result) {
      throw std::invalid_argument("Did not find expected character.");
    }
    return *result;
  }

  bool is_end_of_string() {
    return position == input.length();
  }

};

struct Format_Options {
  bool use_peer_ip = false;
  Optional<int> masked_bits_ipv4;
  Optional<int> masked_bits_ipv6;
};

class Format_Options_Parser : Parser {

public:

  static Format_Options parse(std::string const &input,
      bool allow_use_peer_ip) {
    auto parser = Format_Options_Parser(input, allow_use_peer_ip);
    parser.parse();
    return parser.result;
  }

private:

  bool allow_use_peer_ip;
  Format_Options result;

  Format_Options_Parser(std::string const &input, bool allow_use_peer_ip)
      : Parser(input), allow_use_peer_ip(allow_use_peer_ip) {
  }

  bool accept_use_peer_ip_flag() {
    return accept('c');
  }

  void parse() {
    if (accept_use_peer_ip_flag()) {
      result.use_peer_ip = true;
      if (!is_end_of_string()) {
        expect('|');
      };
    }
    if (is_end_of_string()) {
      return;
    }
    std::string buffer;
    buffer.push_back(expect_any_of("0123456789"));
    auto optional_char = accept_any_of("0123456789");
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    result.masked_bits_ipv4 = std::stoi(buffer);
    if (*result.masked_bits_ipv4 > 32) {
      throw std::invalid_argument("IPv4 address only has 32 bits.");
    }
    buffer.erase();
    expect('|');
    buffer.push_back(expect_any_of("0123456789"));
    optional_char = accept_any_of("0123456789");
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    optional_char = accept_any_of("0123456789");
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    result.masked_bits_ipv6 = std::stoi(buffer);
    if (*result.masked_bits_ipv6 > 128) {
      throw std::invalid_argument("IPv4 address only has 128 bits.");
    }
    if (!is_end_of_string()) {
      throw std::invalid_argument("Unexpected characters at end of string");
    }
  }

};

class IPv4_Address_Parser : Parser {

public:

  static std::array<std::uint8_t, 4> parse(std::string const &input) {
    auto parser = IPv4_Address_Parser(input);
    parser.parse();
    return parser.result;
  }

private:

  std::array<std::uint8_t, 4> result;

  IPv4_Address_Parser(std::string const &input) : Parser(input) {
  }

  Optional<char> accept_digit() {
    return accept_any_of("0123456789");
  }

  char expect_digit() {
    return expect_any_of("0123456789");
  }

  uint8_t expect_octet() {
    std::string buffer;
    buffer.push_back(expect_digit());
    auto optional_char = accept_digit();
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    optional_char = accept_digit();
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    int result = std::stoi(buffer);
    if (result > 255) {
      throw std::invalid_argument("Octet value must be less than 256.");
    }
    return result;
  }

  void parse() {
    result[0] = expect_octet();
    expect('.');
    result[1] = expect_octet();
    expect('.');
    result[2] = expect_octet();
    expect('.');
    result[3] = expect_octet();
    if (!is_end_of_string()) {
      throw std::invalid_argument("Unexpected characters at end of address");
    }
  }

};

class IPv6_Address_Parser : Parser {

public:

  static std::array<std::uint8_t, 16> parse(std::string const &input) {
    auto parser = IPv6_Address_Parser(input);
    parser.parse();
    return parser.result;
  }

private:

  std::array<std::uint8_t, 16> result;

  IPv6_Address_Parser(std::string const &input) : Parser(input) {
  }

  Optional<char> accept_hex_digit() {
    return accept_any_of("0123456789ABCDEFabcdef");
  }

  char expect_hex_digit() {
    return expect_any_of("0123456789ABCDEFabcdef");
  }

  Optional<std::uint16_t> accept_hextet() {
    std::string buffer;
    auto optional_char = accept_hex_digit();
    if (!optional_char) {
      return Optional<std::uint16_t>();
    }
    buffer.push_back(*optional_char);
    optional_char = accept_hex_digit();
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    optional_char = accept_hex_digit();
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    optional_char = accept_hex_digit();
    if (optional_char) {
      buffer.push_back(*optional_char);
    }
    return Optional<std::uint16_t>(std::stoi(buffer, 0, 16));
  }

  std::uint16_t expect_hextet() {
    auto result = accept_hextet();
    if (!result) {
      throw std::invalid_argument("Could not find expected hextet.");
    }
    return *result;
  }

  void parse() {
    // The IPv6 address is represented by 8 hextets, each storing two bytes.
    // The hextets are separated by colons (::)
    // Leading zeros in each hextet may be ommitted and one sequence of all zero
    // hextets may be abbreviated by the double colon (::).
    std::vector<std::uint16_t> hextets_at_start;
    std::vector<std::uint16_t> hextets_at_end;
    bool found_double_colon = false;
    // An address may only start with a colon it is actually a double colon, so
    // we can simply skip the start part if the first character is a colon.
    // Otherwise, we expect a hextet.
    if (accept(':')) {
      expect(':');
      found_double_colon = true;
    } else {
      hextets_at_start.push_back(expect_hextet());
      while (hextets_at_start.size() < 8) {
        // Remove the colon after the last hextet.
        expect(':');
        // If we find another colon, it means there is a double colon.
        if (accept(':')) {
          found_double_colon = true;
          break;
        } else {
          hextets_at_start.push_back(expect_hextet());
        }
      }
    }
    // When we get here, we already read 8 hextets or we found a double colon.
    // In the second case, we want to read the remaining hextets (if there
    // are any).
    if (found_double_colon && !is_end_of_string()) {
      // If there is a double colon, at least one hextet must have been
      // ommitted, so we expect less than 8 hextets in total.
      auto remaining_hextets = 7 - hextets_at_start.size();
      while (remaining_hextets != 0) {
        // There must be at least one additional hextet.
        hextets_at_end.push_back(expect_hextet());
        --remaining_hextets;
        if (is_end_of_string()) {
          break;
        } else {
          expect(':');
          if (is_end_of_string()) {
            // There must be no colon after the last hextet.
            throw std::invalid_argument("Found colon after the last hextet");
          }
        }
      }
    }
    // Now, we should have read all characters.
    if (!is_end_of_string()) {
      throw std::invalid_argument("Unexpected characters at end of address");
    }
    int number_of_hextets_at_start = hextets_at_start.size();
    int number_of_missing_hextets = 8 - number_of_hextets_at_start
        - hextets_at_end.size();
    int hextets_at_end_offset = number_of_hextets_at_start
        + number_of_missing_hextets;
    for (int i = 0; i < 8; ++i) {
      std::uint16_t hextet;
      if (i < number_of_hextets_at_start) {
        hextet = hextets_at_start[i];
      } else if (i < hextets_at_end_offset) {
        hextet = 0;
      } else {
        hextet = hextets_at_end[i - hextets_at_end_offset];
      }
      result[i * 2] = hextet >> 8;
      result[i * 2 + 1] = hextet & 0xff;
    }
  }

};

template <int _number_of_octets, typename Parser, typename Printer>
struct IP_Address {
  using octets_type = std::array<std::uint8_t, _number_of_octets>;

  static constexpr int number_of_octets = _number_of_octets;
  octets_type octets;

  IP_Address() {
    this->octets.fill(0);
  }

  IP_Address(std::string const &str) : octets(Parser::parse(str)) {
  }

  IP_Address(octets_type const &octets) : octets(octets) {
  }

  IP_Address(octets_type &&octets) : octets(octets) {
  }

  void mask(int masked_bits) {
    for (int i = 0; i < number_of_octets; ++i) {
      if (masked_bits >= 8) {
        masked_bits -= 8;
      } else if (masked_bits > 0) {
        int unmasked_bits = 8 - masked_bits;
        uint8_t octet = this->octets[i];
        octet >>= unmasked_bits;
        octet <<= unmasked_bits;
        this->octets[i] = octet;
        masked_bits = 0;
      } else {
        this->octets[i] = 0;
      }
    }
  }

  std::string str() {
    return Printer::print(this->octets);
  }

};

class IPv4_Address_Printer {

public:

  static std::string print(std::array<std::uint8_t, 4> octets) {
    IPv4_Address_Printer printer(octets);
    return printer.os.str();
  }


private:

  std::ostringstream os;

  IPv4_Address_Printer(std::array<std::uint8_t, 4> octets) {
    print_octet(octets[0]);
    os << '.';
    print_octet(octets[1]);
    os << '.';
    print_octet(octets[2]);
    os << '.';
    print_octet(octets[3]);
  }

  void print_octet(std::uint8_t octet) {
    os << static_cast<int>(octet);
  }

};

class IPv6_Address_Printer {

public:

  static std::string print(std::array<std::uint8_t, 16> octets) {
    IPv6_Address_Printer printer(octets);
    return printer.os.str();
  }


private:

  std::ostringstream os;

  IPv6_Address_Printer(std::array<std::uint8_t, 16> octets) {
    // First, we convert to hextets. This makes everything else easier.
    std::array<uint16_t, 8> hextets;
    for (int i = 0; i < 8; ++i) {
      hextets[i] = (octets[2 * i] << 8) + octets[2 * i + 1];
    }
    // We want to find the longest consecutive sequence of empty (zero) hextets.
    // If there are several sequences of the same length, we use the left-most.
    auto zero_seq_end = hextets.begin();
    auto longest_zero_seq_start = hextets.end();
    auto longest_zero_seq_end = hextets.end();
    auto longest_zero_seq_length = longest_zero_seq_end - longest_zero_seq_start;
    do {
      auto zero_seq_start = std::find(zero_seq_end, hextets.end(), 0);
      zero_seq_end = zero_seq_start;
      if (zero_seq_start != hextets.end()) {
        zero_seq_end = std::find_if(zero_seq_start, hextets.end(),
            [](std::uint8_t o){return o != 0;});
        auto zero_seq_length = zero_seq_end - zero_seq_start;
        if (zero_seq_length > longest_zero_seq_length) {
          longest_zero_seq_start = zero_seq_start;
          longest_zero_seq_end = zero_seq_end;
          longest_zero_seq_length = zero_seq_length;
        }
      }

    } while (zero_seq_end != hextets.end());
    // We only print hex numbers, so we change the format flag.
    os.setf(std::ios::hex, std::ios::basefield);
    // According to conventions, a single zero hextet is not shortened using a
    // double colon, so if the longest sequence is shorter than two hextets, we
    // simply print all hextets. Otherwise, we split the printing into the part
    // before the double colon and the part after.
    if (longest_zero_seq_length < 2) {
      os << hextets[0];
      for (int i = 1; i < 8; ++i) {
        os << ':';
        os << hextets[i];
      }
    } else {
      // We print the part before the zero sequence. Note that we print the
      // colon after each element. This means that we will also print the first
      // colon of the double colon.
      for (auto i = hextets.begin(); i != longest_zero_seq_start; ++i) {
        os << *i;
        os << ':';
      }
      // If we did not print a single hextet (because the zero sequence starts
      // right at the beginning), we have to print a colon.
      if (longest_zero_seq_start == hextets.begin()) {
        os << ':';
      }
      // We print the part after the zero sequence. Note that we print the
      // colon before each element. This means that we will also print the
      // second colon of the double colon.
      for (auto i = longest_zero_seq_end; i != hextets.end(); ++i) {
        os << ':';
        os << *i;
      }
      // If we did not print a single hextet (because the zero sequence reaches
      // right to the end), we have to print a colon.
      if (longest_zero_seq_end == hextets.end()) {
        os << ':';
      }
    }
  }

};

using IPv4_Address = IP_Address<4, IPv4_Address_Parser, IPv4_Address_Printer>;
using IPv6_Address = IP_Address<16, IPv6_Address_Parser, IPv6_Address_Printer>;

} // anonymous namespace

extern "C" {


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"

#include "apr_strings.h"

#include "mod_log_config.h"


struct log_ipmask_config {
  Optional<int> masked_bits_ipv4;
  Optional<int> masked_bits_ipv6;
};

// We only declare the get-config function here because its implementation
// depends on the module declaration.
static log_ipmask_config *get_log_ipmask_config(ap_conf_vector_t *configs);

char const* mask_ip_address(char const *address_cstr, log_ipmask_config *config,
    Format_Options format_options, apr_pool_t *pool) {
  // If no mask has been defined, we use the full address by default. This means
  // that only loading this module will not have any effect, without also using
  // the respective configuration directives or specifying the special format.
  int masked_bits_ipv4 = format_options.masked_bits_ipv4.value_or(
      config->masked_bits_ipv4.value_or(32));
  int masked_bits_ipv6 = format_options.masked_bits_ipv6.value_or(
      config->masked_bits_ipv6.value_or(128));
  std::string address_str(address_cstr);
  std::string masked_address_str;
  try {
    IPv4_Address address(address_str);
    address.mask(masked_bits_ipv4);
    masked_address_str = address.str();
  } catch (...) {
    // If the address is not an IPv4 address, it might still be an IPv6 address.
    try {
      IPv6_Address address(address_str);
      address.mask(masked_bits_ipv6);
      masked_address_str = address.str();
    } catch (...) {
      // If the address is not an IPv6 address either, we cannot mask it and
      // return the string as-is.
      return address_cstr;
    }
  }
  // The C string returned by the C++ string is only valid as long as the string
  // object exists, so we have to duplicate it using the memory pool before
  // returning it.
  return apr_pstrdup(pool, masked_address_str.c_str());
}

static char const *log_remote_address(request_rec *request,
    char *option_str) {
  log_ipmask_config *config = get_log_ipmask_config(
      request->server->module_config);
  Format_Options format_options;
  try {
    format_options = Format_Options_Parser::parse(option_str, true);
  } catch (...) {
    // Ignore any exceptions that occur while parsing the format options and
    // simply continue with the default options.
  }
  char const *orig_ip_addr_str;
  if (format_options.use_peer_ip) {
    orig_ip_addr_str = request->connection->client_ip;
  } else {
    orig_ip_addr_str = request->useragent_ip;
  }
  return mask_ip_address(orig_ip_addr_str, config, format_options,
      request->pool);
}

static char const *log_remote_host(request_rec *request, char *option_str) {
  log_ipmask_config *config = get_log_ipmask_config(
      request->server->module_config);
  Format_Options format_options;
  try {
    format_options = Format_Options_Parser::parse(option_str, false);
  } catch (...) {
    // Ignore any exceptions that occur while parsing the format options and
    // simply continue with the default options.
  }
  char const *orig_ip_addr_str = ap_get_remote_host(request->connection,
      request->per_dir_config, REMOTE_NAME, NULL);
  char const *masked_ip_addr_str = mask_ip_address(orig_ip_addr_str, config,
      format_options, request->pool);
  // If the remote host is a name instead of an address, we could not mask it
  // and we have to escape it because it may contain characters that need to be
  // escaped.
  if (masked_ip_addr_str == orig_ip_addr_str) {
    return ap_escape_logitem(request->pool, orig_ip_addr_str);
  } else {
    return masked_ip_addr_str;
  }
}

static void *create_log_ipmask_config(apr_pool_t *pool, server_rec *server) {
  log_ipmask_config *config =
      new(apr_palloc(pool, sizeof(log_ipmask_config))) log_ipmask_config();
  return config;
}

static void *merge_log_ipmask_config(apr_pool_t *pool, void *base_void,
    void *add_void) {
  log_ipmask_config *base = reinterpret_cast<log_ipmask_config *>(base_void);
  log_ipmask_config *add = reinterpret_cast<log_ipmask_config *>(add_void);

  // Merge the configurations.
  if (!add->masked_bits_ipv4) {
    add->masked_bits_ipv4 = base->masked_bits_ipv4;
  }
  if (!add->masked_bits_ipv6) {
    add->masked_bits_ipv6 = base->masked_bits_ipv6;
  }

  return add;
}

// This function is called early (before most of the configuration processing
// happens). However, it is called after the mod_log_config module has run its
// initialization code, so we can overwrite the log handlers registered by that
// module.
static int log_ipmask_pre_config(apr_pool_t *config_pool, apr_pool_t *log_pool,
    apr_pool_t *temp_pool) {
  // The parameters to the ap_register_log_handler function are:
  // - Memory pool used by the function.
  // - Identifier that is used in the format string.
  // - Function that shall be invoked for this format identifier.
  // - The default value for the want-original flag. The want-original flag is
  //   set by specifying < or > in front of the format identifier in the format
  //   string. The value passed to the function is 0 to use the final request by
  //   default (the same as specifying >) or 1 to use the original request by
  //   default (the same as specifying <).
  auto register_log_handler = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);
  if (register_log_handler) {
    // We create char arrays instead of passing a string constant. The
    // ap_register_log_handler expects a char * instead of a char const *, so
    // passing a string constant results in a compiler warning.
    char tag_remote_address[] = {'a', 0};
    char tag_remote_host[] = {'h', 0};
    register_log_handler(config_pool, tag_remote_address, log_remote_address,
        0);
    register_log_handler(config_pool, tag_remote_host, log_remote_host, 0);
  }
  return OK;
}

static char const *set_default_ipv4_mask(cmd_parms *cmd, void *dummy,
    char const *arg) {
  log_ipmask_config *config = get_log_ipmask_config(cmd->server->module_config);
  // We first validate the string. std::stoi would only report an error if it
  // cannot convert the string, not if it contained extra characters.
  for (auto p = arg; *p; p++) {
    if (!isdigit(*p)) return "Argument to LogDefaultIPv4Mask must be a number between zero and 32.";
  }
  int mask_bits = std::atoi(arg);
  if (mask_bits > 32) {
    return "Argument to LogDefaultIPv4Mask must be a number between zero and 32.";
  }
  config->masked_bits_ipv4 = mask_bits;
  return nullptr;
}

static char const *set_default_ipv6_mask(cmd_parms *cmd, void *dummy,
    char const *arg) {
  log_ipmask_config *config = get_log_ipmask_config(cmd->server->module_config);
  // We first validate the string. std::stoi would only report an error if it
  // cannot convert the string, not if it contained extra characters.
  for (auto p = arg; *p; p++) {
    if (!isdigit(*p)) return "Argument to LogDefaultIPv6Mask must be a number between zero and 128.";
  }
  int mask_bits = std::atoi(arg);
  if (mask_bits > 128) {
    return "Argument to LogDefaultIPv6Mask must be a number between zero and 128.";
  }
  config->masked_bits_ipv6 = mask_bits;
  return nullptr;
}

// Data structure storing the supported configuration commands. C++ is more
// strict about casting function pointers than C, so we need a reinterpret_cast.
static const command_rec log_ipmask_config_commands[] = {
    AP_INIT_TAKE1("LogDefaultIPv4Mask",
        reinterpret_cast<cmd_func>(set_default_ipv4_mask), nullptr, RSRC_CONF,
        "bits of the IPv4 address that shall be included in the log"),
    AP_INIT_TAKE1("LogDefaultIPv6Mask",
        reinterpret_cast<cmd_func>(set_default_ipv6_mask), nullptr, RSRC_CONF,
        "bits of the IPv6 address that shall be included in the log"),
    {nullptr}
};

static void log_ipmask_register_hooks(apr_pool_t *p) {
  // The ap_hook_pre_config function takes the predecessor's source file name, not
  // the module name.
  static const char * predecessors[] = { "mod_log_config.c", nullptr };
  ap_hook_pre_config(log_ipmask_pre_config, predecessors, nullptr,
      APR_HOOK_MIDDLE);
}

// Dispatch list for API hooks
module AP_MODULE_DECLARE_DATA log_ipmask_module = {
  STANDARD20_MODULE_STUFF,
  nullptr,                    // create per-dir    config structures
  nullptr,                    // merge  per-dir    config structures
  create_log_ipmask_config,   // create per-server config structures
  merge_log_ipmask_config,    // merge  per-server config structures
  log_ipmask_config_commands, // table of config file commands
  log_ipmask_register_hooks   // register hooks
};

// This function depends on the module declaration, so we have to place it after
// the declaration.
static log_ipmask_config *get_log_ipmask_config(ap_conf_vector_t *configs) {
  log_ipmask_config *config = reinterpret_cast<log_ipmask_config *>(
      ap_get_module_config(configs, &log_ipmask_module));
}

} // extern "C"
