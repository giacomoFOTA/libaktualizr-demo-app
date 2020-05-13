#include "custom-secondary.h"

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>

#include "crypto/crypto.h"
#include "utilities/fault_injection.h"
#include "utilities/utils.h"


bool custom_install(const std::string & data) {
  std::cout << "Data length: " << data.length() << std::endl;
  std::cout << "Data hash: " << boost::algorithm::hex(Crypto::sha256digest(data)) << std::endl;
  return true;
}

bool CustomSecondary::sendFirmware(const std::string& data) {
  if (custom_install(data)) {
    Utils::writeFile(sconfig.target_name_path, expected_target_name);
    Utils::writeFile(sconfig.target_size_path, expected_target_length);
    Utils::writeFile(sconfig.target_hash_path, boost::algorithm::to_lower_copy(expected_target_hashes[0].HashString()));
    return true;
  } else {
    return false;
  }
}

bool CustomSecondary::getFirmwareInfo(Uptane::InstalledImageInfo& firmware_info) const {
  std::string content;

  if (!boost::filesystem::exists(sconfig.target_name_path)) {
    firmware_info.name = std::string("noimage");
  } else {
    firmware_info.name = Utils::readFile(sconfig.target_name_path.string());
  }
  if (!boost::filesystem::exists(sconfig.target_hash_path)) {
    firmware_info.hash = std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  } else {
    firmware_info.hash = Utils::readFile(sconfig.target_hash_path.string());
  }
  if (!boost::filesystem::exists(sconfig.target_size_path)) {
    firmware_info.len = 0;
  } else {
    firmware_info.len = std::stoi(Utils::readFile(sconfig.target_size_path.string()));
  }

  return true;
}

