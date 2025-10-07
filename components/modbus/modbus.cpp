#include "modbus.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"
#include "esphome/core/application.h"

namespace esphome {
namespace modbus {

static const char *const TAG = "modbus";

void Modbus::setup() {
  if (this->current_role_ == ModbusRole::SNIFFER)
    this->current_role_ = ModbusRole::SERVER;
  else
    this->current_role_ = this->role;
  if (this->flow_control_pin_ != nullptr) {
    this->flow_control_pin_->setup();
  }
}

void Modbus::loop() {
  const uint32_t now = App.get_loop_component_start_time();

  while (this->available()) {
    uint8_t byte;
    this->read_byte(&byte);
    if (this->parse_modbus_byte_(byte)) {
      this->last_modbus_byte_ = now;
    } else {
      size_t at = this->rx_buffer_.size();
      if (at > 0) {
        ESP_LOGV(TAG, "Clearing buffer of %d bytes - parse failed", at);
        this->rx_buffer_.clear();
      }
    }
  }

  if (now - this->last_modbus_byte_ > this->timeout_) {
    size_t at = this->rx_buffer_.size();
    if (at > 0) {
      ESP_LOGW(TAG, "Clearing buffer of %d bytes - timeout", at);
      this->rx_buffer_.clear();
    }
  }
}

bool Modbus::parse_modbus_byte_(uint8_t byte) {
  size_t at = this->rx_buffer_.size();
  this->rx_buffer_.push_back(byte);
  const uint8_t *raw = &this->rx_buffer_[0];
  ESP_LOGVV(TAG, "Modbus received Byte %d (0X%x)", byte, byte);

  if (at == 0) // Byte 0: Modbus address (expect 0x01)
    return byte == 0x01;

  if (at == 1) // Byte 1: Function code (expect 0x03 or 0x06)
    return raw[1] == 0x03 || raw[1] == 0x06;

  uint8_t address = raw[0];
  uint8_t function_code = raw[1];
  uint8_t data_len = 0;
  uint8_t data_offset = 3;

  if (at == 2) // Byte 2: Data length for 0x03, register high byte for 0x06
    return true;

  if (at < 4) {
    ESP_LOGV(TAG, "Discarding small packet: size=%d", at + 1);
    return true;
  }

  if (function_code == 0x06) { // Write single register (8 bytes)
    if (at < 7) return true;

    uint16_t register_addr = (raw[2] << 8) | raw[3];
    if (register_addr != 0x07CF && register_addr != 0x07DA && register_addr != 0x07DF && register_addr != 0x0F9F) {
      ESP_LOGV(TAG, "Discarding invalid write register: 0x%04X", register_addr);
      this->rx_buffer_.clear();
      return false;
    }

    if (at == 7) {
      if (!this->check_crc(address, function_code, raw, 6)) {
        ESP_LOGV(TAG, "Clearing buffer of %d bytes - CRC failed", at + 1);
        this->rx_buffer_.clear();
        return false;
      }
      ESP_LOGD(TAG, "Good write packet for address=%d, register=0x%04X", address, register_addr);
      this->rx_buffer_.clear();
      return true;
    }
  } else if (function_code == 0x03) { // Read holding registers
    if (at == 3) {
      if (raw[2] == 0x08 && raw[3] == 0x33) return true;
      ESP_LOGV(TAG, "Discarding invalid read request: start=0x%02X%02X", raw[2], raw[3]);
      this->rx_buffer_.clear();
      return false;
    }
    if (at == 5) {
      if (raw[4] == 0x00 && raw[5] == 0x28) return true;
      ESP_LOGV(TAG, "Discarding invalid read count: 0x%02X%02X", raw[4], raw[5]);
      this->rx_buffer_.clear();
      return false;
    }
    if (at == 7 && raw[2] == 0x08) {
      if (!this->check_crc(address, function_code, raw, 6)) {
        ESP_LOGV(TAG, "Clearing buffer of %d bytes - CRC failed", at + 1);
        this->rx_buffer_.clear();
        return false;
      }
      ESP_LOGD(TAG, "Good read request for address=%d, start=0x0833, count=40", address);
      this->rx_buffer_.clear();
      return true;
    }
    if (at == 2 && raw[2] == 0x50) return true;
    if (at < 84 && raw[2] == 0x50) return true;
    if (at == 84 && raw[2] == 0x50) {
      if (!this->check_crc(address, function_code, raw, 83)) {
        ESP_LOGV(TAG, "Clearing buffer of %d bytes - CRC failed", at + 1);
        this->rx_buffer_.clear();
        return false;
      }
      ESP_LOGD(TAG, "Good read response for address=%d, 40 registers", address);
      this->rx_buffer_.clear();
      return true;
    }
  }

  ESP_LOGV(TAG, "Discarding unknown packet: size=%d, FC=0x%02X", at + 1, function_code);
  this->rx_buffer_.clear();
  return false;
}

bool Modbus::check_crc(uint8_t address, uint8_t function, const uint8_t *data, size_t data_len) {
  if (data_len < 2 || data == nullptr) {
    ESP_LOGW(TAG, "Invalid packet: size=%d, address=%d, function=%d", data_len, address, function);
    return false;
  }
  size_t total_len = data_len + 2;
  if (this->rx_buffer_.size() < total_len) {
    ESP_LOGW(TAG, "Incomplete packet: buffer size=%d, required=%d", this->rx_buffer_.size(), total_len);
    return false;
  }
  uint16_t computed_crc = crc16(data, data_len);
  uint16_t received_crc = (data[data_len] << 8) | data[data_len + 1];
  if (computed_crc != received_crc) {
    uint16_t reg_addr = (function == 0x06) ? ((data[2] << 8) | data[3]) : 0;
    std::string reg_info = (function == 0x06) ? format_hex(static_cast<uint16_t>(reg_addr)) : "read response";
    ESP_LOGW(TAG, "Modbus CRC Check failed! Expected %04X, received %04X for address=%d, function=%d, register=%s",
             computed_crc, received_crc, address, function, reg_info.c_str());
    return false;
  }
  ESP_LOGV(TAG, "Good CRC for address=%d, function=%d", address, function);
  return true;
}

uint16_t Modbus::crc16(const uint8_t *data, uint8_t len) {
  uint16_t crc = 0xFFFF;
  for (uint8_t pos = 0; pos < len; pos++) {
    crc ^= (uint16_t) data[pos];
    for (uint8_t i = 8; i != 0; i--) {
      if ((crc & 0x0001) != 0) {
        crc >>= 1;
        crc ^= 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
}

void Modbus::dump_config() {
  ESP_LOGCONFIG(TAG, "Modbus:");
  ESP_LOGCONFIG(TAG, "Version: 1.1.X");
  LOG_PIN("  Flow Control Pin: ", this->flow_control_pin_);
  ESP_LOGCONFIG(TAG, "  Send Wait Time: %d ms", this->send_wait_time_);
  ESP_LOGCONFIG(TAG, "  CRC Disabled: %s", YESNO(this->disable_crc_));
}
float Modbus::get_setup_priority() const {
  // After UART bus
  return setup_priority::BUS - 1.0f;
}

void Modbus::send(uint8_t address, uint8_t function_code, uint16_t start_address, uint16_t number_of_entities,
                  uint8_t payload_len, const uint8_t *payload) {
  static const size_t MAX_VALUES = 128;

  // Only check max number of registers for standard function codes
  // Some devices use non standard codes like 0x43
  if (number_of_entities > MAX_VALUES && function_code <= 0x10) {
    ESP_LOGE(TAG, "send too many values %d max=%zu", number_of_entities, MAX_VALUES);
    return;
  }

  std::vector<uint8_t> data;
  data.push_back(address);
  data.push_back(function_code);
  if (this->current_role_ == ModbusRole::CLIENT) {
    data.push_back(start_address >> 8);
    data.push_back(start_address >> 0);
    if (function_code != 0x5 && function_code != 0x6) {
      data.push_back(number_of_entities >> 8);
      data.push_back(number_of_entities >> 0);
    }
  }

  if (payload != nullptr) {
    if (this->current_role_ == ModbusRole::SERVER || function_code == 0xF || function_code == 0x10) {  // Write multiple
      data.push_back(payload_len);  // Byte count is required for write
    } else {
      payload_len = 2;  // Write single register or coil
    }
    for (int i = 0; i < payload_len; i++) {
      data.push_back(payload[i]);
    }
  }

  auto crc = crc16(data.data(), data.size());
  data.push_back(crc >> 0);
  data.push_back(crc >> 8);

  if (this->flow_control_pin_ != nullptr)
    this->flow_control_pin_->digital_write(true);

  this->write_array(data);
  this->flush();

  if (this->flow_control_pin_ != nullptr)
    this->flow_control_pin_->digital_write(false);
  waiting_for_response = address;
  last_send_ = millis();
  ESP_LOGV(TAG, "Modbus write: %s", format_hex_pretty(data).c_str());
}

// Helper function for lambdas
// Send raw command. Except CRC everything must be contained in payload
void Modbus::send_raw(const std::vector<uint8_t> &payload) {
  if (payload.empty()) {
    return;
  }

  if (this->flow_control_pin_ != nullptr)
    this->flow_control_pin_->digital_write(true);

  auto crc = crc16(payload.data(), payload.size());
  this->write_array(payload);
  this->write_byte(crc & 0xFF);
  this->write_byte((crc >> 8) & 0xFF);
  this->flush();
  if (this->flow_control_pin_ != nullptr)
    this->flow_control_pin_->digital_write(false);
  waiting_for_response = payload[0];
  ESP_LOGV(TAG, "Modbus write raw: %s", format_hex_pretty(payload).c_str());
  last_send_ = millis();
}

}  // namespace modbus
}  // namespace esphome
