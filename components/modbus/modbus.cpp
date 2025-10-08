#include "modbus.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"
#include "esphome/core/application.h"

namespace esphome {
namespace modbus {

static const char *const TAG = "modbus";

void Modbus::setup() {
  ESP_LOGCONFIG(TAG, "Modbus timeout set to 300 ms");
  if (this->current_role_ == ModbusRole::SNIFFER) {
    ESP_LOGD(TAG, "Switching role from SNIFFER to SERVER");
    this->current_role_ = ModbusRole::SERVER;
  } else {
    this->current_role_ = this->role;
  }
  if (this->flow_control_pin_ != nullptr) {
    this->flow_control_pin_->setup();
  }
  this->last_metric_log_ = millis();
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
        const uint8_t *raw = &this->rx_buffer_[0];
        bool is_control = (at >= 4 && raw[1] == 0x06 && 
                          ((raw[2] << 8) | raw[3]) == 0x07CF ||
                          (raw[2] << 8) | raw[3] == 0x07DA ||
                          (raw[2] << 8) | raw[3] == 0x07DF ||
                          (raw[2] << 8) | raw[3] == 0x0F9F);
        bool is_data = (at >= 3 && raw[1] == 0x03 && raw[2] == 0x50);
        if (is_control) {
          this->control_timeout_bytes_ += at;
          ESP_LOGD(TAG, "Clearing buffer of %d bytes - parse failed (control), control_loss=%.2f%%",
                   at, this->get_control_loss_percentage());
        } else if (is_data) {
          this->data_timeout_bytes_ += at;
          ESP_LOGD(TAG, "Clearing buffer of %d bytes - parse failed (data), data_loss=%.2f%%",
                   at, this->get_data_loss_percentage());
        } else {
          this->data_timeout_bytes_ += at;
          ESP_LOGD(TAG, "Clearing buffer of %d bytes - parse failed, data_loss=%.2f%%",
                   at, this->get_data_loss_percentage());
        }
        this->rx_buffer_.clear();
      }
    }
    // Yield to avoid starving other tasks
    yield();
  }

  if (now - this->last_modbus_byte_ > 300) {
    size_t at = this->rx_buffer_.size();
    if (at > 0) {
      const uint8_t *raw = &this->rx_buffer_[0];
      bool is_control = (at >= 4 && raw[1] == 0x06 && 
                        ((raw[2] << 8) | raw[3]) == 0x07CF ||
                        (raw[2] << 8) | raw[3] == 0x07DA ||
                        (raw[2] << 8) | raw[3] == 0x07DF ||
                        (raw[2] << 8) | raw[3] == 0x0F9F);
      bool is_data = (at >= 3 && raw[1] == 0x03 && raw[2] == 0x50);
      if (is_control) {
        this->control_timeout_bytes_ += at;
        ESP_LOGD(TAG, "Clearing buffer of %d bytes - timeout (control), control_loss=%.2f%%",
                 at, this->get_control_loss_percentage());
      } else if (is_data) {
        this->data_timeout_bytes_ += at;
        ESP_LOGD(TAG, "Clearing buffer of %d bytes - timeout (data), data_loss=%.2f%%",
                 at, this->get_data_loss_percentage());
      } else {
        this->data_timeout_bytes_ += at;
        ESP_LOGD(TAG, "Clearing buffer of %d bytes - timeout, data_loss=%.2f%%",
                 at, this->get_data_loss_percentage());
      }
      this->rx_buffer_.clear();
    }
  }

  // Log metrics every 60 seconds
  if (millis() - this->last_metric_log_ >= 60000) {
    this->log_loss_metrics();
    this->last_metric_log_ = millis();
  }
}

float Modbus::get_control_loss_percentage() const {
  if (this->total_bytes_received_ == 0) return 0.0f;
  return (static_cast<float>(this->control_crc_failed_bytes_ + this->control_timeout_bytes_) / this->total_bytes_received_) * 100.0f;
}

float Modbus::get_data_loss_percentage() const {
  if (this->total_bytes_received_ == 0) return 0.0f;
  return (static_cast<float>(this->data_crc_failed_bytes_ + this->data_timeout_bytes_) / this->total_bytes_received_) * 100.0f;
}

void Modbus::log_loss_metrics() {
  ESP_LOGD(TAG, "Data loss metrics: Total bytes=%u, Control CRC failed=%u, Control timeout=%u, Control loss=%.2f%%, "
                "Data CRC failed=%u, Data timeout=%u, Data loss=%.2f%%",
           this->total_bytes_received_, this->control_crc_failed_bytes_, this->control_timeout_bytes_,
           this->get_control_loss_percentage(), this->data_crc_failed_bytes_, this->data_timeout_bytes_,
           this->get_data_loss_percentage());
}

bool Modbus::parse_modbus_byte_(uint8_t byte) {
  this->total_bytes_received_++; // Increment total bytes received
  size_t at = this->rx_buffer_.size();
  this->rx_buffer_.push_back(byte);
  const uint8_t *raw = &this->rx_buffer_[0];
  ESP_LOGD(TAG, "Received byte %d (0x%02X)", byte, byte);

  // Limit buffer size to prevent overflow
  if (this->rx_buffer_.size() > 256) {
    this->data_timeout_bytes_ += at + 1;
    ESP_LOGD(TAG, "Buffer overflow, clearing %d bytes, data_loss=%.2f%%",
             at + 1, this->get_data_loss_percentage());
    this->rx_buffer_.clear();
    return false;
  }

  // Byte 0: modbus address (match all)
  if (at == 0)
    return true;

  uint8_t address = raw[0];
  uint8_t function_code = raw[1];

  // Byte 2: Size (with modbus rtu function code 3/4)
  if (at == 2 && (function_code == 0x03 || function_code == 0x04)) {
    this->register_count = raw[2] / 2; // Number of registers
    return true;
  }

  // Byte 3: Start address (with modbus rtu function code 6)
  if (at == 3 && function_code == 0x06) {
    this->start_address_ = (raw[2] << 8) | raw[3];
    return true;
  }

  // Full packet received: 0x03/0x04 (read response)
  if ((function_code == 0x03 || function_code == 0x04) && at == (this->register_count * 2 + 4)) {
    uint16_t crc = this->crc16(raw, this->register_count * 2 + 3);
    uint16_t crc_received = (raw[at] << 8) | raw[at - 1];
    bool crc_ok = crc == crc_received || disable_crc_;
    if (!crc_ok) {
      this->data_crc_failed_bytes_ += at + 1;
      ESP_LOGD(TAG, "CRC failed for read response, expected 0x%04X, received 0x%04X, data_loss=%.2f%%",
               crc, crc_received, this->get_data_loss_percentage());
      for (auto *device : this->devices_) {
        if (device->address_ == address)
          device->on_modbus_error(function_code, 0x04);
      }
      this->rx_buffer_.clear();
      return false;
    }
    std::vector<uint8_t> data(this->rx_buffer_.begin() + 3, this->rx_buffer_.begin() + 3 + this->register_count * 2);
    ESP_LOGD(TAG, "Good read response: FC=0x%02X, Start=0x%04X, Count=%u",
             function_code, this->start_address_, this->register_count);
    for (auto *device : this->devices_) {
      if (device->address_ == address) {
        device->on_modbus_data(data);
        if (this->register_count > 0)
          device->on_modbus_read_registers(function_code, this->start_address_, this->register_count);
        device->on_modbus_message(function_code, this->start_address_, this->register_count, data);
      }
    }
    this->rx_buffer_.clear();
    return true;
  }

  // Full packet received: 0x06 (write request)
  if (function_code == 0x06 && at == 7) {
    uint16_t crc = this->crc16(raw, 6);
    uint16_t crc_received = (raw[7] << 8) | raw[6];
    bool crc_ok = crc == crc_received || disable_crc_;
    if (!crc_ok) {
      this->control_crc_failed_bytes_ += at + 1;
      ESP_LOGD(TAG, "CRC failed for write request, register=0x%04X, expected 0x%04X, received 0x%04X, control_loss=%.2f%%",
               this->start_address_, crc, crc_received, this->get_control_loss_percentage());
      for (auto *device : this->devices_) {
        if (device->address_ == address)
          device->on_modbus_error(function_code, 0x04);
      }
      this->rx_buffer_.clear();
      return false;
    }
    std::vector<uint8_t> data(this->rx_buffer_.begin() + 2, this->rx_buffer_.begin() + 6);
    ESP_LOGD(TAG, "Good write request: FC=0x%02X, Register=0x%04X, Data=%s",
             function_code, this->start_address_, format_hex_pretty(data).c_str());
    for (auto *device : this->devices_) {
      if (device->address_ == address) {
        device->on_modbus_data(data);
        device->on_modbus_message(function_code, this->start_address_, 1, data);
      }
    }
    this->rx_buffer_.clear();
    return true;
  }

  // Error packet: 0x83/0x84/0x86
  if (at == 4 && (function_code == 0x83 || function_code == 0x84 || function_code == 0x86)) {
    uint16_t crc = this->crc16(raw, 3);
    uint16_t crc_received = (raw[4] << 8) | raw[3];
    bool crc_ok = crc == crc_received || disable_crc_;
    if (!crc_ok) {
      this->data_crc_failed_bytes_ += at + 1;
      ESP_LOGD(TAG, "CRC failed for error packet, expected 0x%04X, received 0x%04X, data_loss=%.2f%%",
               crc, crc_received, this->get_data_loss_percentage());
      this->rx_buffer_.clear();
      return false;
    }
    for (auto *device : this->devices_) {
      if (device->address_ == address)
        device->on_modbus_error(function_code - 0x80, raw[2]);
    }
    this->rx_buffer_.clear();
    return true;
  }

  // Continue accumulating bytes
  if ((function_code == 0x06 && at < 7) || 
      ((function_code == 0x03 || function_code == 0x04) && at < (this->register_count * 2 + 4))) {
    return true;
  }

  // Discard unknown/invalid packets
  this->data_timeout_bytes_ += at + 1;
  ESP_LOGD(TAG, "Discarding unknown packet: size=%d, FC=0x%02X, data_loss=%.2f%%",
           at + 1, function_code, this->get_data_loss_percentage());
  this->rx_buffer_.clear();
  return false;
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
  ESP_LOGCONFIG(TAG, "  Timeout: 300 ms");
}

float Modbus::get_setup_priority() const { return setup_priority::DATA; }

void Modbus::send(uint8_t address, uint8_t function_code, uint16_t start_address, uint16_t number_of_entities,
                  uint8_t payload_len, const uint8_t *payload) {
  static const size_t MAX_VALUES = 128;

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
    if (this->current_role_ == ModbusRole::SERVER || function_code == 0xF || function_code == 0x10) {
      data.push_back(payload_len);
    } else {
      payload_len = 2;
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
  ESP_LOGD(TAG, "Modbus write: %s", format_hex_pretty(data).c_str());
}

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
  ESP_LOGD(TAG, "Modbus write raw: %s", format_hex_pretty(payload).c_str());
  last_send_ = millis();
}

}  // namespace modbus
}  // namespace esphome
