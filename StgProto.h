#ifndef __STGPROTO_H__
#define __STGPROTO_H__

#include <Arduino.h>

typedef unsigned char StgAesKey[16];

class StgProto {
public:
  StgProto() {
    _deviceAddress = 0;
    _messageCounter = 0;
    _logSerial = NULL;
    _encryptionKey = NULL;
  }

  typedef uint8_t (*rawSendCallBackType)(unsigned char *buffer, uint8_t size);

  void setDeviceAddress(uint8_t, uint8_t, uint8_t);
  void setEncryptionKey(StgAesKey *key);
  uint16_t computePayload(unsigned char *inputBuffer, uint8_t inputSize,
                          unsigned char *outputBuffer, uint8_t outputSize);

  bool send(char *data, uint8_t size);

  bool isBusy();

  void setLogSerial(HardwareSerial *logSerial) { _logSerial = logSerial; }

private:
  uint16_t encrypt(unsigned char *inputBuffer, uint8_t inputSize,
                   unsigned char *outputBuffer, uint8_t outputSize);

  uint32_t _deviceAddress;
  uint16_t _messageCounter;

  StgAesKey *_encryptionKey;

  HardwareSerial *_logSerial;
};

#endif
