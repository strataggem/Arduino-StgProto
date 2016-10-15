#include "StgProto.h"

#include "aes.h"

#define PROTOCOL_VERSION 0x1

#define STGPROTO_LOG(...)                                                      \
  {                                                                            \
    if (_logSerial)                                                            \
      _logSerial->print(__VA_ARGS__);                                          \
  }
#define STGPROTO_LOGLN(...)                                                    \
  {                                                                            \
    if (_logSerial)                                                            \
      _logSerial->println(__VA_ARGS__);                                        \
  }

void StgProto::setDeviceAddress(uint8_t a, uint8_t b, uint8_t c) {
  _deviceAddress = a << 16 | b << 8 | c;
  STGPROTO_LOG("setDeviceAddress: ");
  STGPROTO_LOGLN(_deviceAddress);
}
void StgProto::setEncryptionKey(StgAesKey *key) { _encryptionKey = key; }
uint16_t StgProto::computePayload(unsigned char *inputBuffer, uint8_t inputSize,
                                  unsigned char *outputBuffer,
                                  uint8_t outputSize) {

  STGPROTO_LOGLN("StgProto::computePayload");
  _messageCounter++;
  uint16_t outputIndex = 0;

  outputBuffer[outputIndex++] = PROTOCOL_VERSION;

  outputBuffer[outputIndex++] = (char)(_deviceAddress >> 24) & 0xff;
  outputBuffer[outputIndex++] = (char)(_deviceAddress >> 16) & 0xff;
  outputBuffer[outputIndex++] = (char)(_deviceAddress >> 8) & 0xff;
  outputBuffer[outputIndex++] = (char)((_deviceAddress)&0xff);
  outputBuffer[outputIndex++] = (char)_messageCounter >> 8 & 0xff;
  outputBuffer[outputIndex++] = (char)_messageCounter & 0xff;

  outputBuffer[outputIndex++] = (char)inputSize;

  if (_encryptionKey) {
    outputIndex +=
        encrypt(inputBuffer, inputSize, outputBuffer + outputIndex, outputSize);
  } else {
    memcpy(outputBuffer + outputIndex, inputBuffer, inputSize);
    outputIndex += inputSize;
  }

  STGPROTO_LOG("messageCounter: ");
  STGPROTO_LOGLN((int)_messageCounter);

  STGPROTO_LOG("Payload: ")
  for (int i = 0; i < outputIndex; i++) {
    STGPROTO_LOG((int)outputBuffer[i]);
    STGPROTO_LOG(" ");
  }
  STGPROTO_LOGLN();

  outputIndex++;

  STGPROTO_LOG("Total size is ");
  STGPROTO_LOGLN(outputIndex);

  return outputIndex;
}

uint16_t StgProto::encrypt(unsigned char *inputBuffer, uint8_t inputSize,
                           unsigned char *outputBuffer, uint8_t outputSize) {

  unsigned char toEncrypt[16] = {0};

  unsigned char encrypted[16] = {0};

  outputSize = 16;

  memcpy(toEncrypt, inputBuffer, inputSize);

  STGPROTO_LOG("data to encrypt: ")
  for (int i = 0; i < inputSize; i++) {
    STGPROTO_LOG((int)inputBuffer[i]);
    STGPROTO_LOG(" ");
  }
  STGPROTO_LOGLN();

  AES128_ECB_encrypt(toEncrypt, (const uint8_t *)_encryptionKey, encrypted);

  memcpy(outputBuffer, encrypted, 16);

  STGPROTO_LOG("data encrypted: ")
  for (int i = 0; i < outputSize; i++) {
    STGPROTO_LOG((int)outputBuffer[i]);
    STGPROTO_LOG(" ");
  }
  STGPROTO_LOGLN();

  return outputSize;
}
