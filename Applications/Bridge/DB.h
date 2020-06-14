// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

// Basic light bulb database example. This header file, and the corresponding DB.c implementation in the ADK, is
// platform-independent.

#ifndef DB_H
#define DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "HAP.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**
 * Total number of services and characteristics contained in the accessory.
 */
#define kAttributeCount ((size_t) 31)

/**
 * HomeKit Accessory Information service.
 */
extern const HAPService bridgeAccessoryInformationService;

/**
 * Characteristics to expose accessory information and configuration (associated with Accessory Information service).
 */
extern const HAPBoolCharacteristic bridgeAccessoryInformationIdentifyCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationManufacturerCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationModelCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationNameCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationSerialNumberCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationFirmwareRevisionCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationHardwareRevisionCharacteristic;
extern const HAPStringCharacteristic bridgeAccessoryInformationADKVersionCharacteristic;

extern const HAPService bridgedLightBulbAccessoryInformationService;

/**
 * HAP Protocol Information service.
 */
extern const HAPService hapProtocolInformationService;

/**
 * Pairing service.
 */
extern const HAPService pairingService;

/**
 * Light Bulb service.
 */
extern const HAPService bridgedLightBulbService;

/**
 * The 'On' characteristic of the Light Bulb service.
 */
extern const HAPBoolCharacteristic bridgedLightBulbOnCharacteristic;

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
