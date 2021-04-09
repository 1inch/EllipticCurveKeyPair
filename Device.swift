//
//  Device.swift
//  EllipticCurveKeyPair
//
//  Created by Andrew Podkovyrin on 09.04.2021.
//  Copyright © 2021 Agens AS. All rights reserved.
//

import Foundation
import LocalAuthentication
import EllipticCurveKeyPair

extension EllipticCurveKeyPair.Token {
    public static var secureEnclaveIfAvailable: EllipticCurveKeyPair.Token {
        return Device.hasSecureEnclave ? .secureEnclave : .keychain
    }
}

public enum Device {

    public static var hasBiometrics: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    public static var isSimulator: Bool {
        return TARGET_OS_SIMULATOR != 0
    }

    public static var hasSecureEnclave: Bool {
        return hasBiometrics && !isSimulator
    }

}
