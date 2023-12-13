/**
 *  Copyright (c) 2017 Håvard Fossli.
 *
 *  Licensed under the MIT license, as follows:
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */


import Foundation
import Security

@available(OSX 10.12.2, iOS 11.0, *)
public enum EllipticCurveKeyPair {
    
    public typealias Logger = (String) -> ()
    public static var logger: Logger?
    public static var errorReporter: ((Swift.Error) -> ())?
        
    public struct Config {
        
        // The label used to identify the public key in keychain
        public var publicLabel: String
        
        // The label used to identify the private key on the secure enclave
        public var privateLabel: String

        // The access control used to manage the access to the public key
        public var publicKeyAccessControl: AccessControl
        
        // The access control used to manage the access to the private key
        public var privateKeyAccessControl: AccessControl
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var publicKeyAccessGroup: String?
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var privateKeyAccessGroup: String?
        
        // Should it be stored on .secureEnclave or in .keychain ?
        public var token: Token
        
        public init(publicLabel: String,
                    privateLabel: String,
                    publicKeyAccessControl: AccessControl,
                    privateKeyAccessControl: AccessControl,
                    publicKeyAccessGroup: String? = nil,
                    privateKeyAccessGroup: String? = nil,
                    token: Token) {
            self.publicLabel = publicLabel
            self.privateLabel = privateLabel
            self.publicKeyAccessControl = publicKeyAccessControl
            self.privateKeyAccessControl = privateKeyAccessControl
            self.publicKeyAccessGroup = publicKeyAccessGroup
            self.privateKeyAccessGroup = privateKeyAccessGroup
            self.token = token
        }
    }
    
    // A stateful and opiniated manager for using the secure enclave and keychain
    // If the private or public key is not found this manager will naively just recreate a new keypair
    // If the device doesn't have a Secure Enclave it will store the private key in keychain just like the public key
    //
    // If you think this manager is "too smart" in that sense you may use this manager as an example
    // and create your own manager
    public final class Manager {
        
        private let config: Config
        private let helper: Helper
        private var cachedPublicKey: PublicKey? = nil
        private var cachedPrivateKey: PrivateKey? = nil
        
        public init(config: Config) {
            self.config = config
            self.helper = Helper(config: config)
        }
        
        public func deleteKeyPair() throws {
            clearCache()
            try helper.delete()
        }
        
        public func publicKey() throws -> PublicKey {
            do {
                if let key = cachedPublicKey {
                    return key
                }
                let key = try helper.getPublicKey()
                cachedPublicKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                if let keys = helper.fallbackToFirstAvailableKeyPair() {
                    EllipticCurveKeyPair.errorReporter?(FallbackError.noPublicKeyButRestored)
                    
                    cachedPublicKey = keys.public
                    cachedPrivateKey = keys.private
                    return keys.public
                }
                
                let keys = try helper.generateKeyPair()
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.public
            } catch {
                throw error
            }
        }
        
        public func privateKey() throws -> PrivateKey {
            do {
                if let key = cachedPrivateKey {
                    return key
                }
                let key = try helper.getPrivateKey()
                cachedPrivateKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                if let keys = helper.fallbackToFirstAvailableKeyPair() {
                    EllipticCurveKeyPair.errorReporter?(FallbackError.noPrivateKeyButRestored)
                    
                    cachedPublicKey = keys.public
                    cachedPrivateKey = keys.private
                    return keys.private
                }
                
                let keys = try helper.generateKeyPair()
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.private
            } catch {
                throw error
            }
        }
        
        public func keys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try self.privateKey()
            let publicKey = try self.publicKey()
            return (public: publicKey, private: privateKey)
        }
        
        public func clearCache() {
            cachedPublicKey = nil
            cachedPrivateKey = nil
        }

        public func sign(_ digest: Data, hash: Hash) throws -> Data {
            return try helper.sign(digest, privateKey: privateKey(), hash: hash)
        }

        public func verify(signature: Data, originalDigest: Data, hash: Hash) throws {
            try helper.verify(signature: signature, digest: originalDigest, publicKey: publicKey(), hash: hash)
        }

        public func encrypt(_ digest: Data, hash: Hash = .sha256) throws -> Data {
            return try helper.encrypt(digest, publicKey: publicKey(), hash: hash)
        }
        
        public func decrypt(_ encrypted: Data, hash: Hash = .sha256) throws -> Data {
            return try helper.decrypt(encrypted, privateKey: privateKey(), hash: hash)
        }
        
    }
    
    // Helper is a stateless class for querying the secure enclave and keychain
    // You may create a small stateful facade around this
    // `Manager` is an example of such an opiniated facade
    public struct Helper {
        
        public let config: Config
        
        public init(config: Config) {
            self.config = config
        }
        
        public func getPublicKey() throws -> PublicKey {
            return try Query.getPublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
        }
        
        public func getFirstPublicKey() throws -> PublicKey {
            return try Query.getFirstPublicKey()
        }
        
        public func getPrivateKey() throws -> PrivateKey {
            try Query.getPrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup)
        }
        
        public func getFirstPrivateKey() throws -> PrivateKey {
            try Query.getFirstPrivateKey()
        }
        
        public func fallbackToFirstAvailableKeyPair() -> (`public`: PublicKey, `private`: PrivateKey)? {
            let publicKey = try? getFirstPublicKey()
            let privateKey = try? getFirstPrivateKey()
            
            if publicKey != nil && privateKey != nil {
                return (public: publicKey!, private: privateKey!)
            }
            else if publicKey != nil {
                // no privateKey
                errorReporter?(FallbackError.noPrivateKeyButHasDetachedPublicKey)
                return nil
            }
            else if privateKey != nil {
                // no publicKey
                errorReporter?(FallbackError.noPublicKeyButHasDetachedPrivateKey)
                return nil
            }
            return nil
        }
                
        public func generateKeyPair() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            guard config.privateLabel != config.publicLabel else{
                throw Error.inconcistency(message: "Public key and private key can not have same label")
            }
            let query = try Query.generateKeyPairQuery(config: config, token: config.token)
            var publicOptional, privateOptional: SecKey?
            logger?("SecKeyGeneratePair: \(query)")
            let status = SecKeyGeneratePair(query as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                if status == errSecAuthFailed {
                    throw Error.osStatus(message: "Could not generate keypair. Security probably doesn't like the access flags you provided. Specifically if this device doesn't have secure enclave and you pass `.privateKeyUsage`. it will produce this error.", osStatus: status)
                } else {
                    throw Error.osStatus(message: "Could not generate keypair.", osStatus: status)
                }
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it.")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec)
            try Query.forceSavePublicKey(publicKey, label: config.publicLabel)
            return (public: publicKey, private: privateKey)
        }
        
        public func delete() throws {
            try Query.deletePublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
            try Query.deletePrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup)
        }
        
        public func sign(_ digest: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateSignature(privateKey.underlying, hash.signatureMessage, digest as CFData, &error)
            guard let signature = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
            }
            return signature as Data
        }
        
        public func verify(signature: Data, digest: Data, publicKey: PublicKey, hash: Hash) throws {
            var error : Unmanaged<CFError>?
            let valid = SecKeyVerifySignature(publicKey.underlying, hash.signatureMessage, digest as CFData, signature as CFData, &error)
            if let error = error?.takeRetainedValue() {
                throw Error.fromError(error, message: "Could not verify signature.")
            }
            guard valid == true else {
                throw Error.inconcistency(message: "Signature yielded no error, but still marks itself as unsuccessful")
            }
        }
        
        public func encrypt(_ digest: Data, publicKey: PublicKey, hash: Hash) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.underlying, hash.encryptionEciesEcdh, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
        
        public func decrypt(_ encrypted: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.underlying, hash.encryptionEciesEcdh, encrypted as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not decrypt.")
            }
            return data as Data
        }
    }

    private struct Query {
        
        static func getKey(_ query: [String: Any]) throws -> SecKey {
            var raw: CFTypeRef?
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get key for query: \(query)", osStatus: status)
            }
            return result as! SecKey
        }
        
        static func getKeys(_ query: [String: Any]) throws -> [SecKey] {
            var raw: CFTypeRef?
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get multiple keys for query: \(query)", osStatus: status)
            }
            return result as! [SecKey]
        }
        
        static func publicKeyQuery(labeled: String, accessGroup: String?) -> [String:Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
            ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            return params
        }
        
        static func anyPublicKeyQuery() -> [String:Any] {
            let params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            return params
        }
        
        static func privateKeyQuery(labeled: String, accessGroup: String?) -> [String: Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            return params
        }
        
        static func anyPrivateKeyQuery() -> [String: Any] {
            let params: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            return params
        }
        
        static func generateKeyPairQuery(config: Config, token: Token) throws -> [String:Any] {
            
            /* ========= private ========= */
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                ]
            if let privateKeyAccessGroup = config.privateKeyAccessGroup {
                privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
            }

            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.privateKeyAccessControl.flags.isEmpty {
                privateKeyParams[kSecAttrAccessControl as String] = try config.privateKeyAccessControl.underlying()
            } else {
                privateKeyParams[kSecAttrAccessible as String] = config.privateKeyAccessControl.protection
            }
            
            /* ========= public ========= */
            var publicKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.publicLabel,
                ]
            if let publicKeyAccessGroup = config.publicKeyAccessGroup {
                publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
            }
            
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.publicKeyAccessControl.flags.isEmpty {
                publicKeyParams[kSecAttrAccessControl as String] = try config.publicKeyAccessControl.underlying()
            } else {
                publicKeyParams[kSecAttrAccessible as String] = config.publicKeyAccessControl.protection
            }
            
            /* ========= combined ========= */
            var params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecPublicKeyAttrs as String: publicKeyParams,
                kSecAttrKeySizeInBits as String: 256,
                ]
            if token == .secureEnclave {
                params[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            return params
        }
        
        static func getPublicKey(labeled: String, accessGroup: String?) throws -> PublicKey {
            let query = publicKeyQuery(labeled: labeled, accessGroup: accessGroup)
            return PublicKey(try getKey(query))
        }
        
        static func getFirstPublicKey() throws -> PublicKey {
            let query = anyPublicKeyQuery()
            let keys = try getKeys(query)
            let first = keys.first!
            return PublicKey(first)
        }
        
        static func getPrivateKey(labeled: String, accessGroup: String?) throws -> PrivateKey {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup)
            return PrivateKey(try getKey(query))
        }
        
        static func getFirstPrivateKey() throws -> PrivateKey {
            let query = anyPrivateKeyQuery()
            let keys = try getKeys(query)
            let first = keys.first!
            return PrivateKey(first)
        }
        
        static func deletePublicKey(labeled: String, accessGroup: String?) throws {
            let query = publicKeyQuery(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete public key.", osStatus: status)
            }
        }
        
        static func deletePrivateKey(labeled: String, accessGroup: String?) throws {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
            }
        }
        
        static func forceSavePublicKey(_ publicKey: PublicKey, label: String) throws {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: label,
                kSecValueRef as String: publicKey.underlying
            ]
            var raw: CFTypeRef?
            logger?("SecItemAdd: \(query)")
            var status = SecItemAdd(query as CFDictionary, &raw)
            if status == errSecDuplicateItem {
                logger?("SecItemDelete: \(query)")
                status = SecItemDelete(query as CFDictionary)
                logger?("SecItemAdd: \(query)")
                status = SecItemAdd(query as CFDictionary, &raw)
            }
            if status == errSecInvalidRecord {
                throw Error.osStatus(message: "Could not save public key. It is possible that the access control you have provided is not supported on this OS and/or hardware.", osStatus: status)
            } else if status != errSecSuccess {
                throw Error.osStatus(message: "Could not save public key", osStatus: status)
            }
        }
    }
    
    public struct Constants {        
        public static let noCompression: UInt8 = 4
        public static let attrKeyTypeEllipticCurve = kSecAttrKeyTypeECSECPrimeRandom as String
    }
    
    public final class PublicKeyData {
        
        // As received from Security framework
        public let raw: Data
        
        // The open ssl compatible DER format X.509
        //
        // We take the raw key and prepend an ASN.1 headers to it. The end result is an
        // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
        //
        // See the following DevForums post for more details on this.
        // https://forums.developer.apple.com/message/84684#84684
        //
        // End result looks like this
        // https://lapo.it/asn1js/#3059301306072A8648CE3D020106082A8648CE3D030107034200041F4E3F6CD8163BCC14505EBEEC9C30971098A7FA9BFD52237A3BCBBC48009162AAAFCFC871AC4579C0A180D5F207316F74088BF01A31F83E9EBDC029A533525B
        //
        public lazy var DER: Data = {
            var x9_62HeaderECHeader = [UInt8]([
                /* sequence          */ 0x30, 0x59,
                /* |-> sequence      */ 0x30, 0x13,
                /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
                /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
                /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
                ])
            var result = Data()
            result.append(Data(x9_62HeaderECHeader))
            result.append(self.raw)
            return result
        }()
        
        public lazy var PEM: String = {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append(self.DER.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }()
        
        internal init(_ raw: Data) {
            self.raw = raw
        }
    }
    
    public class Key {
        
        public let underlying: SecKey
        
        internal init(_ underlying: SecKey) {
            self.underlying = underlying
        }
        
        private var cachedAttributes: [String:Any]? = nil
        
        public func attributes() throws -> [String:Any] {
            if let attributes = cachedAttributes {
                return attributes
            } else {
                let attributes = try queryAttributes()
                cachedAttributes = attributes
                return attributes
            }
        }
        
        public func label() throws -> String {
            guard let attribute = try self.attributes()[kSecAttrLabel as String] as? String else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its label.")
            }
            return attribute
        }
        
        public func accessGroup() throws -> String? {
            return try self.attributes()[kSecAttrAccessGroup as String] as? String
        }
        
        public func accessControl() throws -> SecAccessControl {
            guard let attribute = try self.attributes()[kSecAttrAccessControl as String] else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its access control.")
            }
            return attribute as! SecAccessControl
        }
        
        private func queryAttributes() throws -> [String:Any] {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: underlying,
                kSecReturnAttributes as String: true
            ]
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not read attributes for key", osStatus: status)
            }
            guard let attributes = matchResult as? [String:Any] else {
                throw Error.inconcistency(message: "Tried reading key attributes something went wrong. Expected dictionary, but received \(String(describing: matchResult)).")
            }
            return attributes
        }
    }
    
    public final class PublicKey: Key {
        
        private var cachedData: PublicKeyData? = nil
        
        public func data() throws -> PublicKeyData {
            if let data = cachedData {
                return data
            } else {
                let data = try queryData()
                cachedData = data
                return data
            }
        }
        
        private func queryData() throws -> PublicKeyData {
            let keyRaw = try export()
            guard keyRaw.first == Constants.noCompression else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but its headers says it is compressed and this library only handles uncompressed keys.")
            }
            return PublicKeyData(keyRaw)
        }
        
        private func export() throws -> Data {
            var error : Unmanaged<CFError>?
            guard let raw = SecKeyCopyExternalRepresentation(underlying, &error) else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried reading public key bytes.")
            }
            return raw as Data
        }
    }
    
    public final class PrivateKey: Key {

        public func isStoredOnSecureEnclave() throws -> Bool {
            let attribute = try self.attributes()[kSecAttrTokenID as String] as? String
            return attribute == (kSecAttrTokenIDSecureEnclave as String)
        }
    }
    
    public final class AccessControl {
        
        // E.g. kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        public let protection: CFTypeRef
        
        // E.g. [.userPresence, .privateKeyUsage]
        public let flags: SecAccessControlCreateFlags
        
        public init(protection: CFTypeRef, flags: SecAccessControlCreateFlags) {
            self.protection = protection
            self.flags = flags
        }
        
        public func underlying() throws -> SecAccessControl {
            // Seems like not a valid point anymore. Verified on iPhone Xs iOS 14.4.2.
            // if flags.contains(.privateKeyUsage) {
            //     let flagsWithOnlyPrivateKeyUsage: SecAccessControlCreateFlags = [.privateKeyUsage]
            //     guard flags != flagsWithOnlyPrivateKeyUsage else {
            //         throw EllipticCurveKeyPair.Error.inconcistency(message: "Couldn't create access control flag. Keychain chokes if you try to create access control with only [.privateKeyUsage] on devices older than iOS 11 and macOS 10.13.x")
            //     }
            // }
            
            var error: Unmanaged<CFError>?
            let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &error)
            guard let accessControl = result else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(flags) and protection \(protection)")
            }
            return accessControl
        }
    }
    
    public enum FallbackError: Int, Swift.Error {
        case noPublicKeyButRestored = 1
        case noPrivateKeyButRestored = 2
        case noPublicKeyButHasDetachedPrivateKey = 3
        case noPrivateKeyButHasDetachedPublicKey = 4
    }
    
    public enum Error: LocalizedError {
        
        case underlying(message: String, error: NSError)
        case inconcistency(message: String)
        
        public var errorDescription: String? {
            switch self {
            case let .underlying(message: message, error: error):
                return "\(message) \(error.localizedDescription)"
            case let .inconcistency(message: message):
                return "Inconcistency in setup, configuration or keychain. \(message)"
            }
        }
        
        internal static func osStatus(message: String, osStatus: OSStatus) -> Error {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: [
                NSLocalizedDescriptionKey: message,
                NSLocalizedRecoverySuggestionErrorKey: "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(osStatus)"
                ])
            return .underlying(message: message, error: error)
        }

        internal static func fromError(_ error: CFError?, message: String) -> Error {
            if let error = error,
                let domain = CFErrorGetDomain(error) as String? {
                let code = Int(CFErrorGetCode(error))
                var userInfo = (CFErrorCopyUserInfo(error) as? [String:Any]) ?? [String:Any]()
                if userInfo[NSLocalizedRecoverySuggestionErrorKey] == nil {
                    userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(code)"
                }
                let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
                return .underlying(message: message, error: underlying)
            }
            return .inconcistency(message: "\(message) Unknown error occured.")
        }
        
    }
    
    public enum Hash: String {
        
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        var signatureMessage: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
            case .sha224:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
            case .sha256:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            case .sha384:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
            case .sha512:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
            }
        }
        
        var encryptionEciesEcdh: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM
            case .sha224:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM
            case .sha256:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
            case .sha384:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
            case .sha512:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM
            }
        }
    }
    
    public enum Token {
        case secureEnclave
        case keychain        
    }
}
