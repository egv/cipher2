import Flutter
import UIKit
import CryptoSwift

extension String {
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self, options: Data.Base64DecodingOptions(rawValue: 0)) else {
            return nil
        }
        return String(data: data as Data, encoding: String.Encoding.utf8)
    }

    func toBase64() -> String? {
        guard let data = self.data(using: String.Encoding.utf8) else {
            return nil
        }
        return data.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
    }
}

enum TestedParams {
    case params([String:String])
    case error(FlutterError)

    static func fromCall(_ call: FlutterMethodCall) -> TestedParams {
        guard let args = call.arguments as? [String: String] else {
            return .error(
                FlutterError(
                    code: "ERROR_INVALID_PARAMETER_TYPE",
                    message: "the parameters data, key and iv must be all strings",
                    details: nil
                )
            )
        }

        if (args["data"] == nil || args["key"] == nil) {
            return .error(
                FlutterError(
                    code: "ERROR_INVALID_PARAMETER_TYPE",
                    message: "the parameters data, key and iv must be all strings",
                    details: nil
                )
            )
        }

        return .params(args)
    }
}

public class SwiftCipher2Plugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "cipher2", binaryMessenger: registrar.messenger())
        let instance = SwiftCipher2Plugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    private func encryptAesCbc128Padding7(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch TestedParams.fromCall(call) {
        case .error(let error):
            result(error)
            return

        case .params(let args):
            let data = args["data"]!
            let key = args["key"]!
            let iv = args["iv"]!

            let dataArray = Array(data.utf8)
            let keyArray = Array(key.utf8)
            let ivArray = Array(iv.utf8)

            if(key.count != 16 || iv.count != 16){
                result(
                    FlutterError(
                        code: "ERROR_INVALID_KEY_OR_IV_LENGTH",
                        message: "the length of key and iv must be all 128 bits",
                        details: nil
                    )
                )

                return
            }

            var encryptedBase64 = "";

            do {
                let encrypted = try AES(
                    key: keyArray,
                    blockMode: CBC(iv: ivArray),
                    padding: .pkcs7
                ).encrypt(dataArray)
                let encryptedNSData = NSData(bytes: encrypted, length: encrypted.count)
                encryptedBase64 = encryptedNSData.base64EncodedString(options:[])
            } catch {
                result(FlutterError(code: "ERROR_INVALID_CRYPTO_OPERATION", message: "error", details: nil))

            }

            result(encryptedBase64)
        }
    }

    private func decryptAesCbc128Padding7(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch TestedParams.fromCall(call) {
        case .error(let error):
            result(error)
            return

        case .params(let args):
            let data = args["data"]!
            let key = args["key"]!
            let iv = args["iv"]!

            let keyArray = Array(key.utf8)
            let ivArray = Array(iv.utf8)

            if(key.count != 16 || iv.count != 16){
                result(
                    FlutterError(
                        code: "ERROR_INVALID_KEY_OR_IV_LENGTH",
                        message: "the length of key and iv must be all 128 bits",
                        details: nil
                    )
                )
                return
            }

            //解码得到Array<Int32>
            let encryptedData = NSData(base64Encoded: data, options:[]) ?? nil

            if(encryptedData == nil || encryptedData!.length % 4 != 0){
                result(
                    FlutterError(
                        code: "ERROR_INVALID_ENCRYPTED_DATA",
                        message: "the data should be a valid base64 string with length at multiple of 128 bits",
                        details: nil
                    )
                )
                return
            }

            var plaintext = "";
            do {
                let aes = try AES(
                    key: keyArray,
                    blockMode: CBC(iv: ivArray),
                    padding: .pkcs7
                )

                plaintext = try String(bytes: (encryptedData! as Data).decrypt(cipher: aes), encoding: String.Encoding.utf8)!
            } catch {
                result(FlutterError(code: "ERROR_INVALID_CRYPTO_OPERATION", message: "error", details: nil))
            }

            result(plaintext)
        }
    }

    private func encryptAesGcm128(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let p = TestedParams.fromCall(call)
        switch p {
        case .error(let error):
            result(error)
            return

        case .params(let args):
            let data = args["data"]!
            let key = args["key"]!
            let iv = args["nonce"]!

            //let dataArray = Array(data.utf8)
            // let keyArray = Array(key.utf8)
            let ivArray = Array(iv.utf8)
            var additionalData: Array<UInt8>? = nil

            if let additionalDataStr = args["additional_data"] {
                if let additionalDataRaw = Data(base64Encoded: additionalDataStr) {
                    additionalData = additionalDataRaw.bytes
                }
            }

            do {
                let gcm = GCM(iv: ivArray, additionalAuthenticatedData: additionalData, mode: .combined)
                let aes = try AES(key: Data(base64Encoded: key)!.bytes, blockMode: gcm, padding: .noPadding)
                let encrypted = try aes.encrypt(Data(base64Encoded: data)!.bytes)
                let tag = gcm.authenticationTag

                let encoder = JSONEncoder()

                let jsonData = try encoder.encode([
                    "data": Data(bytes: encrypted).base64EncodedString(),
                    "tag": Data(bytes: tag!).base64EncodedString()
                ])

                result(String(bytes: jsonData, encoding: .utf8))
            } catch {
                result(FlutterError(code: "ERROR_INVALID_CRYPTO_OPERATION", message: "error", details: nil))
            }
        }
    }

    private func decryptAesGcm128(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch TestedParams.fromCall(call) {
        case .error(let error):
            result(error)
            return

        case .params(let args):
            let data = args["data"]!
            let key = args["key"]!
            let iv = args["nonce"]!

            let keyArray = Array(key.utf8)
            let ivArray = Array(iv.utf8)

            let encryptedData = NSData(base64Encoded: data, options:[]) ?? nil

            var additionalData: Array<UInt8>? = nil

            if let additionalDataStr = args["additional_data"] {
                if let additionalDataRaw = Data(base64Encoded: additionalDataStr) {
                    additionalData = additionalDataRaw.bytes
                }
            }

            if (encryptedData == nil) {
                result(
                    FlutterError(
                        code: "ERROR_INVALID_ENCRYPTED_DATA",
                        message: "the data should be a valid base64 string with length at multiple of 128 bits",
                        details: nil
                    )
                )
                return
            }

            do {
                let gcm = GCM(iv: ivArray, additionalAuthenticatedData: additionalData, mode: .combined)
                let aes = try AES(key: keyArray, blockMode: gcm, padding: .noPadding)
                let res = try (encryptedData! as Data).decrypt(cipher: aes)

                result(String(bytes: res, encoding: .utf8))
            } catch {
                print(error);
                result(FlutterError(code: "ERROR_INVALID_CRYPTO_OPERATION", message: "error", details: nil))
            }
        }
    }

    private func generateNonce(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        result(Nonce(length: 12).data.base64EncodedString(options: []))
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "Encrypt_AesCbc128Padding7":
            encryptAesCbc128Padding7(call, result: result)

        case "Decrypt_AesCbc128Padding7":
            decryptAesCbc128Padding7(call, result: result)

        case "Encrypt_AesGcm128":
            encryptAesGcm128(call, result: result)

        case "Decrypt_AesGcm128":
            decryptAesGcm128(call, result: result)

        case "Generate_Nonce":
            generateNonce(call, result: result)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

}
