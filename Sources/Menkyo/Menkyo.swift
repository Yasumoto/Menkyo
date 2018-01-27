//
//  Menkyo.swift
//  CertificateViewer
//
// Menkyo is Japanese for License or most appropriately, Certificate 🔐.
// This wraps the OpenSSL library and returns a struct with information
// used to describe a certificate's attributes.
//
//  Created by Joe Smith on 7/18/17.
//

import Foundation
import CTLS

/**
 * Find all certificates in a dictionary and use OpenSSL to parse them
 */
public func enumerateCertificates(baseDirectory: String) -> [String:Certificate] {
    var infos = [String: Certificate]()
    let enumerator = FileManager.default.enumerator(atPath: baseDirectory)
    while true {
        if let fileName = enumerator?.nextObject() as? String {
            let fullPath = "\(baseDirectory)/\(fileName)"
            if fullPath.contains(".crt") || fullPath.contains(".pem") {
                if let certContents = readCert(pathName: fullPath) {
                    let subjectName = retrieveSubjectName(cert: certContents)
                    let sans = retrieveSubjectAltNames(cert: certContents)
                    let issuerAlternativeName = retrieveIssuerAlternativeName(cert: certContents)
                    let issuer = retrieveIssuerName(cert: certContents)
                    let (notBefore, notAfter) = parseExpiryDates(cert: certContents)
                    infos[fullPath] = Certificate(subjectSummary: "",
                                                  issuer: issuer,
                                                  issuerAltName: issuerAlternativeName,
                                                  subjectName: subjectName,
                                                  alternateNames: sans,
                                                  notBefore: notBefore,
                                                  notAfter: notAfter)
                }
            }
        } else {
            break
        }
    }
    return infos
}

/**
 *
 * Based on
 * https://kahdev.wordpress.com/2008/11/23/a-certificates-subject-issuer-and-its-keyusage/
 */
func parseX509Name(name: UnsafeMutablePointer<X509_NAME>) -> [SubjectAttributes:String] {
    var attributes = [SubjectAttributes: String]()
    if let io = BIO_new(BIO_s_mem()) {
        X509_NAME_print_ex(io, name, 0, UInt(XN_FLAG_SEP_MULTILINE))
        var stringPointer: UnsafeMutableRawPointer? = nil
        _ = BIO_ctrl(io, BIO_CTRL_INFO, 0, &stringPointer)
        if let pointer = stringPointer?.assumingMemoryBound(to: CChar.self) {
            let name = String(cString: pointer)
            for element in name.components(separatedBy: "\n") {
                let components = element.components(separatedBy: "=")
                if components.count == 2 {
                    let field = components[0]
                    let value = components[1]
                    if let attribute = SubjectAttributes(rawValue: field) {
                        attributes[attribute] = value
                    } else {
                        print("Unknown attribute on cert: \(element)")
                    }
                } else {
                    print("Unable to pase subjectName: \(element)")
                }

            }
        }
    }
    return attributes
}

/*
 * Read the valid-from and expiration dates for a certificate
 *
 * Formatting from https://www.openssl.org/docs/man1.1.0/crypto/ASN1_TIME_set_string.html
 *
 */
func parseExpiryDates(cert: UnsafeMutablePointer<X509>) -> (Date?, Date?) {
    func readDate(asnTime: UnsafePointer<ASN1_TIME>) -> Date? {
        var stringPointer: UnsafeMutableRawPointer? = nil
        if let bufferIO = BIO_new(BIO_s_mem()) {
            if asnTime.pointee.type == V_ASN1_UTCTIME {
                _ = ASN1_TIME_print(bufferIO, asnTime)
                _ = BIO_ctrl(bufferIO, BIO_CTRL_INFO, 0, &stringPointer)
                if let pointer = stringPointer?.assumingMemoryBound(to: CChar.self) {
                    var timestamp = String(cString: pointer)
                    while timestamp.contains("GMT") {
                        var components = timestamp.components(separatedBy: " ")
                        components.removeLast()
                        timestamp = components.joined(separator: " ")
                    }
                    let formatter = DateFormatter()
                    formatter.locale = Locale(identifier: "en_US_POSIX")
                    formatter.dateFormat = "MMM d HH:mm:ss yyyy"
                    if let parsedDate = formatter.date(from: timestamp) {
                        return parsedDate
                    }
                    print("******** Couldn't read \(timestamp)")
                }
            } else if asnTime.pointee.type == V_ASN1_GENERALIZEDTIME {
                print("ASN1 Generalized Time parsing unsupported")
            } else {
                print("ASN Time format type unknown")
            }
        }
        return nil
    }
    let notBefore = readDate(asnTime: cert.pointee.cert_info.pointee.validity.pointee.notBefore)
    let notAfter = readDate(asnTime: cert.pointee.cert_info.pointee.validity.pointee.notAfter)
    return (notBefore, notAfter)
}

/**
 *
 * This is based off the C version of
 * https://kahdev.wordpress.com/2008/11/29/stack_of-subject-alternate-name-and-extended-key-usage-extensions/
 *
 * - cert: X509 certificate
 * - nid: Something like `NID_subject_alt_name`
 * - nameType: Something like `GEN_DNS`
 */
func parseExtensionNames(cert: UnsafeMutablePointer<X509>, nid: Int32, nameType: Int32) -> [String] {
    var extensionNames = [String]()
    if let rawNames = X509_get_ext_d2i(cert, nid, nil, nil) {
        let names = rawNames.assumingMemoryBound(to: _STACK.self)
        let nameCount = sk_num(names) // Know how many elements are present in the cert

        var count = 0
        while count < nameCount {
            if let rawName = sk_pop(names) {
                let name = rawName.assumingMemoryBound(to: GENERAL_NAME.self)
                if name.pointee.type == nameType {
                    if let san = ASN1_STRING_data(name.pointee.d.uniformResourceIdentifier) {
                        let altName = String(cString: san)
                        extensionNames.append(altName)
                    }
                }
            }
            count += 1
        }
    }
    return extensionNames
}

func retrieveSubjectName(cert: UnsafeMutablePointer<X509>) -> [SubjectAttributes:String]? {
    if let subjectName = X509_get_subject_name(cert) {
        return parseX509Name(name: subjectName)
    }
    return nil
}

/**
 *  Find the issuing CA of an X509 certificate
 */
func retrieveIssuerName(cert: UnsafeMutablePointer<X509>) -> [SubjectAttributes:String]? {
    if let issuerName = X509_get_issuer_name(cert) {
        return parseX509Name(name: issuerName)
    }
    return nil
}

/**
 *  Retrieve the "alternative" name for an issuer
 *
 *  https://tools.ietf.org/html/rfc3280.html#section-4.2.1.8
 */
func retrieveIssuerAlternativeName(cert: UnsafeMutablePointer<X509>) -> [String] {
    return parseExtensionNames(cert: cert, nid: NID_issuer_alt_name, nameType: GEN_URI)
}

/**
 *  Retrieve other names this certificate is valid for
 */
func retrieveSubjectAltNames(cert: UnsafeMutablePointer<X509>) -> [String] {
    return parseExtensionNames(cert: cert, nid: NID_subject_alt_name, nameType: GEN_DNS)
}

func readCert(pathName: String) -> UnsafeMutablePointer<X509>? {
    do {
        let fileHandle = try FileHandle(forReadingFrom: URL(fileURLWithPath: pathName))
        let file = fdopen(fileHandle.fileDescriptor, "r")
        var cert: UnsafeMutablePointer<X509>?
        let certificate = PEM_read_X509(file, &cert, nil, nil)
        fclose(file)
        fileHandle.closeFile()
        if let certificateData = certificate {
            return certificateData
        }
    } catch {
        print("Problem reading file: \(error)")
    }

    return nil
}
