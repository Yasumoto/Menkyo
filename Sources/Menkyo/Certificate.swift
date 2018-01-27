//
//  Certificate.swift
//  CertificateViewer
//
//  Created by Joe Smith on 8/1/17.
//
//

import Foundation

public enum SubjectAttributes: String {
    case commonName = "CN"
    case country = "C"
    case organization = "O"
    case locality = "L"
    case state = "ST"
    case organizationalUnit = "OU"
    case description = "description"
    case emailAddress = "emailAddress"
    case uid = "UID"
}

public struct Certificate {
    public let subjectSummary: String?
    public let issuer: [SubjectAttributes:String]?
    public let issuerAltName: [String]?
    public let subjectName: [SubjectAttributes:String]?
    public let alternateNames: [String]?
    public let notBefore: Date?
    public let notAfter: Date?

    public var valid: Bool? {
        var valid = false
        let now = Date()
        if let notAfter = self.notAfter {
            if now > notAfter {
                return false
            } else {
                valid = true
            }
        }
        if let notBefore = self.notBefore {
            if now < notBefore {
                return false
            } else if valid == true {
                return true
            }
        }
        return nil
    }
}
