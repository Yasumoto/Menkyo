//
//  Certificate.swift
//  CertificateViewer
//
//  Created by Joseph Mehdi Smith on 8/1/17.
//
//

import Foundation

enum SubjectAttributes: String {
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

struct Certificate {
    let subjectSummary: String?
    let issuer: [SubjectAttributes:String]?
    let issuerAltName: [String]?
    let subjectName: [SubjectAttributes:String]?
    let alternateNames: [String]?
    let notBefore: Date?
    let notAfter: Date?

    var valid: Bool? {
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
