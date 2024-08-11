//
//  KeychainManager.swift
//  Telegraph
//
//  Created by Yvo van Beek on 1/26/17.
//  Copyright © 2017 Building42. All rights reserved.
//

import Foundation
import Security

public class KeychainManager {
  public static let shared = KeychainManager()
  public var accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

  public typealias KeychainClass = CFString
  public typealias KeychainValue = AnyObject
  public typealias KeychainQuery = [NSString: AnyObject]
}

// MARK: PKCS12 methods

public extension KeychainManager {
  /// Imports the PKCS12 data into the keychain.
  func importPKCS12(data: Data, passphrase: String, options: KeychainQuery = KeychainQuery()) -> SecIdentity? {
    var query = options
    query[kSecImportExportPassphrase] = passphrase as NSString

    print("Attempting to import PKCS12 data with passphrase: \(passphrase)")

    var importResult: CFArray?
    let status = withUnsafeMutablePointer(to: &importResult) { SecPKCS12Import(data as NSData, query as CFDictionary, $0) }

    print("SecPKCS12Import status: \(status)")

    guard status == errSecSuccess else {
      print("Error importing PKCS12 data: \(status)")
      return nil
    }

    guard let importArray = importResult as? [[NSString: AnyObject]] else {
      print("Failed to cast importResult to expected type")
      return nil
    }

    print("Import result array: \(importArray)")

    let importIdentity = importArray.compactMap { dict in
      dict[kSecImportItemIdentity as NSString]
    }.first

    guard let rawResult = importIdentity, CFGetTypeID(rawResult) == SecIdentityGetTypeID() else {
      print("No valid SecIdentity found in the import result")
      return nil
    }

    let result = rawResult as! SecIdentity
    print("Successfully imported SecIdentity: \(result)")

    return result
  }
}

// MARK: Query methods

public extension KeychainManager {
  /// Adds a value to the keychain.
  func add(value: KeychainValue, label: String, options: KeychainQuery = KeychainQuery()) throws {
    // Don't specify kSecClass otherwise SecItemCopyMatching won't be able to find identities
    var query = options
    query[kSecAttrLabel] = label as NSString
    query[kSecAttrAccessible] = accessibility
    query[kSecValueRef] = value

    print("Adding value to keychain with label: \(label)")

    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) { SecItemAdd(query as CFDictionary, $0) }

    print("SecItemAdd status: \(status)")

    if status != errSecSuccess {
      print("Error adding value to keychain: \(status)")
      throw KeychainError(code: status)
    } else {
      print("Successfully added value to keychain")
    }
  }

  /// Finds an item in the keychain.
  func find<T>(_ kClass: KeychainClass, label: String, options: KeychainQuery = KeychainQuery()) throws -> T {
    var query = options
    query[kSecClass] = kClass
    query[kSecAttrLabel] = label as NSString
    query[kSecReturnRef] = kCFBooleanTrue

    print("Finding item in keychain with label: \(label)")

    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) { SecItemCopyMatching(query as CFDictionary, $0) }

    print("SecItemCopyMatching status: \(status)")

    if status != errSecSuccess && status != errSecItemNotFound {
      print("Error finding item in keychain: \(status)")
      throw KeychainError(code: status)
    }

    guard let item = result else {
      print("Item not found in keychain")
      throw KeychainError.itemNotFound
    }

    guard let typedItem = item as? T else {
      print("Found item but failed to cast to expected type")
      throw KeychainError.invalidResult
    }

    print("Successfully found item in keychain: \(typedItem)")

    return typedItem
  }

  /// Removes an item from the keychain.
  func remove(_ kClass: KeychainClass, label: String, options: KeychainQuery = KeychainQuery()) throws {
    var query = options
    query[kSecClass] = kClass
    query[kSecAttrLabel] = label as NSString

    print("Removing item from keychain with label: \(label)")

    let status = SecItemDelete(query as CFDictionary)

    print("SecItemDelete status: \(status)")

    if status != errSecSuccess {
      print("Error removing item from keychain: \(status)")
      throw KeychainError(code: status)
    } else {
      print("Successfully removed item from keychain")
    }
  }
}
