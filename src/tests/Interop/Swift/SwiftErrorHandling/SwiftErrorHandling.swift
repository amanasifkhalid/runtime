// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
import Foundation

public enum MyError: Error {
    case runtimeError
}

public func conditionallyThrowError(willThrow: Bool) throws -> Int {
    if willThrow {
        print("Throwing")
        throw MyError.runtimeError
    } else {
        return 42
    }
}