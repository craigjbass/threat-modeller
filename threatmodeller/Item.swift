//
//  Item.swift
//  threatmodeller
//
//  Created by Craig J. Bass on 07/09/2026.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
