#!/usr/bin/env swift
// Draws the application mark at every size the .appiconset asks for.
//
// Run it from the repository root:
//     swift scripts/make-icon.swift
//
// The mark is a shield on a blue field, with a node-and-link diagram cut out
// of it: the application draws a diagram and scores what threatens it.

import AppKit

let sizes: [(name: String, pixels: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024)
]

func draw(pixels: Int) -> Data? {
    guard let context = CGContext(
        data: nil,
        width: pixels,
        height: pixels,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else { return nil }

    let side = CGFloat(pixels)
    let unit = side / 1024

    // The rounded field macOS expects behind a mark.
    let inset = 92 * unit
    let field = CGRect(x: inset, y: inset, width: side - inset * 2, height: side - inset * 2)
    let fieldPath = CGPath(
        roundedRect: field,
        cornerWidth: 180 * unit,
        cornerHeight: 180 * unit,
        transform: nil
    )
    context.saveGState()
    context.addPath(fieldPath)
    context.clip()
    let gradient = CGGradient(
        colorsSpace: CGColorSpace(name: CGColorSpace.sRGB)!,
        colors: [
            CGColor(red: 0.16, green: 0.38, blue: 0.78, alpha: 1),
            CGColor(red: 0.07, green: 0.19, blue: 0.45, alpha: 1)
        ] as CFArray,
        locations: [0, 1]
    )!
    context.drawLinearGradient(
        gradient,
        start: CGPoint(x: field.minX, y: field.maxY),
        end: CGPoint(x: field.maxX, y: field.minY),
        options: []
    )
    context.restoreGState()

    // The shield.
    let shield = CGMutablePath()
    let top = CGPoint(x: side / 2, y: 812 * unit)
    let halfWidth = 236 * unit
    shield.move(to: top)
    shield.addLine(to: CGPoint(x: top.x + halfWidth, y: top.y - 128 * unit))
    shield.addLine(to: CGPoint(x: top.x + halfWidth, y: 420 * unit))
    shield.addCurve(
        to: CGPoint(x: top.x, y: 212 * unit),
        control1: CGPoint(x: top.x + halfWidth, y: 300 * unit),
        control2: CGPoint(x: top.x + 130 * unit, y: 236 * unit)
    )
    shield.addCurve(
        to: CGPoint(x: top.x - halfWidth, y: 420 * unit),
        control1: CGPoint(x: top.x - 130 * unit, y: 236 * unit),
        control2: CGPoint(x: top.x - halfWidth, y: 300 * unit)
    )
    shield.addLine(to: CGPoint(x: top.x - halfWidth, y: top.y - 128 * unit))
    shield.closeSubpath()

    context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.94))
    context.addPath(shield)
    context.fillPath()

    // The diagram inside it: three nodes and two links.
    context.setStrokeColor(CGColor(red: 0.07, green: 0.19, blue: 0.45, alpha: 1))
    context.setLineWidth(26 * unit)
    context.setLineCap(.round)
    let nodes = [
        CGPoint(x: side / 2, y: 640 * unit),
        CGPoint(x: side / 2 - 118 * unit, y: 430 * unit),
        CGPoint(x: side / 2 + 118 * unit, y: 430 * unit)
    ]
    context.move(to: nodes[0])
    context.addLine(to: nodes[1])
    context.move(to: nodes[0])
    context.addLine(to: nodes[2])
    context.strokePath()

    context.setFillColor(CGColor(red: 0.07, green: 0.19, blue: 0.45, alpha: 1))
    for node in nodes {
        let radius = 52 * unit
        context.fillEllipse(
            in: CGRect(
                x: node.x - radius,
                y: node.y - radius,
                width: radius * 2,
                height: radius * 2
            )
        )
    }

    guard let image = context.makeImage() else { return nil }
    return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
}

let directory = "threatmodeller/Assets.xcassets/AppIcon.appiconset"
for size in sizes {
    guard let data = draw(pixels: size.pixels) else {
        print("could not draw \(size.name)")
        exit(1)
    }
    let path = "\(directory)/\(size.name).png"
    try data.write(to: URL(fileURLWithPath: path))
    print("wrote \(path)")
}
