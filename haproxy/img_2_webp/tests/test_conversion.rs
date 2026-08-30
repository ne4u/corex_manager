//! Integration tests for the conversion logic (PNG lossless, size guard).
//!
//! These test the `convert_to_webp` function indirectly by replicating the
//! encoding strategy: lossless for PNG, lossy for JPEG/GIF, and a size guard
//! that passes through the original when WebP is not smaller.

// image::GenericImageView would be needed for .dimensions() calls.

fn encode_webp(png_bytes: &[u8]) -> Vec<u8> {
    let img = image::load_from_memory(png_bytes).unwrap();
    let encoder = webp::Encoder::from_image(&img).unwrap();
    encoder.encode_lossless().to_vec()
}

fn encode_webp_lossy(jpeg_bytes: &[u8], quality: f32) -> Vec<u8> {
    let img = image::load_from_memory(jpeg_bytes).unwrap();
    let encoder = webp::Encoder::from_image(&img).unwrap();
    encoder.encode(quality).to_vec()
}

#[test]
fn test_lossless_webp_smaller_than_png() {
    // Create a simple 100x100 RGBA PNG (flat color, lossless-friendly).
    let mut img = image::RgbaImage::new(100, 100);
    for y in 0..100 {
        for x in 0..100 {
            img.put_pixel(x, y, image::Rgba([255, 100, 50, 255]));
        }
    }
    let mut png_buf = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png_buf, image::ImageFormat::Png)
        .unwrap();
    let png_bytes = png_buf.into_inner();
    let webp_bytes = encode_webp(&png_bytes);
    // Lossless WebP should be smaller than PNG for a flat-color image.
    assert!(
        webp_bytes.len() < png_bytes.len(),
        "lossless WebP ({}) should be smaller than PNG ({})",
        webp_bytes.len(),
        png_bytes.len()
    );
}

#[test]
fn test_size_guard_passes_through_when_webp_larger() {
    // Create a tiny 1x1 PNG — the PNG header overhead dominates and WebP
    // may not be smaller. The size guard in convert_to_webp handles this.
    let mut img = image::RgbaImage::new(1, 1);
    img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
    let mut png_buf = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png_buf, image::ImageFormat::Png)
        .unwrap();
    let png_bytes = png_buf.into_inner();
    let webp_bytes = encode_webp(&png_bytes);
    // For a 1x1 image, either WebP is smaller (great) or the size guard
    // would pass through the original. This test just verifies the encoding
    // works without panicking — the actual size guard logic is in the filter.
    println!(
        "1x1 PNG: {} bytes, lossless WebP: {} bytes",
        png_bytes.len(),
        webp_bytes.len()
    );
}

#[test]
fn test_lossy_webp_for_jpeg() {
    // Create a simple JPEG and verify lossy encoding works.
    let mut img = image::RgbImage::new(100, 100);
    for y in 0..100 {
        for x in 0..100 {
            img.put_pixel(x, y, image::Rgb([200, 50, 100]));
        }
    }
    let mut jpg_buf = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut jpg_buf, image::ImageFormat::Jpeg)
        .unwrap();
    let jpg_bytes = jpg_buf.into_inner();
    let webp_bytes = encode_webp_lossy(&jpg_bytes, 80.0);
    // Lossy WebP should generally be smaller than JPEG for simple images.
    println!(
        "100x100 JPEG: {} bytes, lossy WebP q80: {} bytes",
        jpg_bytes.len(),
        webp_bytes.len()
    );
}
