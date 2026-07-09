// Screen capture → JPEG. Origin is assumed (0,0) (primary/single monitor);
// dimensions come from a real capture so coordinate mapping stays exact.
use image::codecs::jpeg::JpegEncoder;
use xcap::Monitor;

pub struct Grabber {
    pub index: usize,
}

impl Grabber {
    fn monitor(&self) -> Option<Monitor> {
        Monitor::all()
            .ok()?
            .into_iter()
            .nth(self.index)
            .or_else(|| Monitor::all().ok().and_then(|m| m.into_iter().next()))
    }

    pub fn grab_jpeg(&self, quality: u8, max_width: u32) -> Option<Vec<u8>> {
        let img = self.monitor()?.capture_image().ok()?; // RgbaImage
        let mut rgb = image::DynamicImage::ImageRgba8(img).to_rgb8();
        if max_width > 0 && rgb.width() > max_width {
            let h = rgb.height() * max_width / rgb.width();
            rgb = image::imageops::resize(&rgb, max_width, h, image::imageops::FilterType::Triangle);
        }
        let (w, h) = (rgb.width(), rgb.height());
        let mut out = Vec::new();
        let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
        enc.encode(rgb.as_raw(), w, h, image::ExtendedColorType::Rgb8).ok()?;
        Some(out)
    }

    /// (origin_x, origin_y, width, height) — origin assumed 0,0.
    pub fn geometry(&self) -> (i32, i32, u32, u32) {
        match self.monitor().and_then(|m| m.capture_image().ok()) {
            Some(img) => (0, 0, img.width(), img.height()),
            None => (0, 0, 1920, 1080),
        }
    }
}
