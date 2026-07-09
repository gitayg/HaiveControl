// Screen capture → JPEG. Origin is assumed (0,0) (primary/single monitor);
// dimensions come from a real capture so coordinate mapping stays exact.
use image::codecs::jpeg::JpegEncoder;
use xcap::Monitor;

#[derive(Clone)]
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

/// Grab a single frame from the given camera index → JPEG. Grabs a few frames
/// first so the camera has time to auto-expose (the first frame is often dark).
pub fn open_camera(index: u32) -> Option<nokhwa::Camera> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
    use nokhwa::Camera;
    let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut cam = Camera::new(CameraIndex::Index(index), requested).ok()?;
    cam.open_stream().ok()?;
    for _ in 0..3 {
        let _ = cam.frame(); // warm up (first frames are often dark)
    }
    Some(cam)
}

/// One frame from an already-open camera → JPEG. MJPEG frames are already JPEG
/// (returned as-is, avoiding the mozjpeg decoder); others decode in pure Rust.
pub fn frame_to_jpeg(cam: &mut nokhwa::Camera, quality: u8) -> Option<Vec<u8>> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::FrameFormat;
    let frame = cam.frame().ok()?;
    if frame.source_frame_format() == FrameFormat::MJPEG {
        return Some(frame.buffer().to_vec());
    }
    let img = frame.decode_image::<RgbFormat>().ok()?;
    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgb8).ok()?;
    Some(out)
}

pub fn camera_snapshot(index: u32, quality: u8) -> Option<Vec<u8>> {
    let mut cam = open_camera(index)?;
    for _ in 0..3 {
        let _ = cam.frame();
    }
    frame_to_jpeg(&mut cam, quality)
}
