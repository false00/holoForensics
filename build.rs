use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use ico::{IconDir, IconDirEntry, IconImage, ResourceType};
use resvg::{tiny_skia, usvg};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/holoForensicsLogo.svg");

    slint_build::compile("ui/app_window.slint").expect("compile Slint UI");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let icon_path = generate_windows_icon(Path::new("assets/holoForensicsLogo.svg"))
            .expect("generate Windows icon");

        let mut resource = winres::WindowsResource::new();
        resource.set_icon(
            icon_path
                .to_str()
                .expect("generated icon path should be valid UTF-8"),
        );
        resource.set("FileDescription", "Holo Forensics Collector");
        resource.set("ProductName", "Holo Forensics Collector");
        resource.set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="Holo.Forensics.Collector" type="win32"/>
  <description>Holo Forensics Collector</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>"#,
        );
        resource
            .compile()
            .expect("compile Windows executable resources");
    }
}

fn generate_windows_icon(svg_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let svg = fs::read(svg_path)?;
    let tree = usvg::Tree::from_data(&svg, &usvg::Options::default())?;

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is not set"))?,
    );
    let icon_path = out_dir.join("holoForensicsLogo.generated.ico");
    let mut icon_dir = IconDir::new(ResourceType::Icon);

    for size in [16, 20, 24, 32, 40, 48, 64, 128, 256] {
        let image = IconImage::from_rgba_data(size, size, render_svg_rgba(&tree, size)?);
        icon_dir.add_entry(IconDirEntry::encode(&image)?);
    }

    let file = File::create(&icon_path)?;
    icon_dir.write(BufWriter::new(file))?;
    Ok(icon_path)
}

fn render_svg_rgba(tree: &usvg::Tree, size: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pixmap = tiny_skia::Pixmap::new(size, size)
        .ok_or_else(|| io::Error::other(format!("allocate {size}x{size} icon pixmap")))?;

    let svg_size = tree.size();
    let scale = (size as f32 / svg_size.width()).min(size as f32 / svg_size.height());
    let tx = (size as f32 - svg_size.width() * scale) * 0.5;
    let ty = (size as f32 - svg_size.height() * scale) * 0.5;
    let transform = tiny_skia::Transform::from_scale(scale, scale).post_translate(tx, ty);

    let mut pixmap_mut = pixmap.as_mut();
    resvg::render(tree, transform, &mut pixmap_mut);

    Ok(pixmap.take_demultiplied())
}
