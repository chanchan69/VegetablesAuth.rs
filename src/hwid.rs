use std::process::Command;

#[cfg(target_os = "linux")]
pub fn get_id() -> std::string::String {
    std::fs::read_to_string("/var/lib/dbus/machine-id").unwrap()
}

#[cfg(target_os = "windows")]
pub fn get_id() -> std::string::String {
    let output = Command::new("cmd")
        .args(&["/C", "wmic csproduct get uuid"])
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&output.stdout);
    let u = output.split("\n");
    let u: Vec<&str> = u.collect();
    let mut p = u.into_iter();
    let h = p.nth(1).unwrap_or_default().to_string();
    h[..h.len() - 4].to_string()
}
