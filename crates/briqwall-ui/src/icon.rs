//! Procedurally drawn tray icons (colored shield with check mark), so the
//! protection state is visible at a glance in the notification area.

pub fn shield_rgba(size: u32, fill: [u8; 3], mark: bool) -> Vec<u8> {
    let n = size as f32;
    let mut out = vec![0u8; (size * size * 4) as usize];
    let ss = 4;
    for py in 0..size {
        for px in 0..size {
            let (mut cover, mut check) = (0.0f32, 0.0f32);
            for sy in 0..ss {
                for sx in 0..ss {
                    let x = (px as f32 + (sx as f32 + 0.5) / ss as f32) / n * 2.0 - 1.0;
                    let y = (py as f32 + (sy as f32 + 0.5) / ss as f32) / n;
                    if inside_shield(x, y) {
                        cover += 1.0;
                        if mark && on_check(x, y) {
                            check += 1.0;
                        }
                    }
                }
            }
            let total = (ss * ss) as f32;
            let a = cover / total;
            if a > 0.0 {
                let c = (check / total) / a;
                let i = ((py * size + px) * 4) as usize;
                for k in 0..3 {
                    out[i + k] = (fill[k] as f32 * (1.0 - c) + 255.0 * c).round() as u8;
                }
                out[i + 3] = (a * 255.0).round() as u8;
            }
        }
    }
    out
}

fn inside_shield(x: f32, y: f32) -> bool {
    let w = 0.82;
    if !(0.06..=0.97).contains(&y) {
        return false;
    }
    let top = 0.06 + 0.06 * (1.0 - x.abs() / w).max(0.0);
    if y < top {
        return false;
    }
    if y < 0.52 {
        x.abs() <= w
    } else {
        let t = (y - 0.52) / 0.45;
        x.abs() <= w * (1.0 - t * t).max(0.0).sqrt()
    }
}

fn on_check(x: f32, y: f32) -> bool {
    seg(x, y, (-0.36, 0.50), (-0.08, 0.72)).min(seg(x, y, (-0.08, 0.72), (0.40, 0.30))) < 0.085
}

fn seg(x: f32, y: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (px, py, bx, by) = (x - a.0, y - a.1, b.0 - a.0, b.1 - a.1);
    let t = ((px * bx + py * by) / (bx * bx + by * by)).clamp(0.0, 1.0);
    ((px - bx * t).powi(2) + (py - by * t).powi(2)).sqrt()
}
