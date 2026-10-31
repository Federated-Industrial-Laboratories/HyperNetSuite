// SPDX-License-Identifier: MIT
// Finite local presentation effects; this module has no transport or action interface.
use crate::{
    markup::{Colour, Effect, Preset},
    page_layout::{Layout, Visual},
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
#[derive(Clone)]
struct Running {
    effect: Effect,
    started: Instant,
}
#[derive(Clone, Default)]
pub struct State {
    active: BTreeMap<usize, Running>,
    last_paint: Option<Instant>,
}
impl State {
    pub fn pause(&mut self) {
        self.active.clear();
        self.last_paint = None;
    }
    pub fn running(&self) -> bool {
        !self.active.is_empty()
    }
    pub fn toggle(&mut self, layout: &Layout, offset: usize, rows: usize, now: Instant) {
        if self.running() {
            self.pause();
            return;
        }
        for visual in &layout.visuals {
            if visible(visual, offset, rows)
                && let Some(effect) = visual.effect
            {
                self.start(visual.key, effect, now);
            }
        }
    }
    fn start(&mut self, key: usize, effect: Effect, now: Instant) {
        if self.active.len() < 8 && !self.active.contains_key(&key) {
            self.active.insert(
                key,
                Running {
                    effect,
                    started: now,
                },
            );
        }
    }
    pub fn target(
        &mut self,
        layout: &Layout,
        target: &str,
        running: bool,
        offset: usize,
        rows: usize,
        now: Instant,
    ) -> bool {
        if let Some(visual) = layout
            .visuals
            .iter()
            .find(|v| v.id.as_deref() == Some(target))
        {
            if running && visible(visual, offset, rows) {
                if let Some(effect) = visual.effect {
                    self.start(visual.key, effect, now)
                }
            } else {
                self.active.remove(&visual.key);
            }
            return self.active.contains_key(&visual.key);
        }
        false
    }
    pub fn sync(&mut self, layout: &Layout, offset: usize, rows: usize, now: Instant) -> bool {
        let before = self.active.len();
        self.active.retain(|key, r| {
            now.saturating_duration_since(r.started)
                < Duration::from_millis(u64::from(r.effect.duration_ms))
                && layout
                    .visuals
                    .iter()
                    .any(|v| v.key == *key && visible(v, offset, rows))
        });
        before != self.active.len()
    }
    pub fn due(&self, now: Instant, bitmap: bool) -> bool {
        self.running()
            && self.last_paint.is_none_or(|at| {
                now.saturating_duration_since(at)
                    >= Duration::from_millis(if bitmap { 500 } else { 100 })
            })
    }
    pub fn can_paint(&self, now: Instant) -> bool {
        !self.running()
            || self
                .last_paint
                .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_millis(100))
    }
    pub fn painted(&mut self, now: Instant) {
        self.last_paint = Some(now)
    }
    pub fn phase(&self, key: usize, now: Instant) -> Option<(Preset, f32)> {
        self.active.get(&key).and_then(|r| {
            let p = now.saturating_duration_since(r.started).as_secs_f32()
                / (f32::from(r.effect.duration_ms) / 1000.);
            (p < 1.).then_some((r.effect.preset, p))
        })
    }
    pub fn apply(&self, layout: &mut Layout, now: Instant) {
        for visual in &layout.visuals {
            let Some((preset, phase)) = self.phase(visual.key, now) else {
                continue;
            };
            if visual.asset.is_some() {
                continue;
            }
            for y in visual.top.max(0)..visual.bottom.max(0) {
                let Some(line) = layout.lines.get_mut(y as usize) else {
                    continue;
                };
                let start = visual.x.max(0) as usize;
                let end = (start + visual.width).min(line.cells.len());
                if start >= end {
                    continue;
                }
                if preset == Preset::TextScroll {
                    let shift = ((phase * std::f32::consts::PI).sin() * ((end - start) / 3) as f32)
                        as usize;
                    if shift > 0 {
                        let saved = line.cells[start..end].to_vec();
                        for (index, cell) in line.cells[start..end].iter_mut().enumerate() {
                            if let Some(source) = saved.get(index + shift) {
                                *cell = source.clone()
                            } else {
                                cell.text = " ".into();
                                cell.continuation = false;
                            }
                        }
                        // A partially clipped wide grapheme becomes a blank cell.
                        if line.cells[start].continuation {
                            line.cells[start].text = " ".into();
                            line.cells[start].continuation = false;
                        }
                    }
                }
                for (index, cell) in line.cells[start..end].iter_mut().enumerate() {
                    let accent = (phase * std::f32::consts::PI * 2.).sin() > 0.35;
                    match preset {
                        Preset::ColourPulse => {
                            if accent {
                                cell.style.bold = true;
                                cell.style.colour = Some(Colour::BrightCyan)
                            }
                        }
                        Preset::TextFade => cell.style.bold = accent,
                        Preset::BorderEmphasis => {
                            if accent
                                && let Some(border) = cell.border.filter(|b| b.key == visual.key)
                            {
                                cell.style.bold = true;
                                cell.style.colour =
                                    Some(if cell.style.colour == Some(Colour::BrightCyan) {
                                        Colour::BrightYellow
                                    } else {
                                        Colour::BrightCyan
                                    });
                                cell.text = border.glyph(true).into();
                            }
                        }
                        Preset::ProgressSweep
                            if cell.text == "#"
                                && index.abs_diff((phase * (end - start) as f32) as usize) < 3 =>
                        {
                            cell.style.colour = Some(Colour::BrightCyan);
                            cell.style.bold = true
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
pub fn visible(v: &Visual, offset: usize, rows: usize) -> bool {
    v.top.max(offset as i64) < v.bottom.min((offset + rows) as i64)
}
#[cfg(test)]
#[path = "../../Tests/Unit/Presentation/MotionUnitTests.rs"]
mod tests;
