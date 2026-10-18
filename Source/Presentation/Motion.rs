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
mod tests {
    use super::*;
    #[test]
    fn targeted_border_emphasis_changes_generated_glyphs_and_preserves_content() {
        for border in ["Light", "Heavy", "Double", "Rounded", "Ascii"] {
            for ascii in [false, true] {
                let d = crate::markup::parse(&format!(
                    "HyperNetPage/2\n# Border\n@Panel {{\"id\":\"Greenhouse\",\"label\":\"A-B + ─ 世界\",\"colour\":\"BrightCyan\",\"border\":\"{border}\",\"motion\":{{\"preset\":\"BorderEmphasis\",\"durationMs\":1000}}}}\n: Keep A-B + | ─ ╬ unchanged\n@Separator {{}}\n@Panel {{\"label\":\"Nested\"}}\n: Inner\n@End\n@End\n"
                )).unwrap();
                let layout = crate::page_layout::build(&d, 50, &BTreeMap::new(), ascii).unwrap();
                let visual = &layout.visuals[0];
                let mut state = State::default();
                let now = Instant::now();
                assert!(!state.target(&layout, "Greenhouse", true, 100, 10, now));
                assert!(state.target(&layout, "Greenhouse", true, 0, 20, now));
                let mut active =
                    crate::page_layout::build(&d, 50, &BTreeMap::new(), ascii).unwrap();
                state.apply(&mut active, now + Duration::from_millis(250));
                let mut changed = 0;
                for (before, after) in layout.lines.iter().zip(&active.lines) {
                    for (a, b) in before.cells.iter().zip(&after.cells) {
                        if a.border.is_some_and(|border| border.key == visual.key) {
                            assert_ne!(a.style.colour, b.style.colour);
                            assert_ne!(a.text, b.text);
                            changed += 1;
                        } else {
                            assert_eq!(a.text, b.text);
                            assert_eq!(a.style.colour, b.style.colour);
                            assert_eq!(a.style.bold, b.style.bold);
                        }
                        if ascii {
                            assert!(b.text.is_ascii());
                        }
                    }
                }
                assert!(changed > 50);
                assert!(state.sync(&layout, 0, 20, now + Duration::from_secs(1)));
                let mut completed =
                    crate::page_layout::build(&d, 50, &BTreeMap::new(), ascii).unwrap();
                state.apply(&mut completed, now + Duration::from_secs(1));
                for (before, after) in layout.lines.iter().zip(&completed.lines) {
                    for (a, b) in before.cells.iter().zip(&after.cells) {
                        assert_eq!(a.text, b.text);
                    }
                }
                assert!(state.target(&layout, "Greenhouse", true, 0, 20, now));
                assert!(!state.target(&layout, "Greenhouse", false, 0, 20, now));
            }
        }
    }
    #[test]
    fn effects_require_input_expire_and_stop_when_hidden() {
        let d=crate::markup::parse("HyperNetPage/2\n# Motion\n@Text {\"id\":\"Greeting\",\"value\":\"Visible\",\"motion\":{\"preset\":\"ColourPulse\",\"durationMs\":1000}}\n").unwrap();
        let layout = crate::page_layout::build(&d, 30, &BTreeMap::new(), false).unwrap();
        let mut s = State::default();
        let now = Instant::now();
        assert!(!s.due(now, false));
        s.toggle(&layout, 0, 10, now);
        assert!(s.due(now, false));
        s.painted(now);
        assert!(!s.due(now + Duration::from_millis(99), false));
        assert!(!s.due(now + Duration::from_millis(499), true));
        assert!(s.sync(&layout, 100, 10, now));
        assert!(!s.running());
        s.toggle(&layout, 0, 10, now);
        assert!(s.sync(&layout, 0, 10, now + Duration::from_secs(1)));
        assert!(!s.running());
    }
}
