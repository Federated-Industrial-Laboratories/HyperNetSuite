// SPDX-License-Identifier: MIT
// Unit tests for Motion.
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
            let mut active = crate::page_layout::build(&d, 50, &BTreeMap::new(), ascii).unwrap();
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
            let mut completed = crate::page_layout::build(&d, 50, &BTreeMap::new(), ascii).unwrap();
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
