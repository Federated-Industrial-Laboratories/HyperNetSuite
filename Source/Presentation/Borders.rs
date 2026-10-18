// SPDX-License-Identifier: MIT
// Finite generated border glyphs; source text never acquires border semantics.
use crate::markup::BorderStyle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Horizontal,
    Vertical,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
    LeftJoin,
    RightJoin,
}
#[derive(Clone, Copy)]
pub struct BorderCell {
    pub key: usize,
    pub style: BorderStyle,
    pub part: Part,
}
impl BorderCell {
    pub fn glyph(self, accent: bool) -> &'static str {
        let style = if accent {
            match self.style {
                BorderStyle::Light | BorderStyle::Rounded | BorderStyle::Double => {
                    BorderStyle::Heavy
                }
                BorderStyle::Heavy => BorderStyle::Double,
                BorderStyle::Ascii => BorderStyle::Ascii,
            }
        } else {
            self.style
        };
        let palette = match style {
            BorderStyle::Light => ["─", "│", "┌", "┐", "└", "┘", "├", "┤"],
            BorderStyle::Heavy => ["━", "┃", "┏", "┓", "┗", "┛", "┣", "┫"],
            BorderStyle::Double => ["═", "║", "╔", "╗", "╚", "╝", "╠", "╣"],
            BorderStyle::Rounded => ["─", "│", "╭", "╮", "╰", "╯", "├", "┤"],
            BorderStyle::Ascii if accent => ["=", "!", "*", "*", "*", "*", "*", "*"],
            BorderStyle::Ascii => ["-", "|", "+", "+", "+", "+", "+", "+"],
        };
        palette[self.part as usize]
    }
}
