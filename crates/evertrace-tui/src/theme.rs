use ratatui::style::Color;

pub struct Palette {
    pub background: Color,
    pub surface: Color,
    pub raised: Color,
    pub ink: Color,
    pub muted: Color,
    pub border: Color,
    pub cyan: Color,
    pub green: Color,
    pub amber: Color,
    pub red: Color,
    pub _model_generated_magenta: Color,
}

pub const EVER_OS: Palette = Palette {
    background: Color::Rgb(0x1d, 0x1c, 0x18),
    surface: Color::Rgb(0x24, 0x23, 0x1e),
    raised: Color::Rgb(0x31, 0x30, 0x2b),
    ink: Color::Rgb(0xf5, 0xed, 0xdc),
    muted: Color::Rgb(0x91, 0x8c, 0x80),
    border: Color::Rgb(0x5a, 0x55, 0x49),
    cyan: Color::Cyan,
    green: Color::Green,
    amber: Color::Yellow,
    red: Color::Red,
    _model_generated_magenta: Color::Magenta,
};
