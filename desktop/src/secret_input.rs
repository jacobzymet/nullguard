//! Password entry without TextEdit's plaintext undo snapshots or layout text.
//! Only the mask is handed to egui's text renderer. OS/input-system buffers
//! remain outside the guarantees of this widget.

use eframe::egui::{self, Color32, Event, Key, Role, Sense, Stroke, WidgetInfo};
use zeroize::{Zeroize, Zeroizing};

pub struct SecretInput {
    text: Zeroizing<String>,
    cursor: usize,
    anchor: usize,
    pub submitted: bool,
}

impl Default for SecretInput {
    fn default() -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(4096)),
            cursor: 0,
            anchor: 0,
            submitted: false,
        }
    }
}

impl SecretInput {
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn clear(&mut self) {
        self.text.zeroize();
        self.cursor = 0;
        self.anchor = 0;
        self.submitted = false;
    }
    pub fn take(&mut self) -> Zeroizing<String> {
        self.cursor = 0;
        self.anchor = 0;
        self.submitted = false;
        std::mem::replace(&mut self.text, Zeroizing::new(String::with_capacity(4096)))
    }

    fn insert(&mut self, text: &str) {
        let from = self.cursor.min(self.anchor);
        let to = self.cursor.max(self.anchor);
        if text.contains(['\r', '\n']) || self.text.len() - (to - from) + text.len() > 4096 {
            return;
        }
        let mut replacement = Zeroizing::new(String::with_capacity(4096));
        replacement.push_str(&self.text[..from]);
        replacement.push_str(text);
        replacement.push_str(&self.text[to..]);
        self.text = replacement; // wipe the old allocation, including removed characters
        self.cursor = from + text.len();
        self.anchor = self.cursor;
    }

    fn previous(&self) -> usize {
        self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i)
    }
    fn next(&self) -> usize {
        self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |c| self.cursor + c.len_utf8())
    }

    pub fn show(&mut self, ui: &mut egui::Ui, id: &str, label: &str) -> egui::Response {
        let id = ui.make_persistent_id(id);
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width().min(420.0), 42.0),
            Sense::hover(),
        );
        let response = ui
            .interact(rect, id, Sense::click())
            .on_hover_cursor(egui::CursorIcon::Text);
        if response.clicked() {
            response.request_focus();
            self.cursor = self.text.len();
            self.anchor = self.cursor;
        }
        let focused = response.has_focus();
        if focused {
            ui.input_mut(|input| {
                for event in &mut input.events {
                    match event {
                        Event::Text(text) | Event::Paste(text) => {
                            self.insert(text);
                            text.zeroize();
                        }
                        Event::Ime(egui::ImeEvent::Commit(text)) => {
                            self.insert(text);
                            text.zeroize();
                        }
                        Event::Ime(egui::ImeEvent::Preedit { text, .. }) => {
                            text.zeroize();
                        }
                        Event::Key {
                            key,
                            pressed: true,
                            modifiers,
                            ..
                        } => match key {
                            Key::A if modifiers.command => {
                                self.anchor = 0;
                                self.cursor = self.text.len();
                            }
                            Key::Backspace => {
                                if self.cursor == self.anchor {
                                    self.anchor = self.previous();
                                }
                                self.insert("");
                            }
                            Key::Delete => {
                                if self.cursor == self.anchor {
                                    self.anchor = self.next();
                                }
                                self.insert("");
                            }
                            Key::ArrowLeft => {
                                self.cursor = self.previous();
                                if !modifiers.shift {
                                    self.anchor = self.cursor;
                                }
                            }
                            Key::ArrowRight => {
                                self.cursor = self.next();
                                if !modifiers.shift {
                                    self.anchor = self.cursor;
                                }
                            }
                            Key::Home => {
                                self.cursor = 0;
                                if !modifiers.shift {
                                    self.anchor = 0;
                                }
                            }
                            Key::End => {
                                self.cursor = self.text.len();
                                if !modifiers.shift {
                                    self.anchor = self.cursor;
                                }
                            }
                            Key::Enter => {
                                self.submitted = true;
                            }
                            Key::Escape => {
                                response.surrender_focus();
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
                // InputState keeps a raw-input copy too. Wipe secret-bearing
                // text there instead of letting it linger into the next pass.
                for event in &mut input.raw.events {
                    match event {
                        Event::Text(text)
                        | Event::Paste(text)
                        | Event::Ime(egui::ImeEvent::Commit(text))
                        | Event::Ime(egui::ImeEvent::Preedit { text, .. }) => text.zeroize(),
                        _ => {}
                    }
                }
            });
            ui.output_mut(|out| {
                out.ime = Some(egui::output::IMEOutput {
                    purpose: egui::IMEPurpose::Password,
                    rect,
                    cursor_rect: rect,
                    should_interrupt_composition: false,
                })
            });
        }
        let stroke = if focused {
            Stroke::new(2.0, Color32::from_rgb(25, 102, 91))
        } else {
            Stroke::new(1.0, ui.visuals().widgets.inactive.bg_stroke.color)
        };
        ui.painter().rect(
            rect,
            6.0,
            ui.visuals().extreme_bg_color,
            stroke,
            egui::StrokeKind::Inside,
        );
        let count = self.text.chars().count().min(40);
        let mask = if count == 0 {
            label.to_owned()
        } else {
            "•".repeat(count)
        };
        ui.painter().text(
            rect.left_center() + egui::vec2(12.0, 0.0),
            egui::Align2::LEFT_CENTER,
            mask,
            egui::FontId::proportional(16.0),
            if count == 0 {
                Color32::from_rgb(88, 101, 108)
            } else {
                ui.visuals().text_color()
            },
        );
        if focused {
            let prefix = self.text[..self.cursor].chars().count().min(40);
            let galley = ui.painter().layout_no_wrap(
                "•".repeat(prefix),
                egui::FontId::proportional(16.0),
                ui.visuals().text_color(),
            );
            let x = (rect.left() + 12.0 + galley.size().x).min(rect.right() - 8.0);
            ui.painter().line_segment(
                [
                    egui::pos2(x, rect.top() + 11.0),
                    egui::pos2(x, rect.bottom() - 11.0),
                ],
                Stroke::new(1.0, ui.visuals().text_color()),
            );
        }
        response.widget_info(|| WidgetInfo::labeled(Role::TextInput, ui.is_enabled(), label));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_entry_is_masked_and_never_enters_undo_history() {
        let ctx = egui::Context::default();
        let mut input = SecretInput::default();
        let mut first = ctx.run_ui(Default::default(), |ui| {
            input.show(ui, "test-password", "Password").request_focus();
        });
        first.textures_delta.clear();
        let secret = "secret password for testing";
        let mut output = ctx.run_ui(
            egui::RawInput {
                events: vec![Event::Paste(secret.into())],
                ..Default::default()
            },
            |ui| {
                input.show(ui, "test-password", "Password");
            },
        );
        output.textures_delta.clear();
        assert_eq!(input.as_str(), secret);
        assert!(!format!("{:?}", output.shapes).contains(secret));
        assert!(ctx.input(|i| {
            i.events
                .iter()
                .all(|e| !matches!(e, Event::Paste(t) if !t.is_empty()))
        }));
        let mut last = ctx.run_ui(
            egui::RawInput {
                events: vec![Event::Key {
                    key: Key::Z,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::COMMAND,
                }],
                ..Default::default()
            },
            |ui| {
                input.show(ui, "test-password", "Password");
            },
        );
        last.textures_delta.clear();
        assert_eq!(input.as_str(), secret);
    }
    #[test]
    fn utf8_selection_and_limits_do_not_split_a_password() {
        let mut input = SecretInput::default();
        input.insert("中文é");
        input.anchor = input.previous();
        input.insert("");
        assert_eq!(input.as_str(), "中文");
        input.insert(&"x".repeat(4096));
        assert_eq!(input.as_str(), "中文");
        input.anchor = 0;
        input.insert("replacement password");
        assert_eq!(input.as_str(), "replacement password");
        let taken = input.take();
        assert!(input.as_str().is_empty());
        assert_eq!(&*taken, "replacement password");
    }
}
