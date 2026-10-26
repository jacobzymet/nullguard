use eframe::egui;
use std::sync::mpsc;

#[derive(Clone, Copy)]
pub enum Action {
    Show,
    LockAll,
    Quit,
}

pub fn icon_rgba() -> Vec<u8> {
    let mut pixels = vec![0; 32 * 32 * 4];
    for y in 0..32usize {
        for x in 0..32usize {
            let body = (7..25).contains(&x) && (14..27).contains(&y);
            let shackle = (9..23).contains(&x)
                && (5..17).contains(&y)
                && !((12..20).contains(&x) && (8..17).contains(&y));
            if body || shackle {
                pixels[(y * 32 + x) * 4..(y * 32 + x) * 4 + 4].copy_from_slice(&[26, 104, 92, 255]);
            }
        }
    }
    pixels
}

#[cfg(target_os = "linux")]
pub struct Tray(ksni::blocking::Handle<LinuxTray>);

#[cfg(target_os = "linux")]
struct LinuxTray {
    sender: mpsc::Sender<Action>,
    ctx: egui::Context,
}

#[cfg(target_os = "linux")]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "nullguard".into()
    }
    fn title(&self) -> String {
        "Nullguard".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let mut data = icon_rgba();
        for pixel in data.as_chunks_mut::<4>().0 {
            pixel.rotate_right(1);
        }
        vec![ksni::Icon {
            width: 32,
            height: 32,
            data,
        }]
    }
    fn activate(&mut self, _: i32, _: i32) {
        let _ = self.sender.send(Action::Show);
        self.ctx.request_repaint();
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        [
            ("Show Nullguard", Action::Show),
            ("Lock all vaults", Action::LockAll),
            ("Lock and quit", Action::Quit),
        ]
        .into_iter()
        .map(|(label, action)| {
            ksni::menu::StandardItem {
                label: label.into(),
                activate: Box::new(move |this: &mut Self| {
                    let _ = this.sender.send(action);
                    this.ctx.request_repaint();
                }),
                ..Default::default()
            }
            .into()
        })
        .collect()
    }
}

#[cfg(target_os = "linux")]
impl Tray {
    pub fn new(sender: mpsc::Sender<Action>, ctx: egui::Context) -> Option<Self> {
        use ksni::blocking::TrayMethods;
        LinuxTray { sender, ctx }.spawn().ok().map(Self)
    }
}

#[cfg(target_os = "linux")]
impl Drop for Tray {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub struct Tray {
    _icon: tray_icon::TrayIcon,
}

#[cfg(any(windows, target_os = "macos"))]
impl Tray {
    pub fn new(sender: mpsc::Sender<Action>, ctx: egui::Context) -> Option<Self> {
        use tray_icon::{
            Icon, TrayIconBuilder,
            menu::{Menu, MenuEvent, MenuItem},
        };
        let menu = Menu::new();
        let show = MenuItem::new("Show Nullguard", true, None);
        let lock = MenuItem::new("Lock all vaults", true, None);
        let quit = MenuItem::new("Lock and quit", true, None);
        menu.append_items(&[&show, &lock, &quit]).ok()?;
        let ids = [
            (show.id().clone(), Action::Show),
            (lock.id().clone(), Action::LockAll),
            (quit.id().clone(), Action::Quit),
        ];
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some((_, action)) = ids.iter().find(|(id, _)| *id == event.id) {
                let _ = sender.send(*action);
                ctx.request_repaint();
            }
        }));
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Nullguard")
            .with_icon(Icon::from_rgba(icon_rgba(), 32, 32).ok()?)
            .build()
            .ok()?;
        Some(Self { _icon: icon })
    }
}
