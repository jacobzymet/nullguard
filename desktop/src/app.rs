use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroizing;

use crate::{
    paths::{self, Settings},
    protocol::{Control, Event, LocalPath, Operation, Request},
    secret_input::SecretInput,
    session::{Message, Session},
    tray::{self, Action, Tray},
};

const INK: Color32 = Color32::from_rgb(27, 39, 47);
const MUTED: Color32 = Color32::from_rgb(88, 101, 108);
const ACCENT: Color32 = Color32::from_rgb(23, 99, 87);
const PAPER: Color32 = Color32::from_rgb(248, 249, 246);

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Locked,
    Creating,
    Unlocking,
    Unlocked,
    Locking,
    Checking,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Locked => "Locked",
            Self::Creating => "Creating vault",
            Self::Unlocking => "Unlocking",
            Self::Unlocked => "Unlocked",
            Self::Locking => "Saving and locking",
            Self::Checking => "Checking integrity",
        }
    }
}

struct VaultItem {
    id: u64,
    path: PathBuf,
    phase: Phase,
    session: Option<Session>,
    progress: f32,
    message: Option<String>,
    warning: Option<String>,
    had_error: bool,
}

struct App {
    dir: Option<PathBuf>,
    items: Vec<VaultItem>,
    selected: Option<usize>,
    next_id: u64,
    sender: mpsc::Sender<Message>,
    receiver: mpsc::Receiver<Message>,
    tray_receiver: mpsc::Receiver<Action>,
    tray: Option<Tray>,
    creating: Option<PathBuf>,
    password: SecretInput,
    repeat: SecretInput,
    keyfile: Option<PathBuf>,
    use_keyfile: bool,
    read_only: bool,
    low_memory: bool,
    size: u64,
    unit: u64,
    error: Option<String>,
    dependency: Option<String>,
    cost_warning: Option<String>,
    allow_cost: bool,
    closing: bool,
}

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([940.0, 660.0])
            .with_min_inner_size([700.0, 560.0])
            .with_icon(egui::IconData {
                rgba: tray::icon_rgba(),
                width: 32,
                height: 32,
            }),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Nullguard",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let ctx = cc.egui_ctx.clone();
        let mut style = egui::Style {
            visuals: egui::Visuals::light(),
            ..Default::default()
        };
        style.visuals.override_text_color = Some(INK);
        style.visuals.panel_fill = PAPER;
        style.visuals.window_fill = PAPER;
        style.visuals.extreme_bg_color = Color32::WHITE;
        style.visuals.selection.bg_fill = ACCENT;
        style.visuals.selection.stroke.color = Color32::WHITE;
        style.spacing.item_spacing = egui::vec2(10.0, 12.0);
        style.spacing.button_padding = egui::vec2(14.0, 9.0);
        style.spacing.interact_size.y = 36.0;
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(27.0));
        ctx.set_theme(egui::Theme::Light);
        ctx.set_style_of(egui::Theme::Light, style);
        let (sender, receiver) = mpsc::channel();
        let (tray_sender, tray_receiver) = mpsc::channel();
        let dir = paths::data_dir();
        let (dir, settings, error) = match dir {
            Ok(dir) => match paths::load(&dir) {
                Ok(settings) => (Some(dir), settings, None),
                Err(e) => (Some(dir), Settings::default(), Some(e.to_string())),
            },
            Err(e) => (None, Settings::default(), Some(e.to_string())),
        };
        let mut app = Self {
            dir,
            items: vec![],
            selected: None,
            next_id: 1,
            sender,
            receiver,
            tray_receiver,
            tray: Tray::new(tray_sender, ctx),
            creating: None,
            password: SecretInput::default(),
            repeat: SecretInput::default(),
            keyfile: None,
            use_keyfile: false,
            read_only: false,
            low_memory: false,
            size: 10,
            unit: 1 << 30,
            error,
            dependency: paths::check_dependencies().err().map(|e| e.to_string()),
            cost_warning: None,
            allow_cost: false,
            closing: false,
        };
        for path in settings.recent {
            if let Ok(path) = path.decode() {
                app.add(path);
            }
        }
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.first().is_some_and(|a| a == "--new") {
            if let Some(path) = args.get(1) {
                app.creating = Some(PathBuf::from(path));
            }
        } else if let Some(path) = args.first() {
            app.add(PathBuf::from(path));
        }
        app
    }

    fn add(&mut self, path: PathBuf) -> usize {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        if let Some(index) = self.items.iter().position(|v| v.path == path) {
            self.select(index);
            return index;
        }
        let index = self.items.len();
        self.items.push(VaultItem {
            id: self.next_id,
            path,
            phase: Phase::Locked,
            session: None,
            progress: 0.0,
            message: None,
            warning: None,
            had_error: false,
        });
        self.next_id += 1;
        self.select(index);
        index
    }

    fn select(&mut self, index: usize) {
        self.password.clear();
        self.repeat.clear();
        self.keyfile = None;
        self.use_keyfile = false;
        self.selected = Some(index);
        self.creating = None;
        self.error = None;
        self.allow_cost = false;
        self.read_only = false;
        self.cost_warning = nullguard::vault::unusual_kdf_warning(&self.items[index].path);
    }

    fn save(&mut self) {
        if let Some(dir) = &self.dir {
            let settings = Settings {
                recent: self
                    .items
                    .iter()
                    .filter(|v| v.path.exists())
                    .take(50)
                    .map(|v| LocalPath::new(&v.path))
                    .collect(),
            };
            if let Err(e) = paths::save(dir, &settings) {
                self.error = Some(format!("Could not remember vault paths: {e}"));
            }
        }
    }

    fn choose_open(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a vault")
            .add_filter("Nullguard vault", &["ngv"])
            .pick_file()
        {
            self.add(path);
            self.save();
        }
    }

    fn choose_create(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Create a vault")
            .set_file_name("New vault.ngv")
            .add_filter("Nullguard vault", &["ngv"])
            .save_file()
        {
            self.password.clear();
            self.repeat.clear();
            self.creating = Some(path);
            self.error = None;
            self.use_keyfile = false;
            self.keyfile = None;
        }
    }

    fn start(&mut self, ctx: &egui::Context, verify: bool) {
        let result = self.prepare_start(ctx, verify);
        if let Err(e) = result {
            self.error = Some(format!("{e:#}"));
        }
    }

    fn prepare_start(&mut self, ctx: &egui::Context, verify: bool) -> anyhow::Result<()> {
        let create = self.creating.clone();
        let path = create
            .clone()
            .or_else(|| self.selected.map(|i| self.items[i].path.clone()))
            .ok_or_else(|| anyhow::anyhow!("Choose a vault first."))?;
        check_target(
            &path,
            create.is_some(),
            self.items
                .iter()
                .filter(|v| v.session.is_some())
                .map(|v| v.path.as_path()),
        )?;
        if !verify {
            paths::check_dependencies()?;
        }
        let password = nullguard::crypto::kdf::normalize_password(self.password.as_str());
        if create.is_some() {
            crate::worker::validate_password(&password)?;
            let repeat = nullguard::crypto::kdf::normalize_password(self.repeat.as_str());
            if !nullguard::crypto::ct_eq(password.as_bytes(), repeat.as_bytes()) {
                anyhow::bail!("The passwords do not match. Enter them again.");
            }
        } else if self.use_keyfile && self.keyfile.is_none() {
            anyhow::bail!("Choose your keyfile first.");
        } else if !self.use_keyfile && password.is_empty() {
            anyhow::bail!("Enter your vault password.");
        }
        if create.is_none() && !self.use_keyfile && self.cost_warning.is_some() && !self.allow_cost
        {
            anyhow::bail!("Confirm the unusually expensive key derivation before continuing.");
        }
        let dir = self.dir.as_ref().ok_or_else(|| anyhow::anyhow!("The application-data folder is unavailable. Fix its permissions and reopen Nullguard."))?;
        let mountpoint = if verify {
            PathBuf::new()
        } else {
            paths::mountpoint(dir, &path)?
        };
        let size = self
            .size
            .checked_mul(self.unit)
            .filter(|s| *s >= 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("Choose a vault size of at least 1 MiB."))?;
        let index = if create.is_some() {
            self.add(path.clone())
        } else {
            self.selected.unwrap()
        };
        let request = Request {
            operation: if create.is_some() {
                Operation::Create {
                    size,
                    low_memory: self.low_memory,
                }
            } else if verify {
                Operation::Verify
            } else {
                Operation::Unlock
            },
            vault: LocalPath::new(&path),
            mountpoint: LocalPath::new(&mountpoint),
            keyfile: if self.use_keyfile {
                self.keyfile.as_ref().map(|p| LocalPath::new(p))
            } else {
                None
            },
            password: if self.use_keyfile {
                Zeroizing::new(String::new())
            } else {
                password
            },
            read_only: self.read_only,
        };
        drop(self.password.take());
        drop(self.repeat.take());
        let session = match Session::start(
            self.items[index].id,
            &request,
            self.sender.clone(),
            ctx.clone(),
        ) {
            Ok(session) => session,
            Err(e) => {
                paths::cleanup_mountpoint(&mountpoint);
                return Err(e);
            }
        };
        let item = &mut self.items[index];
        item.session = Some(session);
        item.message = None;
        item.warning = None;
        item.had_error = false;
        item.phase = if create.is_some() {
            Phase::Creating
        } else if verify {
            Phase::Checking
        } else {
            Phase::Unlocking
        };
        item.progress = 0.0;
        self.creating = None;
        self.error = None;
        self.save();
        Ok(())
    }

    fn lock(&mut self, index: usize) {
        let item = &mut self.items[index];
        if let Some(session) = &mut item.session {
            if item.phase != Phase::Unlocked {
                let _ = session.send(Control::Cancel);
            }
            match session.send(Control::Lock) {
                Ok(()) => {
                    item.phase = Phase::Locking;
                    item.message = None;
                }
                Err(e) => {
                    item.message = Some(format!(
                        "Could not request locking: {e}. The worker's exit is still being checked."
                    ));
                }
            }
        }
    }

    fn lock_all(&mut self) {
        for i in 0..self.items.len() {
            if self.items[i].session.is_some() {
                self.lock(i);
            }
        }
    }

    fn messages(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.receiver.try_recv() {
            let id = match &message {
                Message::Event(id, _) | Message::Exited(id, _) => *id,
            };
            let Some(index) = self.items.iter().position(|v| v.id == id) else {
                continue;
            };
            let item = &mut self.items[index];
            match message {
                Message::Event(_, Event::Progress { fraction }) => {
                    item.progress = fraction.clamp(0.0, 1.0)
                }
                Message::Event(_, Event::Created) => {
                    item.message = Some("Vault created. Unlocking it now…".into());
                    self.save();
                }
                Message::Event(_, Event::Mounted) => {
                    if item.phase != Phase::Locking && !self.closing {
                        item.phase = Phase::Unlocked;
                        item.message = None;
                        if let Some(session) = &item.session
                            && let Err(e) = paths::open_folder(&session.mountpoint)
                        {
                            item.message = Some(e.to_string());
                        }
                    }
                }
                Message::Event(_, Event::Warning(warning)) => {
                    item.warning = Some(match item.warning.take() {
                        Some(old) => format!("{old}\n{warning}"),
                        None => warning,
                    });
                }
                Message::Event(_, Event::Error(error)) => {
                    item.message = Some(error);
                    item.had_error = true;
                }
                Message::Event(_, Event::LockFailed(error)) => {
                    item.phase = Phase::Unlocked;
                    item.message = Some(error);
                    self.closing = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                }
                Message::Event(_, Event::Verified { files, blocks }) => {
                    item.message = Some(format!(
                        "Integrity check passed: {files} files, {blocks} blocks."
                    ))
                }
                Message::Event(_, Event::Cancelled) => {
                    item.message = Some(
                        if item.path.exists() {
                            "Operation cancelled. The vault remains available."
                        } else {
                            "Creation cancelled. No vault was kept."
                        }
                        .into(),
                    )
                }
                Message::Event(_, Event::Finished) => item.phase = Phase::Locking,
                Message::Exited(_, success) => {
                    item.session.take();
                    item.phase = Phase::Locked;
                    if !success && !item.had_error {
                        item.message = Some("The vault worker stopped unexpectedly. Reopen the vault and run an integrity check before continuing.".into());
                    }
                    self.save();
                }
            }
        }
        while let Ok(action) = self.tray_receiver.try_recv() {
            match action {
                Action::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Action::LockAll => self.lock_all(),
                Action::Quit => {
                    self.closing = true;
                    self.lock_all();
                }
            }
        }
        if self.closing && self.items.iter().all(|v| v.session.is_none()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(18.0);
        ui.label(RichText::new("nullguard").size(23.0).strong());
        ui.add_space(24.0);
        ui.label(RichText::new("VAULTS").small().color(MUTED));
        ui.add_space(8.0);
        let mut select = None;
        egui::ScrollArea::vertical()
            .id_salt("vault-list-scroll")
            .max_height((ui.available_height() - 190.0).max(60.0))
            .show(ui, |ui| {
                for (i, item) in self.items.iter().enumerate() {
                    let name = item
                        .path
                        .file_name()
                        .map(Path::new)
                        .map(paths::display)
                        .unwrap_or_else(|| "Vault".into());
                    let active = self.selected == Some(i) && self.creating.is_none();
                    if ui
                        .selectable_label(
                            active,
                            RichText::new(name).size(15.0).color(if active {
                                Color32::WHITE
                            } else {
                                INK
                            }),
                        )
                        .clicked()
                    {
                        select = Some(i);
                    }
                    ui.label(RichText::new(item.phase.label()).small().color(
                        if item.phase == Phase::Unlocked {
                            ACCENT
                        } else {
                            MUTED
                        },
                    ));
                    ui.add_space(9.0);
                }
            });
        if let Some(i) = select {
            self.select(i);
        }
        if self.items.is_empty() {
            ui.label(RichText::new("No vaults added yet.").color(MUTED));
        }
        ui.add_space(18.0);
        if ui.button("Open a vault…").clicked() {
            self.choose_open();
        }
        if ui.button("Create a vault…").clicked() {
            self.choose_create();
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.label(
                RichText::new("Encrypted vaults, on your computer.")
                    .small()
                    .color(MUTED),
            );
            if self.tray.is_some() && ui.small_button("Hide to tray / menu bar").clicked() {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        });
    }

    fn content(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        if let Some(error) = self.error.clone() {
            notice(ui, &error, true);
        }
        if self.creating.is_some() {
            self.create_view(ui);
            return;
        }
        let Some(index) = self.selected else {
            self.empty(ui);
            return;
        };
        let item = &self.items[index];
        let phase = item.phase;
        let title = item
            .path
            .file_name()
            .map(Path::new)
            .map(paths::display)
            .unwrap_or_else(|| "Vault".into());
        ui.heading(title);
        ui.label(
            RichText::new(paths::display(&item.path))
                .color(MUTED)
                .size(13.0),
        );
        ui.add_space(20.0);
        ui.label(RichText::new(phase.label()).size(17.0).strong().color(
            if phase == Phase::Unlocked {
                ACCENT
            } else {
                INK
            },
        ));
        if let Some(warning) = item.warning.clone() {
            notice(ui, &warning, false);
        }
        if let Some(message) = item.message.clone() {
            notice(ui, &message, item.had_error || phase == Phase::Unlocked);
        }
        ui.add_space(16.0);
        match phase {
            Phase::Locked => self.unlock_view(ui, index),
            Phase::Unlocked => {
                if let Some(session) = &self.items[index].session {
                    ui.label(RichText::new("Your files are available at").color(MUTED));
                    ui.label(paths::display(&session.mountpoint));
                }
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if primary(ui, "Open folder").clicked()
                        && let Some(session) = &self.items[index].session
                        && let Err(e) = paths::open_folder(&session.mountpoint)
                    {
                        self.error = Some(e.to_string());
                    }
                    if ui.button("Lock vault").clicked() {
                        self.lock(index);
                    }
                });
                ui.add_space(22.0);
                ui.label(
                    RichText::new("Lock the vault when you finish using its files.").color(MUTED),
                );
            }
            Phase::Creating => {
                ui.add(
                    egui::ProgressBar::new(self.items[index].progress)
                        .show_percentage()
                        .desired_width(400.0),
                );
                ui.label(
                    "Filling the vault with random data. Your files will open when it is ready.",
                );
                if ui.button("Cancel creation").clicked() {
                    self.lock(index);
                }
            }
            Phase::Unlocking | Phase::Checking | Phase::Locking => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(match phase {
                        Phase::Locking => "Finishing writes and closing the vault…",
                        Phase::Checking => "Authenticating the header, metadata, and file blocks…",
                        _ => "Checking your credentials. This can take a few seconds…",
                    });
                });
            }
        }
    }

    fn empty(&mut self, ui: &mut egui::Ui) {
        ui.add_space(80.0);
        lock_icon(ui);
        ui.add_space(22.0);
        ui.heading("Add your first vault");
        ui.add_space(8.0);
        ui.label(
            RichText::new("Open an existing vault, or create one to get started.").color(MUTED),
        );
        ui.add_space(22.0);
        ui.horizontal(|ui| {
            if primary(ui, "Open a vault…").clicked() {
                self.choose_open();
            }
            if ui.button("Create a vault…").clicked() {
                self.choose_create();
            }
        });
        if let Some(dependency) = self.dependency.clone() {
            ui.add_space(28.0);
            notice(ui, &dependency, false);
        }
    }

    fn unlock_view(&mut self, ui: &mut egui::Ui, index: usize) {
        if let Some(dependency) = self.dependency.clone() {
            notice(ui, &dependency, false);
            if ui.button("Check again").clicked() {
                self.dependency = paths::check_dependencies().err().map(|e| e.to_string());
            }
        }
        ui.horizontal(|ui| {
            if ui
                .selectable_label(
                    !self.use_keyfile,
                    RichText::new("Password").color(if self.use_keyfile {
                        INK
                    } else {
                        Color32::WHITE
                    }),
                )
                .clicked()
            {
                self.use_keyfile = false;
            }
            if ui
                .selectable_label(
                    self.use_keyfile,
                    RichText::new("Keyfile").color(if self.use_keyfile {
                        Color32::WHITE
                    } else {
                        INK
                    }),
                )
                .clicked()
            {
                self.use_keyfile = true;
                self.password.clear();
            }
        });
        if self.use_keyfile {
            if ui
                .button(
                    self.keyfile
                        .as_ref()
                        .map(|p| paths::display(p))
                        .unwrap_or_else(|| "Choose keyfile…".into()),
                )
                .clicked()
            {
                self.keyfile = rfd::FileDialog::new()
                    .set_title("Choose your keyfile")
                    .pick_file();
            }
        } else {
            self.password.show(ui, "unlock-password", "Vault password");
        }
        if let Some(warning) = self.cost_warning.clone() {
            notice(ui, &warning, false);
            ui.checkbox(
                &mut self.allow_cost,
                "Allow this unusually expensive key derivation",
            );
        }
        ui.add_space(6.0);
        let enabled = self.dependency.is_none()
            && (self.cost_warning.is_none() || self.allow_cost || self.use_keyfile);
        let enter = self.password.submitted;
        self.password.submitted = false;
        let unlock = ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new("Unlock vault").color(Color32::WHITE)).fill(ACCENT),
        );
        if unlock.clicked() || (enter && enabled) {
            self.start(ui.ctx(), false);
        }
        ui.add_space(18.0);
        egui::CollapsingHeader::new("Advanced").show(ui, |ui| {
            ui.checkbox(&mut self.read_only, "Open read-only");
            if ui.button("Check vault integrity").clicked() {
                self.start(ui.ctx(), true);
            }
            ui.label(
                RichText::new(
                    "Password changes, rekeying, and keyfile management are available in the CLI.",
                )
                .small()
                .color(MUTED),
            );
            if ui.small_button("Remove from this list").clicked() {
                self.items.remove(index);
                self.selected = None;
                self.password.clear();
                self.save();
            }
            ui.label(
                RichText::new("Removing an entry does not delete the vault file.")
                    .small()
                    .color(MUTED),
            );
        });
    }

    fn create_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create a vault");
        ui.label(
            RichText::new("Choose a size and a password of at least 12 characters.").color(MUTED),
        );
        ui.add_space(8.0);
        if let Some(path) = &self.creating {
            ui.label(paths::display(path));
        }
        if ui.small_button("Change location…").clicked() {
            self.choose_create();
        }
        ui.add_space(4.0);
        ui.label("Vault size");
        ui.horizontal(|ui| {
            ui.add(
                egui::DragValue::new(&mut self.size)
                    .range(1..=1024 * 1024)
                    .speed(1),
            );
            egui::ComboBox::from_id_salt("size-unit")
                .selected_text(match self.unit {
                    1048576 => "MiB",
                    1099511627776 => "TiB",
                    _ => "GiB",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.unit, 1 << 20, "MiB");
                    ui.selectable_value(&mut self.unit, 1 << 30, "GiB");
                    ui.selectable_value(&mut self.unit, 1 << 40, "TiB");
                });
        });
        ui.label(
            RichText::new("This space is reserved on disk when the vault is created.")
                .small()
                .color(MUTED),
        );
        ui.add_space(4.0);
        ui.label("Password");
        self.password
            .show(ui, "new-password", "At least 12 characters");
        ui.label("Repeat password");
        self.repeat
            .show(ui, "repeat-password", "Enter the password again");
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Advanced").show(ui, |ui| {
            ui.checkbox(
                &mut self.low_memory,
                "Use less memory for unlocking (64 MiB)",
            );
            ui.label(
                RichText::new("The default uses 1 GiB and makes password guesses more expensive.")
                    .small()
                    .color(MUTED),
            );
        });
        if let Some(dependency) = self.dependency.clone() {
            notice(ui, &dependency, false);
        }
        let enter = self.repeat.submitted;
        self.repeat.submitted = false;
        ui.horizontal(|ui| {
            let button = ui.add_enabled(
                self.dependency.is_none(),
                egui::Button::new(RichText::new("Create and unlock").color(Color32::WHITE))
                    .fill(ACCENT),
            );
            if button.clicked() || (enter && self.dependency.is_none()) {
                self.start(ui.ctx(), false);
            }
            if ui.button("Cancel").clicked() {
                self.creating = None;
                self.password.clear();
                self.repeat.clear();
                self.error = None;
            }
        });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.messages(ctx);
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        for file in ctx.input(|i| i.raw.dropped_files.clone()) {
            self.add(file.path().to_path_buf());
            self.save();
        }
        if ctx.input(|i| i.viewport().close_requested())
            && self.items.iter().any(|v| v.session.is_some())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if !self.closing {
                self.closing = true;
                self.lock_all();
            }
        }
        ctx.request_repaint_after(Duration::from_millis(200));
        egui::Panel::left("vault-list")
            .exact_size(214.0)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(237, 241, 237))
                    .inner_margin(20),
            )
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(PAPER).inner_margin(28))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.content(ui));
            });
    }
    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.password.clear();
        self.repeat.clear();
        self.lock_all();
        // Child stdin pipes close when the app exits; workers then request
        // clean unmounts even if the window system bypassed close handling.
    }
}

fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(ACCENT))
}

fn check_target<'a>(
    path: &Path,
    create: bool,
    active: impl Iterator<Item = &'a Path>,
) -> anyhow::Result<()> {
    if create && std::fs::symlink_metadata(path).is_ok() {
        anyhow::bail!(
            "A file already exists at this location. Choose another location for the new vault."
        );
    }
    let identity = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if active
        .into_iter()
        .any(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()) == identity)
    {
        anyhow::bail!(
            "This vault already has an operation running. Wait for it to finish or lock it first."
        );
    }
    Ok(())
}

fn notice(ui: &mut egui::Ui, text: &str, error: bool) {
    egui::Frame::new()
        .fill(if error {
            Color32::from_rgb(252, 235, 230)
        } else {
            Color32::from_rgb(242, 236, 214)
        })
        .inner_margin(12)
        .corner_radius(6)
        .show(ui, |ui| {
            ui.set_max_width(470.0);
            ui.label(RichText::new(text).color(if error {
                Color32::from_rgb(125, 41, 29)
            } else {
                Color32::from_rgb(97, 72, 19)
            }));
        });
    ui.add_space(8.0);
}

fn lock_icon(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(54.0, 62.0), egui::Sense::hover());
    let stroke = egui::Stroke::new(3.0, ACCENT);
    let top = egui::Rect::from_min_size(rect.min + egui::vec2(13.0, 0.0), egui::vec2(28.0, 37.0));
    ui.painter()
        .rect_stroke(top, 13.0, stroke, egui::StrokeKind::Inside);
    let body = egui::Rect::from_min_size(rect.min + egui::vec2(2.0, 25.0), egui::vec2(50.0, 35.0));
    ui.painter().rect_filled(body, 7.0, PAPER);
    ui.painter()
        .rect_stroke(body, 7.0, stroke, egui::StrokeKind::Inside);
    ui.painter().circle_filled(body.center(), 3.0, ACCENT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_replace_an_existing_file_or_an_active_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.ngv");
        // A creation in progress owns its session even before its file exists.
        assert!(check_target(&path, true, [path.as_path()].into_iter()).is_err());
        assert!(check_target(&path, true, std::iter::empty()).is_ok());
        std::fs::write(&path, b"existing vault").unwrap();
        assert!(check_target(&path, true, std::iter::empty()).is_err());
        assert!(check_target(&path, false, [path.as_path()].into_iter()).is_err());
        assert!(check_target(&path, false, std::iter::empty()).is_ok());
        assert_eq!(std::fs::read(path).unwrap(), b"existing vault");
    }

    #[test]
    fn created_event_remembers_vault_before_its_session_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.ngv");
        let (sender, receiver) = mpsc::channel();
        let (_, tray_receiver) = mpsc::channel();
        let mut app = App {
            dir: Some(dir.path().to_owned()),
            items: vec![],
            selected: None,
            next_id: 1,
            sender,
            receiver,
            tray_receiver,
            tray: None,
            creating: None,
            password: SecretInput::default(),
            repeat: SecretInput::default(),
            keyfile: None,
            use_keyfile: false,
            read_only: false,
            low_memory: false,
            size: 10,
            unit: 1 << 30,
            error: None,
            dependency: None,
            cost_warning: None,
            allow_cost: false,
            closing: false,
        };
        let index = app.add(path.clone());
        app.items[index].phase = Phase::Creating;
        app.save();
        assert!(paths::load(dir.path()).unwrap().recent.is_empty());
        std::fs::write(&path, b"created vault").unwrap();
        app.sender
            .send(Message::Event(app.items[index].id, Event::Created))
            .unwrap();
        app.messages(&egui::Context::default());
        assert_eq!(
            paths::load(dir.path()).unwrap().recent,
            vec![LocalPath::new(&path)]
        );
        assert!(app.items[index].phase == Phase::Creating);
    }
}
