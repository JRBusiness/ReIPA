#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc::{Receiver, Sender};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Info,
    Classes,
    Swift,
    Strings,
    Disasm,
    Decompile,
}

#[derive(Clone, Copy)]
enum Which {
    Verify,
    Info,
    Classes,
    Swift,
    Strings,
    Disasm,
    Decompile,
}

struct Opened {
    path: PathBuf,
    label: String,
}

enum Msg {
    Opened(Result<Opened, String>),
    Done {
        which: Which,
        result: Result<String, String>,
    },
    Chat(Result<String, String>),
    Exported(Result<String, String>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Claude,
    Codex,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Backend::Claude => "Claude",
            Backend::Codex => "Codex",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    User,
    Assistant,
    Error,
}

struct ChatMsg {
    role: Role,
    text: String,
}

struct App {
    reipa_exe: PathBuf,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,

    binary: Option<PathBuf>,
    label: String,
    opening: bool,
    error: Option<String>,
    encrypted: Option<bool>,
    tab: Tab,
    dark: bool,

    show_chat: bool,
    backend: Backend,
    chat_msgs: Vec<ChatMsg>,
    chat_input: String,
    chat_running: bool,
    chat_context: bool,

    info: Option<String>,
    info_loading: bool,

    classes: Option<Vec<(String, String)>>,
    classes_loading: bool,
    class_filter: String,
    class_sel: Option<usize>,
    class_checked: std::collections::HashSet<usize>,

    export_msg: Option<String>,
    exporting: bool,

    swift: Option<Vec<String>>,
    swift_loading: bool,
    swift_filter: String,
    swift_sel: Option<usize>,

    strings: Option<Vec<(String, String)>>,
    strings_loading: bool,
    strings_filter: String,

    disasm_addr: String,
    disasm_count: String,
    disasm_lines: Vec<String>,
    disasm_loaded: bool,
    disasm_loading: bool,

    decomp_addr: String,
    decomp_out: Option<String>,
    decomp_loading: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            reipa_exe: locate_sibling("reipa"),
            tx,
            rx,
            binary: None,
            label: String::new(),
            opening: false,
            error: None,
            encrypted: None,
            tab: Tab::Info,
            dark: true,
            show_chat: true,
            backend: Backend::Claude,
            chat_msgs: Vec::new(),
            chat_input: String::new(),
            chat_running: false,
            chat_context: true,
            info: None,
            info_loading: false,
            classes: None,
            classes_loading: false,
            class_filter: String::new(),
            class_sel: None,
            class_checked: std::collections::HashSet::new(),
            export_msg: None,
            exporting: false,
            swift: None,
            swift_loading: false,
            swift_filter: String::new(),
            swift_sel: None,
            strings: None,
            strings_loading: false,
            strings_filter: String::new(),
            disasm_addr: String::new(),
            disasm_count: "128".to_string(),
            disasm_lines: Vec::new(),
            disasm_loaded: false,
            disasm_loading: false,
            decomp_addr: String::new(),
            decomp_out: None,
            decomp_loading: false,
        }
    }

    fn reset_views(&mut self) {
        self.encrypted = None;
        self.info = None;
        self.classes = None;
        self.class_sel = None;
        self.class_filter.clear();
        self.class_checked.clear();
        self.swift = None;
        self.swift_filter.clear();
        self.swift_sel = None;
        self.strings = None;
        self.strings_filter.clear();
        self.disasm_lines.clear();
        self.disasm_loaded = false;
        self.decomp_out = None;
    }

    fn dispatch(&self, ctx: &egui::Context, which: Which, mut args: Vec<String>) {
        let path = match &self.binary {
            Some(p) => p.clone(),
            None => return,
        };
        args.insert(1, path.to_string_lossy().into_owned());
        let exe = self.reipa_exe.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = run_cli(&exe, &args);
            let _ = tx.send(Msg::Done { which, result });
            ctx.request_repaint();
        });
    }

    fn base_name(&self) -> String {
        self.binary
            .as_ref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "reipa".to_string())
    }

    /// Run a `reipa` subcommand and stream its stdout directly into a file the
    /// user picks. Streaming (rather than capturing to memory) matters: a full
    /// decompile or __text disassembly of a large binary can be many gigabytes.
    fn start_export(&mut self, ctx: &egui::Context, args: Vec<String>, default_name: String) {
        let Some(path) = self.binary.clone() else {
            return;
        };
        let Some(save) = rfd::FileDialog::new()
            .set_file_name(&default_name)
            .save_file()
        else {
            return;
        };
        let mut args = args;
        args.insert(1, path.to_string_lossy().into_owned());
        self.exporting = true;
        self.export_msg = Some(format!("Exporting to {}…", save.display()));
        let exe = self.reipa_exe.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = run_cli_to_file(&exe, &args, &save).map(|_| save.display().to_string());
            let _ = tx.send(Msg::Exported(r));
            ctx.request_repaint();
        });
    }

    /// Decompile the whole binary into a structured multi-folder project the
    /// user picks. The CLI writes the tree itself, so we only capture its short
    /// stdout summary.
    fn start_project_export(&mut self, ctx: &egui::Context) {
        let Some(path) = self.binary.clone() else {
            return;
        };
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        self.exporting = true;
        self.export_msg = Some(format!("Decompiling project into {}…", dir.display()));
        let exe = self.reipa_exe.clone();
        let args = vec![
            "decompile".to_string(),
            path.to_string_lossy().into_owned(),
            "--project".to_string(),
            dir.to_string_lossy().into_owned(),
        ];
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = run_cli(&exe, &args).map(|out| {
                let summary = out.lines().last().unwrap_or("").trim();
                if summary.is_empty() {
                    dir.display().to_string()
                } else {
                    summary.to_string()
                }
            });
            let _ = tx.send(Msg::Exported(r));
            ctx.request_repaint();
        });
    }

    fn open_dialog(&mut self, ctx: &egui::Context) {
        let file = rfd::FileDialog::new()
            .add_filter("iOS app / Mach-O", &["ipa", "app"])
            .add_filter("All files", &["*"])
            .pick_file();
        let Some(path) = file else { return };
        self.opening = true;
        self.error = None;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = open_binary(&path);
            let _ = tx.send(Msg::Opened(result));
            ctx.request_repaint();
        });
    }

    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Opened(Ok(o)) => {
                    self.binary = Some(o.path);
                    self.label = o.label;
                    self.opening = false;
                    self.error = None;
                    self.reset_views();
                    self.info_loading = true;
                    self.dispatch(ctx, Which::Info, vec!["info".into()]);
                    self.dispatch(ctx, Which::Verify, vec!["verify".into()]);
                }
                Msg::Opened(Err(e)) => {
                    self.opening = false;
                    self.error = Some(e);
                }
                Msg::Done { which, result } => self.finish(which, result),
                Msg::Chat(r) => {
                    self.chat_running = false;
                    let (role, text) = match r {
                        Ok(t) => (Role::Assistant, t),
                        Err(e) => (Role::Error, e),
                    };
                    self.chat_msgs.push(ChatMsg { role, text });
                }
                Msg::Exported(r) => {
                    self.exporting = false;
                    self.export_msg = Some(match r {
                        Ok(p) => format!("Saved to {p}"),
                        Err(e) => format!("Export failed: {e}"),
                    });
                }
            }
        }
    }

    fn finish(&mut self, which: Which, result: Result<String, String>) {
        match which {
            Which::Verify => {
                if let Ok(t) = &result {
                    self.encrypted = t
                        .lines()
                        .find(|l| l.contains("ENCRYPTED"))
                        .map(|l| l.to_lowercase().contains("yes"));
                }
            }
            Which::Info => {
                self.info_loading = false;
                self.info = Some(unwrap_out(result));
            }
            Which::Classes => {
                self.classes_loading = false;
                match result {
                    Ok(t) => self.classes = Some(parse_classdump(&t)),
                    Err(e) => self.classes = Some(vec![("<error>".into(), e)]),
                }
            }
            Which::Swift => {
                self.swift_loading = false;
                self.swift = Some(match result {
                    Ok(t) => {
                        let mut v: Vec<String> = t
                            .lines()
                            .filter(|l| !l.starts_with("//") && !l.trim().is_empty())
                            .map(|l| l.to_string())
                            .collect();
                        v.sort_by(|a, b| {
                            let (ka, na) = a.split_once(' ').unwrap_or(("", a));
                            let (kb, nb) = b.split_once(' ').unwrap_or(("", b));
                            ka.cmp(kb).then_with(|| na.cmp(nb))
                        });
                        v
                    }
                    Err(e) => vec![e],
                });
            }
            Which::Strings => {
                self.strings_loading = false;
                self.strings = Some(match result {
                    Ok(t) => t
                        .lines()
                        .filter_map(|l| {
                            l.split_once(' ')
                                .map(|(a, s)| (a.to_string(), s.to_string()))
                        })
                        .collect(),
                    Err(e) => vec![("".into(), e)],
                });
            }
            Which::Disasm => {
                self.disasm_loading = false;
                self.disasm_loaded = true;
                self.disasm_lines = unwrap_out(result).lines().map(|l| l.to_string()).collect();
            }
            Which::Decompile => {
                self.decomp_loading = false;
                self.decomp_out = Some(unwrap_out(result));
            }
        }
    }

    fn lazy_load(&mut self, ctx: &egui::Context) {
        if self.binary.is_none() {
            return;
        }
        if matches!(self.tab, Tab::Swift) && self.classes.is_none() && !self.classes_loading {
            self.classes_loading = true;
            self.dispatch(ctx, Which::Classes, vec!["classdump".into()]);
        }
        match self.tab {
            Tab::Classes if self.classes.is_none() && !self.classes_loading => {
                self.classes_loading = true;
                self.dispatch(ctx, Which::Classes, vec!["classdump".into()]);
            }
            Tab::Swift if self.swift.is_none() && !self.swift_loading => {
                self.swift_loading = true;
                self.dispatch(ctx, Which::Swift, vec!["swift-types".into()]);
            }
            Tab::Strings if self.strings.is_none() && !self.strings_loading => {
                self.strings_loading = true;
                self.dispatch(ctx, Which::Strings, vec!["strings".into()]);
            }
            Tab::Disasm if !self.disasm_loaded && !self.disasm_loading => {
                self.disasm_loading = true;
                self.dispatch(ctx, Which::Disasm, vec!["disasm".into()]);
            }
            _ => {}
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain(ctx);
        self.lazy_load(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📂  Open .ipa / Mach-O").clicked() {
                    self.open_dialog(ctx);
                }
                if self.opening {
                    ui.spinner();
                    ui.label("opening…");
                }
                if !self.label.is_empty() {
                    ui.separator();
                    ui.strong(&self.label);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(self.show_chat, "💬 Chat")
                        .on_hover_text("Toggle the AI assistant panel")
                        .clicked()
                    {
                        self.show_chat = !self.show_chat;
                    }
                    let icon = if self.dark { "☀ Light" } else { "🌙 Dark" };
                    if ui.button(icon).clicked() {
                        self.dark = !self.dark;
                        ctx.set_visuals(if self.dark {
                            egui::Visuals::dark()
                        } else {
                            egui::Visuals::light()
                        });
                        // set_visuals only takes effect next frame; in reactive
                        // mode nothing schedules that frame, so the theme change
                        // wouldn't show until the next interaction (a second
                        // click). Force the follow-up repaint now.
                        ctx.request_repaint();
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let has = self.binary.is_some();
                ui.add_enabled_ui(has, |ui| {
                    ui.selectable_value(&mut self.tab, Tab::Info, "Info");
                    ui.selectable_value(&mut self.tab, Tab::Classes, "Classes");
                    ui.selectable_value(&mut self.tab, Tab::Swift, "Swift types");
                    ui.selectable_value(&mut self.tab, Tab::Strings, "Strings");
                    ui.selectable_value(&mut self.tab, Tab::Disasm, "Disasm");
                    ui.selectable_value(&mut self.tab, Tab::Decompile, "Decompile");
                });
            });
            if self.encrypted == Some(true) {
                ui.add_space(2.0);
                ui.colored_label(
                    egui::Color32::from_rgb(220, 150, 60),
                    "🔒  This binary is FairPlay-encrypted — class/Swift/string data will be garbage. Decrypt the .ipa first.",
                );
            }
            if self.exporting || self.export_msg.is_some() {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    if self.exporting {
                        ui.spinner();
                    }
                    if let Some(m) = &self.export_msg {
                        ui.colored_label(egui::Color32::from_rgb(120, 180, 120), format!("⬇  {m}"));
                    }
                    if !self.exporting && ui.small_button("✕").clicked() {
                        self.export_msg = None;
                    }
                });
            }
            ui.add_space(2.0);
        });

        if let Some(err) = self.error.clone() {
            egui::TopBottomPanel::bottom("err").show(ctx, |ui| {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠  {err}"));
            });
        }

        if self.show_chat {
            self.ui_chat(ctx);
        }

        if self.binary.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new(
                            "ReIPA\n\nOpen an .ipa or a raw Mach-O executable to begin.",
                        )
                        .size(18.0)
                        .weak(),
                    );
                });
            });
            return;
        }

        match self.tab {
            Tab::Info => self.ui_info(ctx),
            Tab::Classes => self.ui_classes(ctx),
            Tab::Swift => self.ui_list_swift(ctx),
            Tab::Strings => self.ui_list_strings(ctx),
            Tab::Disasm => self.ui_disasm(ctx),
            Tab::Decompile => self.ui_decompile(ctx),
        }
    }
}

impl App {
    fn ui_info(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.info_loading {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("loading header…");
                });
            }
            let text = self.info.clone().unwrap_or_default();
            let def = ui.visuals().text_color();
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(egui::Label::new(highlight(&text, def)).selectable(true));
            });
        });
    }

    fn ui_classes(&mut self, ctx: &egui::Context) {
        let classes = self.classes.take();
        let data: &[(String, String)] = classes.as_deref().unwrap_or(&[]);
        let base = self.base_name();

        egui::SidePanel::left("class_list")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("🔎");
                    ui.text_edit_singleline(&mut self.class_filter);
                });
                if self.classes_loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("dumping classes…");
                    });
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!data.is_empty(), egui::Button::new("⬇ Export all"))
                        .on_hover_text("Export every class @interface to a file")
                        .clicked()
                    {
                        export_class_bodies(data, None, &base, &mut self.export_msg);
                    }
                    let n = self.class_checked.len();
                    if ui
                        .add_enabled(n > 0, egui::Button::new(format!("⬇ Selected ({n})")))
                        .on_hover_text("Export only the checked classes")
                        .clicked()
                    {
                        export_class_bodies(data, Some(&self.class_checked), &base, &mut self.export_msg);
                    }
                    if n > 0 && ui.small_button("clear").clicked() {
                        self.class_checked.clear();
                    }
                });
                ui.separator();
                let needle = self.class_filter.to_lowercase();
                let idx: Vec<usize> = data
                    .iter()
                    .enumerate()
                    .filter(|(_, (n, _))| needle.is_empty() || n.to_lowercase().contains(&needle))
                    .map(|(i, _)| i)
                    .collect();
                ui.label(
                    egui::RichText::new(format!("{} classes", idx.len()))
                        .weak()
                        .small(),
                );
                let row_h = ui.text_style_height(&egui::TextStyle::Body);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, idx.len(), |ui, range| {
                        for &vi in &idx[range] {
                            ui.horizontal(|ui| {
                                let mut checked = self.class_checked.contains(&vi);
                                if ui.checkbox(&mut checked, "").clicked() {
                                    if checked {
                                        self.class_checked.insert(vi);
                                    } else {
                                        self.class_checked.remove(&vi);
                                    }
                                }
                                let selected = self.class_sel == Some(vi);
                                if ui.selectable_label(selected, &data[vi].0).clicked() {
                                    self.class_sel = Some(vi);
                                }
                            });
                        }
                    });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(body) = self
                .class_sel
                .and_then(|i| data.get(i))
                .map(|(_, b)| b.clone())
            else {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new("Select a class").weak());
                });
                return;
            };
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    self.class_body_view(ui, ctx, &body);
                });
        });

        self.classes = classes;
    }

    fn class_body_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, body: &str) {
        let def = ui.visuals().text_color();
        for line in body.lines() {
            if let Some(addr) = imp_of(line) {
                ui.horizontal(|ui| {
                    if ui
                        .small_button("▶")
                        .on_hover_text("Decompile this method")
                        .clicked()
                    {
                        self.decomp_addr = addr.clone();
                        self.decomp_out = None;
                        self.decomp_loading = true;
                        self.tab = Tab::Decompile;
                        self.dispatch(
                            ctx,
                            Which::Decompile,
                            vec!["decompile".into(), addr.clone()],
                        );
                    }
                    ui.add(egui::Label::new(highlight(line, def)).selectable(true));
                });
            } else {
                ui.add(egui::Label::new(highlight(line, def)).selectable(true));
            }
        }
    }

    fn ui_list_swift(&mut self, ctx: &egui::Context) {
        let items = self.swift.take();
        let data: &[String] = items.as_deref().unwrap_or(&[]);
        let classes = self.classes.take();
        let cdata: &[(String, String)] = classes.as_deref().unwrap_or(&[]);

        egui::SidePanel::left("swift_list")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("🔎");
                    ui.text_edit_singleline(&mut self.swift_filter);
                    if self.swift_loading {
                        ui.spinner();
                    }
                });
                if ui
                    .add_enabled(!self.exporting, egui::Button::new("⬇ Export Swift types"))
                    .on_hover_text("Save the full Swift type listing to a file")
                    .clicked()
                {
                    let name = format!("{}.swift-types.txt", self.base_name());
                    self.start_export(ctx, vec!["swift-types".into()], name);
                }
                ui.separator();
                let needle = self.swift_filter.to_lowercase();
                let idx: Vec<usize> = data
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| needle.is_empty() || s.to_lowercase().contains(&needle))
                    .map(|(i, _)| i)
                    .collect();
                ui.label(
                    egui::RichText::new(format!("{} types", idx.len()))
                        .weak()
                        .small(),
                );
                let row_h = ui.text_style_height(&egui::TextStyle::Body);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, idx.len(), |ui, range| {
                        for &vi in &idx[range] {
                            let selected = self.swift_sel == Some(vi);
                            if ui.selectable_label(selected, &data[vi]).clicked() {
                                self.swift_sel = Some(vi);
                            }
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(entry) = self.swift_sel.and_then(|i| data.get(i)) else {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new("Select a Swift type").weak());
                });
                return;
            };
            let (kind, tyname) = match entry.split_once(' ') {
                Some((k, n)) => (k, n.trim()),
                None => ("", entry.as_str()),
            };
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!("{kind} {tyname}"))
                    .monospace()
                    .strong()
                    .size(14.0),
            );
            ui.separator();
            let body = cdata
                .iter()
                .find(|(n, _)| n == tyname)
                .map(|(_, b)| b.clone());
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match body {
                    Some(b) => self.class_body_view(ui, ctx, &b),
                    None if self.classes_loading => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("loading methods…");
                        });
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "No Objective-C-visible methods for this type.\n\
                                 Pure-Swift types (structs, enums, and classes not exposed to \
                                 the Objective-C runtime) carry no method addresses in \
                                 __swift5_types, so there is nothing to decompile from here.",
                            )
                            .weak(),
                        );
                    }
                });
        });

        self.swift = items;
        self.classes = classes;
    }

    fn ui_list_strings(&mut self, ctx: &egui::Context) {
        let items = self.strings.take();
        let data: &[(String, String)] = items.as_deref().unwrap_or(&[]);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("🔎");
                ui.text_edit_singleline(&mut self.strings_filter);
                if self.strings_loading {
                    ui.spinner();
                }
            });
            ui.separator();
            let needle = self.strings_filter.to_lowercase();
            let idx: Vec<usize> = data
                .iter()
                .enumerate()
                .filter(|(_, (_, s))| needle.is_empty() || s.to_lowercase().contains(&needle))
                .map(|(i, _)| i)
                .collect();
            ui.label(
                egui::RichText::new(format!("{} strings", idx.len()))
                    .weak()
                    .small(),
            );
            let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, row_h, idx.len(), |ui, range| {
                    for &vi in &idx[range] {
                        let (addr, s) = &data[vi];
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("{addr}  {s}")).monospace(),
                            )
                            .selectable(true),
                        );
                    }
                });
        });
        self.strings = items;
    }

    fn ui_disasm(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Full __text").clicked() {
                    self.disasm_loading = true;
                    self.disasm_loaded = false;
                    self.disasm_lines.clear();
                    self.dispatch(ctx, Which::Disasm, vec!["disasm".into()]);
                }
                ui.separator();
                ui.label("Jump to:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.disasm_addr)
                        .hint_text("0x100008000")
                        .desired_width(130.0),
                );
                ui.label("count:");
                ui.add(egui::TextEdit::singleline(&mut self.disasm_count).desired_width(56.0));
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let go = ui.button("Go").clicked() || enter;
                if self.disasm_loading {
                    ui.spinner();
                } else if self.disasm_loaded {
                    ui.weak(format!("{} lines", self.disasm_lines.len()));
                }
                if go && !self.disasm_addr.trim().is_empty() {
                    self.disasm_loading = true;
                    self.disasm_loaded = false;
                    self.disasm_lines.clear();
                    let count = self.disasm_count.trim().to_string();
                    let addr = self.disasm_addr.trim().to_string();
                    self.dispatch(
                        ctx,
                        Which::Disasm,
                        vec!["disasm".into(), addr, "--count".into(), count],
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.exporting, egui::Button::new("⬇ Export full __text"))
                        .on_hover_text("Disassemble all of __text and save to a file")
                        .clicked()
                    {
                        let name = format!("{}.disasm.txt", self.base_name());
                        self.start_export(ctx, vec!["disasm".into()], name);
                    }
                });
            });
            ui.separator();
            lines_pane(ui, &self.disasm_lines);
        });
    }

    fn ui_decompile(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Function address:");
                ui.add(egui::TextEdit::singleline(&mut self.decomp_addr).hint_text("0x100008000"));
                let go = ui.button("Decompile").clicked();
                if self.decomp_loading {
                    ui.spinner();
                }
                if go && !self.decomp_addr.trim().is_empty() {
                    self.decomp_loading = true;
                    self.decomp_out = None;
                    let addr = self.decomp_addr.trim().to_string();
                    self.dispatch(ctx, Which::Decompile, vec!["decompile".into(), addr]);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.exporting, egui::Button::new("⬇ Export project"))
                        .on_hover_text(
                            "Decompile the whole binary into a structured multi-folder \
                             project (classes/, categories/, functions/, manifest.csv).\n\
                             Pick a destination folder. Large binaries have hundreds of \
                             thousands of functions, so this can take a while.",
                        )
                        .clicked()
                    {
                        self.start_project_export(ctx);
                    }
                    if ui
                        .add_enabled(!self.exporting, egui::Button::new("⬇ Single file"))
                        .on_hover_text("Decompile every function into one flat .c file")
                        .clicked()
                    {
                        let name = format!("{}.decompiled.c", self.base_name());
                        self.start_export(ctx, vec!["decompile".into(), "--all".into()], name);
                    }
                });
            });
            ui.separator();
            output_pane(ui, self.decomp_out.as_deref());
        });
    }

    fn ui_chat(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("chat")
            .resizable(true)
            .default_width(360.0)
            .min_width(260.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong("💬 AI Assistant");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::ComboBox::from_id_salt("backend")
                            .selected_text(self.backend.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.backend, Backend::Claude, "Claude");
                                ui.selectable_value(&mut self.backend, Backend::Codex, "Codex");
                            });
                    });
                });
                ui.checkbox(&mut self.chat_context, "Send current view as context");
                ui.separator();

                egui::TopBottomPanel::bottom("chat_input")
                    .resizable(false)
                    .show_inside(ui, |ui| {
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::multiline(&mut self.chat_input)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY)
                                .hint_text("Ask about this binary…  (Ctrl+Enter to send)"),
                        );
                        let ctrl_enter =
                            ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            let can_send = !self.chat_running && !self.chat_input.trim().is_empty();
                            let clicked = ui
                                .add_enabled(can_send, egui::Button::new("Send"))
                                .clicked();
                            if self.chat_running {
                                ui.spinner();
                                ui.label("thinking…");
                            }
                            if ui.button("Clear").clicked() {
                                self.chat_msgs.clear();
                            }
                            if (clicked || ctrl_enter) && can_send {
                                self.send_chat(ctx);
                            }
                        });
                        ui.add_space(4.0);
                    });

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if self.chat_msgs.is_empty() {
                            ui.add_space(8.0);
                            ui.weak(
                                "Ask the assistant to explain a class, a decompiled function, \
                                 or a disassembly. Toggle the context checkbox to include the \
                                 current view.",
                            );
                        }
                        for m in &self.chat_msgs {
                            let (name, color) = match m.role {
                                Role::User => ("You", egui::Color32::from_rgb(100, 170, 240)),
                                Role::Assistant => {
                                    ("Assistant", egui::Color32::from_rgb(150, 200, 120))
                                }
                                Role::Error => ("Error", egui::Color32::from_rgb(220, 90, 90)),
                            };
                            ui.add_space(6.0);
                            ui.colored_label(color, name);
                            ui.add(
                                egui::Label::new(egui::RichText::new(&m.text).monospace())
                                    .selectable(true),
                            );
                        }
                    });
            });
    }

    fn send_chat(&mut self, ctx: &egui::Context) {
        let msg = self.chat_input.trim().to_string();
        if msg.is_empty() || self.chat_running {
            return;
        }
        self.chat_input.clear();
        self.chat_msgs.push(ChatMsg {
            role: Role::User,
            text: msg.clone(),
        });
        self.chat_running = true;
        let prompt = self.build_prompt(&msg);
        let backend = self.backend;
        let binary = self.binary.clone();
        let reipa_exe = self.reipa_exe.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = run_assistant(backend, &prompt, binary.as_deref(), &reipa_exe);
            let _ = tx.send(Msg::Chat(r));
            ctx.request_repaint();
        });
    }

    fn build_prompt(&self, new_msg: &str) -> String {
        let mut p = String::from(
            "You are an expert iOS reverse-engineering assistant embedded in ReIPA, a Mach-O \
             disassembler/decompiler. Be concise and technical.\n\n",
        );
        if !self.label.is_empty() {
            p.push_str(&format!("Binary: {}\n", self.label));
        }
        if let Some(bin) = &self.binary {
            p.push_str(&reipa_api_prompt(bin));
        }
        if self.chat_context {
            if let Some(view) = self.current_context() {
                let capped: String = view.chars().take(8000).collect();
                p.push_str("\nCurrent ReIPA view:\n```\n");
                p.push_str(&capped);
                p.push_str("\n```\n");
            }
        }
        let history = &self.chat_msgs[..self.chat_msgs.len().saturating_sub(1)];
        if !history.is_empty() {
            p.push_str("\nConversation so far:\n");
            for m in history {
                let who = match m.role {
                    Role::User => "User",
                    Role::Assistant => "Assistant",
                    Role::Error => continue,
                };
                p.push_str(&format!("{who}: {}\n", m.text));
            }
        }
        p.push_str(&format!("\nUser: {new_msg}\nAssistant:"));
        p
    }

    fn current_context(&self) -> Option<String> {
        match self.tab {
            Tab::Decompile => self.decomp_out.clone(),
            Tab::Disasm if !self.disasm_lines.is_empty() => Some(
                self.disasm_lines
                    .iter()
                    .take(400)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            Tab::Info => self.info.clone(),
            Tab::Classes => {
                let i = self.class_sel?;
                self.classes.as_ref()?.get(i).map(|(_, b)| b.clone())
            }
            _ => None,
        }
    }
}

fn reipa_api_prompt(binary: &Path) -> String {
    format!(
        "You can inspect this binary yourself by running the `reipa` command-line tool \
         (already on your PATH) through your shell. The binary under analysis is:\n  {bin}\n\
         Run these to gather facts before answering; prefer real output over guessing. \
         Use that path as <bin> (quote it):\n\
         - reipa info <bin>            header, segments, UUID, symbol/string counts\n\
         - reipa verify <bin>          encryption / FairPlay status\n\
         - reipa classdump <bin>       Objective-C @interface dump; methods note their address as 0x...\n\
         - reipa swift-types <bin>     Swift classes, structs, enums\n\
         - reipa symbols <bin>         symbols with addresses\n\
         - reipa strings <bin>         __cstring strings with addresses\n\
         - reipa objc <bin>            Objective-C selector / class-name / method-type pools\n\
         - reipa disasm <bin> <addr> [--count N]     arm64 disassembly from a virtual address\n\
         - reipa decompile <bin> <addr> [--count N]  pseudocode for the function at an address\n\
         Find addresses for disasm/decompile from classdump or symbols. Only run `reipa` commands.\n\n",
        bin = binary.display()
    )
}

fn prepend_path(dir: &Path) -> Option<std::ffi::OsString> {
    let existing = std::env::var_os("PATH")?;
    let mut dirs = vec![dir.to_path_buf()];
    dirs.extend(std::env::split_paths(&existing));
    std::env::join_paths(dirs).ok()
}

#[cfg(windows)]
fn allow_reipa_tool(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.raw_arg("--allowedTools \"Bash(reipa:*)\"");
}
#[cfg(not(windows))]
fn allow_reipa_tool(cmd: &mut std::process::Command) {
    cmd.args(["--allowedTools", "Bash(reipa:*)"]);
}

fn run_assistant(
    backend: Backend,
    prompt: &str,
    binary: Option<&Path>,
    reipa_exe: &Path,
) -> Result<String, String> {
    let prog = match backend {
        Backend::Claude => "claude",
        Backend::Codex => "codex",
    };
    let dir = std::env::temp_dir().join("reipa-gui");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmp = dir.join("prompt.txt");
    std::fs::write(&tmp, prompt).map_err(|e| e.to_string())?;
    let infile = std::fs::File::open(&tmp).map_err(|e| e.to_string())?;
    let last_msg = dir.join("codex_last.txt");
    let codex_tools = backend == Backend::Codex && binary.is_some();
    if codex_tools {
        let _ = std::fs::remove_file(&last_msg);
    }

    let mut cmd = base_cmd(prog);
    match backend {
        Backend::Claude => {
            cmd.arg("-p");
            if binary.is_some() {
                allow_reipa_tool(&mut cmd);
            }
        }
        Backend::Codex => {
            cmd.arg("exec");
            if binary.is_some() {
                cmd.arg("--dangerously-bypass-approvals-and-sandbox")
                    .arg("--skip-git-repo-check")
                    .arg("-o")
                    .arg(&last_msg);
            }
        }
    }

    if let Some(bin) = binary {
        if let Some(bdir) = bin.parent() {
            cmd.current_dir(bdir);
            if backend == Backend::Codex {
                cmd.arg("-C").arg(bdir);
            }
        }
        if let Some(rdir) = reipa_exe.parent() {
            if let Some(newpath) = prepend_path(rdir) {
                cmd.env("PATH", newpath);
            }
        }
    }

    cmd.stdin(Stdio::from(infile))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    no_window(&mut cmd);
    let out = cmd.output().map_err(|e| {
        format!("cannot launch '{prog}': {e}. Is the {prog} CLI installed and on PATH?")
    })?;
    if out.status.success() {
        let s = if codex_tools {
            std::fs::read_to_string(&last_msg)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        Ok(if s.is_empty() {
            "(no output)".into()
        } else {
            s
        })
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = err.trim();
        let msg = if msg.is_empty() {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        } else {
            msg.to_string()
        };
        Err(if msg.is_empty() {
            format!("{prog} exited with status {}", out.status)
        } else {
            msg
        })
    }
}

#[cfg(windows)]
fn base_cmd(program: &str) -> std::process::Command {
    let mut c = std::process::Command::new("cmd");
    c.arg("/c").arg(program);
    c
}
#[cfg(not(windows))]
fn base_cmd(program: &str) -> std::process::Command {
    std::process::Command::new(program)
}

fn no_window(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

fn output_pane(ui: &mut egui::Ui, text: Option<&str>) {
    let text = text.unwrap_or("");
    let def = ui.visuals().text_color();
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(egui::Label::new(highlight(text, def)).selectable(true));
        });
}

fn lines_pane(ui: &mut egui::Ui, lines: &[String]) {
    let def = ui.visuals().text_color();
    let row_h = ui.fonts(|f| f.row_height(&egui::FontId::monospace(12.0)));
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show_rows(ui, row_h, lines.len(), |ui, range| {
            for i in range {
                ui.add(egui::Label::new(highlight(&lines[i], def)).selectable(true));
            }
        });
}

const C_COMMENT: egui::Color32 = egui::Color32::from_rgb(120, 140, 120);
const C_NUMBER: egui::Color32 = egui::Color32::from_rgb(214, 157, 122);
const C_KEYWORD: egui::Color32 = egui::Color32::from_rgb(197, 134, 192);
const C_REGISTER: egui::Color32 = egui::Color32::from_rgb(86, 182, 194);
const C_STRING: egui::Color32 = egui::Color32::from_rgb(152, 195, 121);

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.' | '$' | '@' | '#')
}

fn is_register(w: &str) -> bool {
    if matches!(w, "sp" | "lr" | "fp" | "pc" | "xzr" | "wzr" | "nzcv") {
        return true;
    }
    let mut chars = w.chars();
    let first = chars.next();
    if !matches!(first, Some('x' | 'w' | 'v' | 'q' | 'd' | 's' | 'b' | 'h')) {
        return false;
    }
    let rest = &w[first.map(|c| c.len_utf8()).unwrap_or(0)..];
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn classify(w: &str, def: egui::Color32) -> egui::Color32 {
    if let Some(hex) = w.strip_prefix("0x") {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return C_NUMBER;
        }
    }
    if w.starts_with('#') || (!w.is_empty() && w.chars().all(|c| c.is_ascii_digit())) {
        return C_NUMBER;
    }
    if w.starts_with('@') {
        return C_KEYWORD;
    }
    if matches!(
        w,
        "if" | "else" | "goto" | "return" | "while" | "do" | "for" | "break" | "continue"
    ) {
        return C_KEYWORD;
    }
    if is_register(w) {
        return C_REGISTER;
    }
    def
}

fn highlight(text: &str, def: egui::Color32) -> egui::text::LayoutJob {
    use egui::text::{LayoutJob, TextFormat};
    let mut job = LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let font = egui::FontId::monospace(12.0);
    let fmt = |c: egui::Color32| TextFormat {
        font_id: font.clone(),
        color: c,
        ..Default::default()
    };

    for (li, line) in text.split('\n').enumerate() {
        if li > 0 {
            job.append("\n", 0.0, fmt(def));
        }
        let (code, comment) = match line.find("//") {
            Some(i) => (&line[..i], Some(&line[i..])),
            None => (line, None),
        };
        let mut rest = code;
        while !rest.is_empty() {
            let c = rest.chars().next().unwrap();
            if c == '"' {
                let mut end = c.len_utf8();
                for ch in rest[end..].chars() {
                    end += ch.len_utf8();
                    if ch == '"' {
                        break;
                    }
                }
                job.append(&rest[..end], 0.0, fmt(C_STRING));
                rest = &rest[end..];
            } else if is_word_char(c) {
                let end = rest.find(|c: char| !is_word_char(c)).unwrap_or(rest.len());
                let w = &rest[..end];
                job.append(w, 0.0, fmt(classify(w, def)));
                rest = &rest[end..];
            } else {
                let end = c.len_utf8();
                job.append(&rest[..end], 0.0, fmt(def));
                rest = &rest[end..];
            }
        }
        if let Some(cm) = comment {
            job.append(cm, 0.0, fmt(C_COMMENT));
        }
    }
    job
}

fn imp_of(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("// 0x")?;
    let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() {
        None
    } else {
        Some(format!("0x{hex}"))
    }
}

fn parse_classdump(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for line in text.lines() {
        if line.starts_with("@interface") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            let head = line.strip_prefix("@interface ").unwrap_or(line);
            let name = head.split(" :").next().unwrap_or(head).trim().to_string();
            cur = Some((name, String::new()));
        }
        if let Some((_, body)) = cur.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
        if line.starts_with("@end") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out
}

fn unwrap_out(r: Result<String, String>) -> String {
    match r {
        Ok(s) => s,
        Err(e) => format!("error: {e}"),
    }
}

fn run_cli(exe: &Path, args: &[String]) -> Result<String, String> {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    no_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(if err.trim().is_empty() {
            format!("reipa exited with {}", out.status)
        } else {
            err.into_owned()
        })
    }
}

/// Run `reipa` with stdout redirected straight into `out_path`, capturing only
/// stderr for error reporting. Avoids buffering huge exports in memory.
fn run_cli_to_file(exe: &Path, args: &[String], out_path: &Path) -> Result<(), String> {
    use std::io::Read;
    let file = std::fs::File::create(out_path)
        .map_err(|e| format!("cannot create {}: {e}", out_path.display()))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args)
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped());
    no_window(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
    let mut stderr = String::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut stderr);
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else if stderr.trim().is_empty() {
        Err(format!("reipa exited with {status}"))
    } else {
        Err(stderr.trim().to_string())
    }
}

/// Write class @interface bodies to a user-picked file. `selected` limits the
/// export to the checked class indices; `None` exports every class.
fn export_class_bodies(
    data: &[(String, String)],
    selected: Option<&std::collections::HashSet<usize>>,
    base: &str,
    msg: &mut Option<String>,
) {
    let default_name = match selected {
        Some(_) => format!("{base}.classes.selected.h"),
        None => format!("{base}.classes.h"),
    };
    let Some(save) = rfd::FileDialog::new()
        .set_file_name(&default_name)
        .save_file()
    else {
        return;
    };
    let mut buf = String::new();
    for (i, (_, body)) in data.iter().enumerate() {
        if let Some(sel) = selected {
            if !sel.contains(&i) {
                continue;
            }
        }
        buf.push_str(body);
        if !body.ends_with('\n') {
            buf.push('\n');
        }
        buf.push('\n');
    }
    *msg = Some(match std::fs::write(&save, buf) {
        Ok(()) => format!("Saved to {}", save.display()),
        Err(e) => format!("Export failed: {e}"),
    });
}

fn locate_sibling(stem: &str) -> PathBuf {
    let name = if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join(&name);
            if sib.exists() {
                return sib;
            }
        }
    }
    PathBuf::from(name)
}

fn open_binary(path: &Path) -> Result<Opened, String> {
    let mut head = [0u8; 4];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let _ = f.read(&mut head);
    }
    if &head == b"PK\x03\x04" {
        let out = extract_ipa(path)?;
        let label = format!(
            "{}  (extracted from {})",
            out.file_name().unwrap_or_default().to_string_lossy(),
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        Ok(Opened { path: out, label })
    } else {
        Ok(Opened {
            path: path.to_path_buf(),
            label: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        })
    }
}

fn extract_ipa(ipa: &Path) -> Result<PathBuf, String> {
    let file = std::fs::File::open(ipa).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("bad zip: {e}"))?;

    let mut exact: Option<String> = None;
    let mut fallback: Option<(String, u64)> = None;
    for i in 0..zip.len() {
        let f = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = f.name().replace('\\', "/");
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() == 3 && parts[0] == "Payload" && parts[1].ends_with(".app") {
            let app = parts[1].trim_end_matches(".app");
            if parts[2] == app {
                exact = Some(name.clone());
                break;
            }
            if !parts[2].contains('.') {
                let sz = f.size();
                if fallback.as_ref().map(|(_, s)| sz > *s).unwrap_or(true) {
                    fallback = Some((name.clone(), sz));
                }
            }
        }
    }
    let target = exact
        .or_else(|| fallback.map(|(n, _)| n))
        .ok_or("no Payload/<App>.app/<Executable> found in .ipa")?;

    let out_dir = std::env::temp_dir().join("reipa-gui");
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let exe_name = target.rsplit('/').next().unwrap_or("binary");
    let out_path = out_dir.join(exe_name);

    let mut entry = zip.by_name(&target).map_err(|e| e.to_string())?;
    let mut out = std::fs::File::create(&out_path).map_err(|e| e.to_string())?;
    std::io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
    Ok(out_path)
}

fn window_icon() -> Option<egui::IconData> {
    let img = image::load_from_memory(include_bytes!("../reipa.ico"))
        .ok()?
        .to_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1100.0, 720.0])
        .with_title("ReIPA");
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native("ReIPA", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
