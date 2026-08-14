//! Init boot configuration.
//!
//! Parsed from two sources, later ones overriding earlier ones:
//!
//! 1. `/etc/init.conf` in BOOTFS.
//! 2. The HBI kernel command line, using `init.`-prefixed keys.
//!
//! Everything here is fixed-capacity: init is `no_std` with no
//! allocator, so the stage table is an array and labels are inline
//! byte buffers rather than `&str` into a borrowed image. Copying the
//! label costs 32 bytes per stage and frees the caller from keeping
//! the BOOTFS mapping alive for the whole boot.
//!
//! Parsing never fails. A malformed line is counted and skipped: a
//! typo in a splash colour must not stop a machine from booting. The
//! count is reported on UART so the typo is still discoverable.

/// Maximum boot stages. Six today (driver-manager, storage, hxfs,
/// shutdown-broker, terminal, plus one spare); the array is sized with
/// headroom so adding a stage stays a config edit.
pub const MAX_STAGES: usize = 12;

/// Maximum bytes retained for a stage label.
pub const MAX_LABEL: usize = 32;

/// Maximum bytes retained for a stage id.
pub const MAX_ID: usize = 24;

/// Default per-stage timeout when the config does not override it.
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;

/// An RGB colour triple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

/// A fixed-capacity inline byte string.
#[derive(Clone, Copy)]
pub struct InlineStr<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> InlineStr<N> {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Copy up to `N` bytes of `src`. Longer input is truncated rather
    /// than rejected; a long label is a cosmetic problem, not a boot
    /// failure.
    pub fn from_bytes(src: &[u8]) -> Self {
        let mut out = Self::empty();
        let take = if src.len() > N { N } else { src.len() };
        out.bytes[..take].copy_from_slice(&src[..take]);
        out.len = take;
        out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("<non-utf8>")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

/// One boot stage: an id services are matched against, a relative
/// weight, a human label, and a wall-clock timeout.
#[derive(Clone, Copy)]
pub struct StageConfig {
    pub id: InlineStr<MAX_ID>,
    pub label: InlineStr<MAX_LABEL>,
    pub weight: u32,
    pub timeout_secs: u32,
}

impl StageConfig {
    const fn empty() -> Self {
        Self {
            id: InlineStr::empty(),
            label: InlineStr::empty(),
            weight: 1,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

/// Parsed init configuration.
#[derive(Clone, Copy)]
pub struct InitConfig {
    /// Mirror technical log text onto the framebuffer.
    pub log_screen: bool,
    /// Draw the graphical splash.
    pub splash: bool,
    pub spinner: bool,
    pub top: Rgb,
    pub bottom: Rgb,
    pub accent: Rgb,
    pub default_timeout_secs: u32,
    stages: [StageConfig; MAX_STAGES],
    stage_count: usize,
    /// Lines that parsed as neither a comment nor a known key.
    pub unknown_keys: u32,
    /// Lines whose value could not be parsed (bad colour, bad number).
    pub bad_values: u32,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl InitConfig {
    /// Built-in defaults, used verbatim when no config source exists.
    ///
    /// The default stage table mirrors the boot sequence init performs
    /// today. Weights are relative and reflect measured duration: the
    /// storage path (NVMe enumeration + Hxfs mount) dominates, so an
    /// unweighted bar would stall in the middle and then jump.
    pub const fn new() -> Self {
        Self {
            log_screen: false,
            splash: true,
            spinner: true,
            top: Rgb::new(10, 14, 34),
            bottom: Rgb::new(4, 6, 14),
            accent: Rgb::new(90, 200, 255),
            default_timeout_secs: DEFAULT_TIMEOUT_SECS,
            stages: [StageConfig::empty(); MAX_STAGES],
            stage_count: 0,
            unknown_keys: 0,
            bad_values: 0,
        }
    }

    /// Install the built-in stage table. Called before parsing so a
    /// config file can override weights and labels by id without
    /// having to redeclare the whole sequence.
    pub fn with_default_stages(mut self) -> Self {
        self.push_stage(b"selftest", b"Checking kernel interfaces", 5);
        self.push_stage(b"driver-manager", b"Starting driver manager", 10);
        self.push_stage(b"storage", b"Probing storage controller", 30);
        self.push_stage(b"shutdown-broker", b"Arming power control", 8);
        self.push_stage(b"terminal", b"Starting terminal", 12);
        self
    }

    fn push_stage(&mut self, id: &[u8], label: &[u8], weight: u32) {
        if self.stage_count >= MAX_STAGES {
            return;
        }
        let slot = &mut self.stages[self.stage_count];
        slot.id = InlineStr::from_bytes(id);
        slot.label = InlineStr::from_bytes(label);
        slot.weight = weight;
        slot.timeout_secs = self.default_timeout_secs;
        self.stage_count += 1;
    }

    pub fn stages(&self) -> &[StageConfig] {
        &self.stages[..self.stage_count]
    }

    pub fn stage_count(&self) -> usize {
        self.stage_count
    }

    fn stage_index(&mut self, id: &[u8]) -> Option<usize> {
        for (index, stage) in self.stages[..self.stage_count].iter().enumerate() {
            if stage.id.eq_bytes(id) {
                return Some(index);
            }
        }
        if self.stage_count >= MAX_STAGES {
            return None;
        }
        // Unknown stage id: declaring `stage.foo=5` creates the stage.
        // That is what makes the table data rather than code.
        let index = self.stage_count;
        let timeout = self.default_timeout_secs;
        let slot = &mut self.stages[index];
        slot.id = InlineStr::from_bytes(id);
        slot.label = InlineStr::from_bytes(id);
        slot.weight = 1;
        slot.timeout_secs = timeout;
        self.stage_count += 1;
        Some(index)
    }

    /// Parse `/etc/init.conf`.
    ///
    /// Line-oriented: everything after `=` up to the end of the line is
    /// the value, so labels may contain spaces. A `#` starts a comment
    /// that runs to end of line.
    pub fn parse_file(&mut self, blob: &[u8]) {
        for line in blob.split(|byte| *byte == b'\n' || *byte == b'\r') {
            let line = match comment_start(line) {
                Some(hash) => &line[..hash],
                None => line,
            };
            let line = trim(line);
            if line.is_empty() {
                continue;
            }
            self.parse_pair(line, b"");
        }
    }

    /// Parse the kernel command line, honouring only `prefix`-ed keys.
    ///
    /// Whitespace-separated, because that is how a command line is
    /// structured; values therefore cannot contain spaces. That is an
    /// accepted limit — a label with spaces belongs in the file.
    pub fn parse_cmdline(&mut self, blob: &[u8], prefix: &[u8]) {
        for token in blob.split(|byte| byte.is_ascii_whitespace()) {
            let token = trim(token);
            if token.is_empty() {
                continue;
            }
            self.parse_pair(token, prefix);
        }
    }

    fn parse_pair(&mut self, token: &[u8], prefix: &[u8]) {
        let Some(eq) = token.iter().position(|byte| *byte == b'=') else {
            self.unknown_keys += 1;
            return;
        };
        let key = trim(&token[..eq]);
        let value = trim(&token[eq + 1..]);
        if !prefix.is_empty() {
            let Some(stripped) = strip_prefix(key, prefix) else {
                // A cmdline token that is not ours (e.g. `panic_test=1`)
                // is not an error; it belongs to another consumer.
                return;
            };
            self.apply(stripped, value);
            return;
        }
        self.apply(key, value);
    }

    fn apply(&mut self, key: &[u8], value: &[u8]) {
        match key {
            b"log.screen" => match parse_bool(value) {
                Some(on) => self.log_screen = on,
                None => self.bad_values += 1,
            },
            b"splash" => match parse_bool(value) {
                Some(on) => self.splash = on,
                None => self.bad_values += 1,
            },
            b"splash.spinner" => match parse_bool(value) {
                Some(on) => self.spinner = on,
                None => self.bad_values += 1,
            },
            b"splash.top" => match parse_rgb(value) {
                Some(rgb) => self.top = rgb,
                None => self.bad_values += 1,
            },
            b"splash.bottom" => match parse_rgb(value) {
                Some(rgb) => self.bottom = rgb,
                None => self.bad_values += 1,
            },
            b"splash.accent" => match parse_rgb(value) {
                Some(rgb) => self.accent = rgb,
                None => self.bad_values += 1,
            },
            b"timeout.default" => match parse_u32(value) {
                Some(secs) => self.default_timeout_secs = secs,
                None => self.bad_values += 1,
            },
            _ => self.apply_prefixed(key, value),
        }
    }

    fn apply_prefixed(&mut self, key: &[u8], value: &[u8]) {
        if let Some(rest) = strip_prefix(key, b"stage.") {
            if let Some(id) = strip_suffix(rest, b".label") {
                let label = InlineStr::from_bytes(value);
                match self.stage_index(id) {
                    Some(index) => self.stages[index].label = label,
                    None => self.unknown_keys += 1,
                }
                return;
            }
            if let Some(id) = strip_suffix(rest, b".timeout") {
                match (parse_u32(value), self.stage_index(id)) {
                    (Some(secs), Some(index)) => self.stages[index].timeout_secs = secs,
                    (None, _) => self.bad_values += 1,
                    (_, None) => self.unknown_keys += 1,
                }
                return;
            }
            match (parse_u32(value), self.stage_index(rest)) {
                // Weight 0 would make a stage invisible on the bar
                // while still gating the boot; clamp to 1 so every
                // declared stage occupies a band.
                (Some(weight), Some(index)) => self.stages[index].weight = weight.max(1),
                (None, _) => self.bad_values += 1,
                (_, None) => self.unknown_keys += 1,
            }
            return;
        }
        if let Some(id) = strip_prefix(key, b"timeout.") {
            match (parse_u32(value), self.stage_index(id)) {
                (Some(secs), Some(index)) => self.stages[index].timeout_secs = secs,
                (None, _) => self.bad_values += 1,
                (_, None) => self.unknown_keys += 1,
            }
            return;
        }
        self.unknown_keys += 1;
    }

    /// Resolve interactions between keys after all sources are parsed.
    ///
    /// `splash=off` forces `log.screen=on`: a blank screen with no
    /// diagnostics is the one outcome nobody wants, so turning off the
    /// decorative surface turns on the useful one.
    pub fn finish(&mut self) {
        if !self.splash {
            self.log_screen = true;
        }
    }

    /// Sum of all stage weights, floored at 1 so progress arithmetic
    /// never divides by zero on an empty table.
    pub fn total_weight(&self) -> u32 {
        let mut total = 0u32;
        for stage in self.stages() {
            total = total.saturating_add(stage.weight);
        }
        total.max(1)
    }
}

/// Find the start of a trailing comment.
///
/// `#` only opens a comment at the start of a line or after
/// whitespace. Otherwise `splash.top=#0A0E22` would parse as an empty
/// value: `#` is both the comment marker and the conventional hex
/// colour prefix, and rejecting the familiar `#RRGGBB` spelling to
/// keep the lexer simple would be the wrong trade.
fn comment_start(line: &[u8]) -> Option<usize> {
    for (index, byte) in line.iter().enumerate() {
        if *byte != b'#' {
            continue;
        }
        let preceded_by_space = match index.checked_sub(1) {
            None => true,
            Some(previous) => line[previous].is_ascii_whitespace(),
        };
        if preceded_by_space {
            return Some(index);
        }
    }
    None
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() > prefix.len() && &bytes[..prefix.len()] == prefix {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn strip_suffix<'a>(bytes: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() > suffix.len() && &bytes[bytes.len() - suffix.len()..] == suffix {
        Some(&bytes[..bytes.len() - suffix.len()])
    } else {
        None
    }
}

fn parse_bool(value: &[u8]) -> Option<bool> {
    match value {
        b"on" | b"1" | b"true" | b"yes" => Some(true),
        b"off" | b"0" | b"false" | b"no" => Some(false),
        _ => None,
    }
}

fn parse_u32(value: &[u8]) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    let mut out: u32 = 0;
    for byte in value {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        out = out.checked_mul(10)?.checked_add(digit as u32)?;
    }
    Some(out)
}

fn parse_rgb(value: &[u8]) -> Option<Rgb> {
    let value = if value.len() == 7 && value[0] == b'#' {
        &value[1..]
    } else {
        value
    };
    if value.len() != 6 {
        return None;
    }
    Some(Rgb {
        r: hex_byte(value[0], value[1])?,
        g: hex_byte(value[2], value[3])?,
        b: hex_byte(value[4], value[5])?,
    })
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Look up a stage by id in a test. Returns a reference, panicking
    /// with the id when absent so a failure names the missing stage.
    fn stage<'a>(config: &'a InitConfig, id: &[u8]) -> &'a StageConfig {
        let position = config.stages().iter().position(|s| s.id.eq_bytes(id));
        assert!(
            position.is_some(),
            "stage not found: {}",
            core::str::from_utf8(id).unwrap_or("?")
        );
        &config.stages()[position.unwrap_or(0)]
    }

    #[test]
    fn defaults_hide_log_and_show_splash() {
        let config = InitConfig::new();
        assert!(!config.log_screen);
        assert!(config.splash);
    }

    #[test]
    fn splash_off_forces_log_on() {
        // The interaction that matters: never leave the operator with
        // a blank screen and no diagnostics.
        let mut config = InitConfig::new();
        config.parse_file(b"splash=off");
        config.finish();
        assert!(!config.splash);
        assert!(config.log_screen);
    }

    #[test]
    fn cmdline_prefix_ignores_foreign_keys() {
        let mut config = InitConfig::new();
        config.parse_cmdline(b"panic_test=1 init.log.screen=on extable_test=1", b"init.");
        assert!(config.log_screen);
        // Foreign cmdline tokens are not our errors.
        assert_eq!(config.unknown_keys, 0);
    }

    #[test]
    fn cmdline_overrides_file() {
        let mut config = InitConfig::new();
        config.parse_file(b"splash=on\nlog.screen=off\n");
        config.parse_cmdline(b"init.log.screen=on", b"init.");
        config.finish();
        assert!(config.log_screen);
        assert!(config.splash);
    }

    #[test]
    fn colours_parse_both_forms() {
        let mut config = InitConfig::new();
        config.parse_file(b"splash.top=#0A0E22\nsplash.bottom=04060e\n");
        assert_eq!(config.top, Rgb::new(10, 14, 34));
        assert_eq!(config.bottom, Rgb::new(4, 6, 14));
        assert_eq!(config.bad_values, 0);
    }

    #[test]
    fn bad_value_is_counted_not_fatal() {
        let mut config = InitConfig::new();
        config.parse_file(b"splash.top=zzz\nsplash=on\n");
        assert_eq!(config.bad_values, 1);
        // The good key on the next line still applies.
        assert!(config.splash);
        // And the default colour survives the bad one.
        assert_eq!(config.top, InitConfig::new().top);
    }

    #[test]
    fn file_values_may_contain_spaces() {
        // Regression: the first parser split file lines on whitespace
        // like a command line, so every multi-word label was silently
        // truncated to its first word.
        let mut config = InitConfig::new().with_default_stages();
        config.parse_file(b"stage.storage.label=Mounting the root volume\n");
        let stage = stage(&config, b"storage");
        assert_eq!(stage.label.as_str(), "Mounting the root volume");
    }

    #[test]
    fn trailing_comment_is_stripped_from_a_value() {
        let mut config = InitConfig::new().with_default_stages();
        config.parse_file(b"stage.storage=42  # heaviest stage\n");
        let stage = stage(&config, b"storage");
        assert_eq!(stage.weight, 42);
        assert_eq!(config.bad_values, 0);
        assert_eq!(config.unknown_keys, 0);
    }

    #[test]
    fn hash_colour_is_not_mistaken_for_a_comment() {
        // Regression: `#` is both the comment marker and the hex
        // colour prefix. It only opens a comment after whitespace.
        let mut config = InitConfig::new();
        config.parse_file(b"splash.accent=#5AC8FF # accent colour\n");
        assert_eq!(config.accent, Rgb::new(0x5A, 0xC8, 0xFF));
        assert_eq!(config.bad_values, 0);
        assert_eq!(config.unknown_keys, 0);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let mut config = InitConfig::new();
        config.parse_file(b"# comment\n\n   \nsplash=off\n");
        assert_eq!(config.unknown_keys, 0);
        assert_eq!(config.bad_values, 0);
        assert!(!config.splash);
    }

    #[test]
    fn stage_weight_and_label_override_by_id() {
        let mut config = InitConfig::new().with_default_stages();
        let before = config.stage_count();
        config.parse_file(b"stage.storage=50\nstage.storage.label=Mounting root\n");
        assert_eq!(
            config.stage_count(),
            before,
            "override must not add a stage"
        );
        let stage = stage(&config, b"storage");
        assert_eq!(stage.weight, 50);
        assert_eq!(stage.label.as_str(), "Mounting root");
    }

    #[test]
    fn unknown_stage_id_declares_a_new_stage() {
        // This is the property that keeps the table data, not code:
        // a future service is added by config alone.
        let mut config = InitConfig::new().with_default_stages();
        let before = config.stage_count();
        config.parse_file(b"stage.network=7\nstage.network.label=Bringing up network\n");
        assert_eq!(config.stage_count(), before + 1);
        let stage = stage(&config, b"network");
        assert_eq!(stage.weight, 7);
        assert_eq!(stage.label.as_str(), "Bringing up network");
    }

    #[test]
    fn zero_weight_is_clamped() {
        let mut config = InitConfig::new().with_default_stages();
        config.parse_file(b"stage.storage=0");
        let stage = stage(&config, b"storage");
        assert_eq!(stage.weight, 1);
    }

    #[test]
    fn timeouts_are_per_stage_with_a_default() {
        let mut config = InitConfig::new().with_default_stages();
        config.parse_file(b"timeout.storage=90");
        let storage = stage(&config, b"storage");
        let terminal = stage(&config, b"terminal");
        assert_eq!(storage.timeout_secs, 90);
        assert_eq!(terminal.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn stage_table_cannot_overflow() {
        let mut config = InitConfig::new().with_default_stages();
        for _ in 0..MAX_STAGES * 2 {
            config.parse_file(b"stage.extra=1");
        }
        assert!(config.stage_count() <= MAX_STAGES);
    }

    #[test]
    fn long_label_is_truncated_not_dropped() {
        let mut config = InitConfig::new().with_default_stages();
        config
            .parse_file(b"stage.storage.label=ThisLabelIsFarTooLongToFitInTheInlineBufferProvided");
        let stage = stage(&config, b"storage");
        assert_eq!(stage.label.as_bytes().len(), MAX_LABEL);
    }

    #[test]
    fn total_weight_never_zero() {
        let config = InitConfig::new();
        assert_eq!(config.stage_count(), 0);
        assert_eq!(config.total_weight(), 1);
    }
}
