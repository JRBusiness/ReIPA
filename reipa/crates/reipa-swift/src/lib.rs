pub mod metadata;

pub fn demangle(sym: &str) -> String {
    if let Some(rest) = sym.strip_prefix("_Tt") {
        let mut p = Demangler { b: rest.as_bytes(), i: 0, depth: 0 };
        if let Some(s) = p.parse_type() {
            if p.i == p.b.len() {
                return s;
            }
        }
    }
    for pre in ["_$s", "$s", "_$S", "$S"] {
        if let Some(rest) = sym.strip_prefix(pre) {
            if let Some(s) = demangle_modern(rest) {
                return s;
            }
        }
    }
    sym.to_string()
}

fn demangle_modern(rest: &str) -> Option<String> {
    let mut p = Demangler { b: rest.as_bytes(), i: 0, depth: 0 };
    let module = p.parse_identifier()?;
    let mut path = vec![module];
    while let Some(id) = p.parse_identifier() {
        match p.peek() {
            Some(b'C') | Some(b'V') | Some(b'O') | Some(b'P') => {
                p.i += 1;
                path.push(id);
            }
            _ => {
                path.push(id);
                break;
            }
        }
    }
    if path.len() < 2 {
        return None;
    }
    Some(path.join("."))
}

const MAX_DEPTH: usize = 64;

struct Demangler<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Demangler<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn parse_type(&mut self) -> Option<String> {
        if self.depth > MAX_DEPTH {
            return None;
        }
        self.depth += 1;
        let r = self.parse_type_inner();
        self.depth -= 1;
        r
    }

    fn parse_type_inner(&mut self) -> Option<String> {
        match self.peek()? {
            b'C' | b'V' | b'O' | b'P' => {
                self.i += 1;
                let context = self.parse_context()?;
                let name = self.parse_name()?;
                Some(format!("{context}.{name}"))
            }
            b'G' => self.parse_generic(),
            b'S' => self.parse_stdlib_shortcut(),
            _ => None,
        }
    }

    fn parse_context(&mut self) -> Option<String> {
        match self.peek()? {
            b'C' | b'V' | b'O' | b'P' | b'G' | b'S' => self.parse_type(),
            b's' => {
                self.i += 1;
                Some("Swift".to_string())
            }
            c if c.is_ascii_digit() => self.parse_identifier(),
            _ => None,
        }
    }

    fn parse_name(&mut self) -> Option<String> {
        if self.peek() == Some(b'P') {
            self.i += 1;
            let _disc = self.parse_identifier()?;
            self.parse_identifier()
        } else {
            self.parse_identifier()
        }
    }

    fn parse_identifier(&mut self) -> Option<String> {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        let len: usize = core::str::from_utf8(&self.b[start..self.i]).ok()?.parse().ok()?;
        if len == 0 {
            return None;
        }
        let end = self.i.checked_add(len)?;
        if end > self.b.len() {
            return None;
        }
        let s = core::str::from_utf8(&self.b[self.i..end]).ok()?.to_string();
        self.i = end;
        Some(s)
    }

    fn parse_generic(&mut self) -> Option<String> {
        self.i += 1;
        let base = self.parse_type()?;
        let mut args = Vec::new();
        loop {
            match self.peek()? {
                b'_' => {
                    self.i += 1;
                    break;
                }
                _ => args.push(self.parse_type()?),
            }
            if args.len() > 64 {
                return None;
            }
        }
        Some(format!("{}<{}>", base, args.join(", ")))
    }

    fn parse_stdlib_shortcut(&mut self) -> Option<String> {
        self.i += 1;
        let name = match self.peek()? {
            b'S' => "Swift.String",
            b'i' => "Swift.Int",
            b'u' => "Swift.UInt",
            b'd' => "Swift.Double",
            b'f' => "Swift.Float",
            b'b' => "Swift.Bool",
            b'c' => "Swift.UnicodeScalar",
            b'a' => "Swift.Array",
            b'q' => "Swift.Optional",
            _ => return None,
        };
        self.i += 1;
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_class() {
        assert_eq!(demangle("_TtC6TWorld11Application"), "TWorld.Application");
        assert_eq!(demangle("_TtC10ADPService14ADPServiceImpl"), "ADPService.ADPServiceImpl");
    }

    #[test]
    fn swift_stdlib_module() {
        assert_eq!(demangle("_TtCs12_SwiftObject"), "Swift._SwiftObject");
    }

    #[test]
    fn nested_class() {
        assert_eq!(
            demangle("_TtCC10DDCommonUI26CameraPickerViewController18CenterFocusOverlay"),
            "DDCommonUI.CameraPickerViewController.CenterFocusOverlay"
        );
    }

    #[test]
    fn private_discriminator_dropped() {
        assert_eq!(
            demangle("_TtCC10MapboxMaps16MapboxObservableP33_D7FE31DC82D97CBC9D480B03D975E3C813BlockObserver"),
            "MapboxMaps.MapboxObservable.BlockObserver"
        );
    }

    #[test]
    fn struct_and_enum_kinds() {
        assert_eq!(demangle("_TtV4Core5Thing"), "Core.Thing");
        assert_eq!(demangle("_TtO4Core4Kind"), "Core.Kind");
    }

    #[test]
    fn non_swift_returned_unchanged() {
        assert_eq!(demangle("NSObject"), "NSObject");
        assert_eq!(demangle("UIViewController"), "UIViewController");
    }

    #[test]
    fn modern_mangling_nominal_path() {
        assert_eq!(demangle("_$s10Foundation10CocoaErrorV4CodeVMa"), "Foundation.CocoaError.Code");
        assert_eq!(
            demangle("_$s10Foundation10URLRequestV10httpMethodSSSgvg"),
            "Foundation.URLRequest.httpMethod"
        );
        assert_eq!(demangle("$s6TWorld11ApplicationCMa"), "TWorld.Application");
    }

    #[test]
    fn unparseable_falls_back_to_raw() {
        let raw = "_TtCFC8BrazeKitP33_9A88XYZ22NotificationClientLive3fooFT_T_L_9Inner";
        assert_eq!(demangle(raw), raw);
    }

    #[test]
    fn deeply_nested_does_not_overflow() {
        let s = format!("_Tt{}1A1B", "C".repeat(100_000));
        let _ = demangle(&s);
    }
}
