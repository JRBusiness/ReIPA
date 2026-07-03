const MAX_TYPE_DEPTH: usize = 64;

pub fn decode_type(enc: &str) -> String {
    let mut p = Parser::new(enc);
    p.parse_type_d(0).unwrap_or_else(|| enc.to_string())
}

pub fn method_signature(selector: &str, encoding: &str) -> String {
    let mut p = Parser::new(encoding);
    let ret = p.parse_type_d(0).unwrap_or_else(|| "id".to_string());
    p.read_number();

    let mut args = Vec::new();
    while p.peek().is_some() {
        match p.parse_type_d(0) {
            Some(t) => {
                p.read_number();
                args.push(t);
            }
            None => break,
        }
    }
    let params: Vec<String> = if args.len() >= 2 {
        args[2..].to_vec()
    } else {
        Vec::new()
    };

    let colon_count = selector.matches(':').count();
    if colon_count == 0 {
        return format!("({}){}", ret, selector);
    }
    let parts: Vec<&str> = selector.split(':').collect();
    let mut out = format!("({})", ret);
    for idx in 0..colon_count {
        let keyword = parts.get(idx).copied().unwrap_or("");
        let ty = params.get(idx).cloned().unwrap_or_else(|| "id".to_string());
        out.push_str(&format!("{}:({})arg{} ", keyword, ty, idx + 1));
    }
    out.trim_end().to_string()
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Parser<'a> {
        Parser {
            b: s.as_bytes(),
            i: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn read_number(&mut self) -> String {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.b[start..self.i]).into_owned()
    }

    fn read_quoted(&mut self) -> String {
        self.i += 1;
        let start = self.i;
        while matches!(self.peek(), Some(c) if c != b'"') {
            self.i += 1;
        }
        let s = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
        if self.peek() == Some(b'"') {
            self.i += 1;
        }
        s
    }

    fn read_balanced(&mut self, open: u8, close: u8) -> String {
        self.i += 1;
        let start = self.i;
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            self.i += 1;
        }
        let inner = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
        if self.peek() == Some(close) {
            self.i += 1;
        }
        inner
    }

    fn skip_qualifiers(&mut self) -> bool {
        let mut is_const = false;
        while let Some(c) = self.peek() {
            match c {
                b'r' => {
                    is_const = true;
                    self.i += 1;
                }
                b'n' | b'N' | b'o' | b'O' | b'R' | b'V' => self.i += 1,
                _ => break,
            }
        }
        is_const
    }

    fn parse_type_d(&mut self, depth: usize) -> Option<String> {
        if depth > MAX_TYPE_DEPTH {
            return Some("?".to_string());
        }
        let is_const = self.skip_qualifiers();
        let c = self.peek()?;
        let ty = match c {
            b'v' => self.take("void"),
            b'c' => self.take("char"),
            b'i' => self.take("int"),
            b's' => self.take("short"),
            b'l' => self.take("long"),
            b'q' => self.take("long long"),
            b'C' => self.take("unsigned char"),
            b'I' => self.take("unsigned int"),
            b'S' => self.take("unsigned short"),
            b'L' => self.take("unsigned long"),
            b'Q' => self.take("unsigned long long"),
            b'f' => self.take("float"),
            b'd' => self.take("double"),
            b'D' => self.take("long double"),
            b'B' => self.take("BOOL"),
            b'*' => self.take("char *"),
            b'#' => self.take("Class"),
            b':' => self.take("SEL"),
            b'@' => {
                self.i += 1;
                match self.peek() {
                    Some(b'"') => {
                        let name = self.read_quoted();
                        if name.is_empty() {
                            "id".to_string()
                        } else if name.starts_with('<') {
                            format!("id {}", name)
                        } else {
                            format!("{} *", name)
                        }
                    }
                    Some(b'?') => {
                        self.i += 1;
                        "id /* block */".to_string()
                    }
                    _ => "id".to_string(),
                }
            }
            b'?' => self.take("void *"),
            b'^' => {
                self.i += 1;
                let inner = self
                    .parse_type_d(depth + 1)
                    .unwrap_or_else(|| "void".to_string());
                format!("{} *", inner)
            }
            b'{' => {
                let inner = self.read_balanced(b'{', b'}');
                named_aggregate(&inner, "struct")
            }
            b'(' => {
                let inner = self.read_balanced(b'(', b')');
                named_aggregate(&inner, "union")
            }
            b'[' => {
                let inner = self.read_balanced(b'[', b']');
                let digits: String = inner.chars().take_while(|c| c.is_ascii_digit()).collect();
                let elem = Parser::new(&inner[digits.len()..])
                    .parse_type_d(depth + 1)
                    .unwrap_or_else(|| "void".to_string());
                format!("{}[{}]", elem, digits)
            }
            b'b' => {
                self.i += 1;
                let n = self.read_number();
                format!("int : {}", n)
            }
            _ => {
                self.i += 1;
                (c as char).to_string()
            }
        };
        Some(if is_const {
            format!("const {}", ty)
        } else {
            ty
        })
    }

    fn take(&mut self, s: &str) -> String {
        self.i += 1;
        s.to_string()
    }
}

fn named_aggregate(inner: &str, anon: &str) -> String {
    let name = inner.split('=').next().unwrap_or("");
    if name.is_empty() || name == "?" {
        anon.to_string()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives() {
        assert_eq!(decode_type("v"), "void");
        assert_eq!(decode_type("B"), "BOOL");
        assert_eq!(decode_type("Q"), "unsigned long long");
        assert_eq!(decode_type("d"), "double");
        assert_eq!(decode_type("q"), "long long");
        assert_eq!(decode_type("#"), "Class");
        assert_eq!(decode_type(":"), "SEL");
        assert_eq!(decode_type("*"), "char *");
    }

    #[test]
    fn objects_and_blocks() {
        assert_eq!(decode_type("@"), "id");
        assert_eq!(decode_type("@\"NSString\""), "NSString *");
        assert_eq!(decode_type("@\"<MTLTexture>\""), "id <MTLTexture>");
        assert_eq!(decode_type("@?"), "id /* block */");
    }

    #[test]
    fn pointers_structs_arrays() {
        assert_eq!(decode_type("^i"), "int *");
        assert_eq!(decode_type("^v"), "void *");
        assert_eq!(decode_type("^{__CVBuffer=}"), "__CVBuffer *");
        assert_eq!(decode_type("{CGRect={CGPoint=dd}{CGSize=dd}}"), "CGRect");
        assert_eq!(decode_type("{?=ii}"), "struct");
        assert_eq!(decode_type("[10i]"), "int[10]");
        assert_eq!(decode_type("r^v"), "const void *");
    }

    #[test]
    fn no_arg_method() {
        assert_eq!(
            method_signature("startUpdating", "v16@0:8"),
            "(void)startUpdating"
        );
        assert_eq!(
            method_signature("isRecording", "B16@0:8"),
            "(BOOL)isRecording"
        );
    }

    #[test]
    fn one_arg_method() {
        assert_eq!(
            method_signature("enableHookPresent:", "v20@0:8B16"),
            "(void)enableHookPresent:(BOOL)arg1"
        );
    }

    #[test]
    fn multi_arg_method_with_block() {
        assert_eq!(
            method_signature("startRecordingWithConfig:completion:", "v32@0:8@16@?24"),
            "(void)startRecordingWithConfig:(id)arg1 completion:(id /* block */)arg2"
        );
    }

    #[test]
    fn method_returning_object() {
        assert_eq!(
            method_signature("converToCodecConfig:", "@24@0:8@16"),
            "(id)converToCodecConfig:(id)arg1"
        );
    }

    #[test]
    fn unparseable_encoding_falls_back() {
        assert_eq!(method_signature("foo", ""), "(id)foo");
    }

    #[test]
    fn deeply_nested_pointers_do_not_overflow() {
        let enc = format!("{}v", "^".repeat(100_000));
        let out = decode_type(&enc);
        assert!(out.ends_with('*') || out.contains('?'), "got: {out}");
    }

    #[test]
    fn deeply_nested_arrays_do_not_overflow() {
        let enc = format!("{}{}i{}", "[1".repeat(50_000), "", "]".repeat(50_000));
        let _ = decode_type(&enc);
    }
}
