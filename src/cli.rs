use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct LinkConverterOpt {
    pub src: PathBuf,
    pub is_from: bool,
    pub dst: Option<PathBuf>,
}

// cli.rs
#[derive(Clone, Debug, Default)]
pub struct Args {
    pub link_converter: Vec<LinkConverterOpt>,
    pub proxies: bool,
    pub proxy: Option<String>,

    pub proxy_delay: Option<String>,
    pub group_delay: Option<String>,
    pub url: String,
    pub timeout_ms: u64,

    pub groups: bool,
    pub group: Option<String>,
    pub select: Option<(String, String)>,

    pub rules: bool,
    pub connections: bool,
    pub close_all_connections: bool,
    pub close_connection: Option<String>,

    pub dns_query: Option<(String, String)>,
    pub flush_fakeip_cache: bool,
    pub flush_dns_cache: bool,
    pub upgrade_ui: bool,

    // API address
    pub api: String,
    pub token: Option<String>,
}

impl Args {
    pub fn parse() -> Self {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        match argv.first().map(String::as_str) {
            Some("--complete") => complete(&argv[1..]),
            Some("--completions") => {
                // print!("{}", include_str!("../completion.sh"));
                std::process::exit(0);
            }
            _ => {}
        }

        let mut args = Self::default();
        let mut last: Option<char> = None;
        let mut output: Option<char> = None;

        if args.api.is_empty() {
            args.api = "http://127.0.0.1:9090".into();
        }
        if args.url.is_empty() {
            args.url = "https://www.gstatic.com/generate_204".to_string();
        }
        if args.timeout_ms == 0 {
            args.timeout_ms = 5000;
        }

        let mut iter = argv.into_iter();
        while let Some(arg) = iter.next() {
            if let Some(flag) = arg.strip_prefix("--") {
                match flag {
                    // value-taking
                    "links-to-outbounds" => last = Some('l'),
                    "links-from-outbounds" => last = Some('L'),
                    "output" => last = Some('o'),
                    "proxy" => last = Some('p'),
                    "group" => last = Some('g'),
                    "proxy-delay" => last = Some('d'),
                    "group-delay" => last = Some('D'),
                    "select" => last = Some('s'),
                    "close-connection" => last = Some('c'),
                    "dns-query" => last = Some('q'),
                    "url" => last = Some('u'),
                    "timeout" => last = Some('t'),
                    "api" => last = Some('a'),
                    "token" => last = Some('T'),
                    // boolean
                    "proxies" => args.proxies = true,
                    "groups" => args.groups = true,
                    "rules" => args.rules = true,
                    "connections" => args.connections = true,
                    "close-all-connections" => args.close_all_connections = true,
                    "flush-fakeip-cache" => args.flush_fakeip_cache = true,
                    "flush-dns-cache" => args.flush_dns_cache = true,
                    "upgrade-ui" => args.upgrade_ui = true,
                    // terminal
                    "help" => {
                        println!("{}", help());
                        std::process::exit(0);
                    }
                    "version" => {
                        println!("{}", VERSION);
                        std::process::exit(0);
                    }
                    _ => (),
                }
            } else if let Some(flags) = arg.strip_prefix('-') {
                for c in flags.chars() {
                    match c {
                        'l' | 'L' | 'o' | 'p' | 'g' | 'd' | 'D' | 's' | 'c' | 'q' | 'u' | 't'
                        | 'a' | 'T' => last = Some(c),
                        'P' => args.proxies = true,
                        'G' => args.groups = true,
                        'R' => args.rules = true,
                        'C' => args.connections = true,
                        'X' => args.close_all_connections = true,
                        'F' => args.flush_fakeip_cache = true,
                        'N' => args.flush_dns_cache = true,
                        'U' => args.upgrade_ui = true,
                        'h' => {
                            println!("{}", help());
                            std::process::exit(0);
                        }
                        'V' => {
                            println!("{}", VERSION);
                            std::process::exit(0);
                        }
                        _ => (),
                    }
                }
            } else {
                match last.take() {
                    Some('l') => {
                        output.replace('l');
                        args.link_converter.push(LinkConverterOpt {
                            src: PathBuf::from(arg),
                            is_from: false,
                            dst: None,
                        });
                    }
                    Some('L') => {
                        output.replace('l');
                        args.link_converter.push(LinkConverterOpt {
                            src: PathBuf::from(arg),
                            is_from: true,
                            dst: None,
                        });
                    }
                    Some('o') => match output.take() {
                        Some('l') => {
                            args.link_converter
                                .last_mut()
                                .map(|l| l.dst = Some(PathBuf::from(arg)));
                        }
                        _ => {}
                    },
                    Some('p') => args.proxy = Some(arg),
                    Some('g') => args.group = Some(arg),
                    Some('d') => args.proxy_delay = Some(arg),
                    Some('D') => args.group_delay = Some(arg),
                    Some('s') => {
                        // select: первый токен — группа, второй — участник
                        match args.select.take() {
                            None => args.select = Some((arg, String::new())),
                            Some((g, _)) => args.select = Some((g, arg)),
                        }
                        last = Some('s');
                    }
                    Some('c') => args.close_connection = Some(arg),
                    Some('q') => {
                        // dns-query: первый токен — имя, второй — тип
                        match args.dns_query.take() {
                            None => args.dns_query = Some((arg, String::new())),
                            Some((n, _)) => args.dns_query = Some((n, arg)),
                        }
                        last = Some('q');
                    }
                    Some('u') => args.url = arg,
                    Some('t') => args.timeout_ms = arg.parse().unwrap_or(args.timeout_ms),
                    Some('a') => args.api = arg,
                    Some('T') => {
                        args.token.replace(arg);
                    }
                    _ => {}
                }
            }
        }

        args
    }
}

const VERSION: &str = concat!(
    "singbox-cli ",
    env!("CARGO_PKG_VERSION"),
    " [https://github.com/nlkli/recol]"
);

fn help() -> String {
    format!(
        "\
{VERSION}

USAGE:
    singbox-cli [OPTIONS]

API:
    -a, --api <URL>                   API base URL (default: http://127.0.0.1:9090)
    -T, --token <TOKEN>               Bearer token

PROXIES:
    -P, --proxies                     GET /proxies
    -p, --proxy <NAME>                GET /proxies/{{name}}
    -s, --select <GROUP> <MEMBER>     PUT /proxies/{{group}}
    -d, --proxy-delay <NAME>          GET /proxies/{{name}}/delay
    -u, --url <URL>                   Probe URL, https:// (default: gstatic 204)
    -t, --timeout <MS>                Probe timeout (proxy: 1..=32767, group: 1..=i32::MAX)

GROUPS:
    -G, --groups                      GET /group
    -g, --group <NAME>                GET /group/{{name}}
    -D, --group-delay <NAME>          GET /group/{{name}}/delay

RULES:
    -R, --rules                       GET /rules

CONNECTIONS:
    -C, --connections                 GET /connections
    -X, --close-all-connections       DELETE /connections
    -c, --close-connection <ID>       DELETE /connections/{{id}}

DNS:
    -q, --dns-query <NAME> <TYPE>     GET /dns/query (TYPE: A, AAAA, TXT, ...)

CACHE:
    -F, --flush-fakeip-cache          POST /cache/fakeip/flush
    -N, --flush-dns-cache             POST /cache/dns/flush

UI:
    -U, --upgrade-ui                  POST /upgrade/ui

LINK CONVERTER:
    -l, --links-to-outbounds <SRC>    links -> outbounds
    -L, --links-from-outbounds <SRC>  outbounds -> links
    -o, --output <DST>                Output for last -l/-L

MISC:
    -h, --help                        Print help
    -V, --version                     Print version
",
        VERSION = VERSION
    )
}

// fn help() -> String {
//     format!(
//         r#"sing-box cli tool
// {magenta}https://github.com/nlkli/singbox-cli{reset}
//
// {green}Usage:{reset} {blue}singbox-cli [OPTIONS]{reset}
//
// {green}Options:{reset} (most flags can be combined)
//   {blue}-h{reset}, {blue}--help{reset}; {blue}-V{reset}, {blue}--version{reset}; {blue}--completions{reset}; {blue}--logo{reset}"#,
//         reset = RESET,
//         green = GREEN,
//         blue = BLUE,
//         magenta = MAGENTA,
//     )
// }

// Standard ANSI color codes
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
// const BRIGHT_BLACK: &str = "\x1b[90m";
const BRIGHT_BLUE: &str = "\x1b[94m";
const BRIGHT_MAGENTA: &str = "\x1b[95m";

#[derive(Debug, Clone, Default)]
pub enum StdIn {
    #[default]
    None,
}

pub fn read_stdin(args: &Args) -> crate::Result<StdIn> {
    use std::io::{IsTerminal, Read};

    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(StdIn::None);
    }

    let mut input = String::new();
    stdin.read_to_string(&mut input)?;

    let trimmed = input.trim();

    Ok(StdIn::None)
}

const FLAGS: &[&str] = &[];

fn complete(args: &[String]) {
    // let idx: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    // let words = args.get(1..).unwrap_or(&[]);
    // let cur_owned: String = words
    //     .get(idx)
    //     .map(|s| {
    //         s.chars()
    //             .filter(|c| !matches!(c, '\\' | '"' | '\''))
    //             .collect()
    //     })
    //     .unwrap_or_default();
    // let cur = cur_owned.as_str();
    //
    // let mut j = idx;
    // while j > 0 && (words[j] == "=" || words[j - 1] == "=") {
    //     j -= 1;
    // }
    // let prev = j
    //     .checked_sub(1)
    //     .and_then(|i| words.get(i))
    //     .map(String::as_str);
    // let after_eq = idx > 0 && words[idx - 1] == "=";
    //
    // let out: Vec<String> = match prev {
    //     Some("-m" | "--media" | "-c" | "--contains") => vec![],
    //
    //     _ if cur.starts_with('-') => FLAGS
    //         .iter()
    //         .filter(|f| f.starts_with(cur))
    //         .map(|s| s.to_string())
    //         .collect(),
    //
    //     // _ => {}
    // };
    //
    // for s in out {
    //     println!("{s}");
    // }
    // std::process::exit(0);
}
