use std::path::PathBuf;

/// One `-l` / `-L` conversion request.
#[derive(Clone, Debug, Default)]
pub struct LinkConverterOpt {
    pub src: PathBuf,
    /// `true` for `-L` (outbounds -> links), `false` for `-l` (links -> outbounds).
    pub is_from: bool,
    /// Set by a following `-o`.
    pub dst: Option<PathBuf>,
}

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
    /// `(group, member)`
    pub select: Vec<(String, String)>,
    pub select_random: Vec<String>,
    // pub select_best: Vec<String>,

    pub rules: bool,
    pub connections: bool,
    pub close_all_connections: bool,
    pub close_connection: Vec<String>,

    /// `(name, record type)`
    pub dns_query: Option<(String, String)>,
    pub flush_fakeip_cache: bool,
    pub flush_dns_cache: bool,
    pub upgrade_ui: bool,

    pub api: String,
    pub token: Option<String>,

    pub uuid_tag: bool,

    pub interactive: bool,
}

impl Args {
    pub fn parse() -> Self {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        // match argv.first().map(String::as_str) {
        //     Some("--complete") => complete(&argv[1..]),
        //     Some("--completions") => {
        //         print!("{}", include_str!("../completion.sh"));
        //         std::process::exit(0);
        //     }
        //     _ => {}
        // }

        let mut args = Self::default();
        // Value flag waiting for its argument.
        let mut pending: Option<char> = None;
        let mut output_pending = false;
        let mut select_group: Option<String> = None;

        args.api =
            std::env::var("SINGBOX_CLASH_API").unwrap_or_else(|_| "http://127.0.0.1:9090".into());
        args.url = "https://www.gstatic.com/generate_204".to_string();
        args.timeout_ms = 5000;

        let mut iter = argv.into_iter();
        while let Some(arg) = iter.next() {
            if let Some(flag) = arg.strip_prefix("--") {
                match flag {
                    // value-taking
                    "links-to-outbounds" => pending = Some('l'),
                    "links-from-outbounds" => pending = Some('L'),
                    "output" => pending = Some('o'),
                    "proxy" => pending = Some('p'),
                    "group" => pending = Some('g'),
                    "proxy-delay" => pending = Some('d'),
                    "group-delay" => pending = Some('D'),
                    "select" => pending = Some('s'),
                    "select-rand" => pending = Some('S'),
                    "close-connection" => pending = Some('c'),
                    "dns-query" => pending = Some('q'),
                    "url" => pending = Some('u'),
                    "timeout" => pending = Some('t'),
                    "api" => pending = Some('a'),
                    "token" => pending = Some('T'),
                    // boolean
                    "proxies" => args.proxies = true,
                    "groups" => args.groups = true,
                    "rules" => args.rules = true,
                    "connections" => args.connections = true,
                    "interactive" => args.interactive = true,
                    "close-all-connections" => args.close_all_connections = true,
                    "flush-fakeip-cache" => args.flush_fakeip_cache = true,
                    "flush-dns-cache" => args.flush_dns_cache = true,
                    "upgrade-ui" => args.upgrade_ui = true,
                    "uuid-tag" => args.uuid_tag = true,
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
                        'l' | 'L' | 'o' | 'p' | 'g' | 'd' | 'D' | 's' | 'S' | 'c' | 'q' | 'u'
                        | 't' | 'a' | 'T' => pending = Some(c),
                        'P' => args.proxies = true,
                        'G' => args.groups = true,
                        'R' => args.rules = true,
                        'C' => args.connections = true,
                        'X' => args.close_all_connections = true,
                        'F' => args.flush_fakeip_cache = true,
                        'N' => args.flush_dns_cache = true,
                        'U' => args.upgrade_ui = true,
                        'Z' => args.uuid_tag = true,
                        'i' => args.interactive = true,
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
                match pending.take() {
                    Some(c @ ('l' | 'L')) => {
                        output_pending = true;
                        args.link_converter.push(LinkConverterOpt {
                            src: PathBuf::from(arg),
                            is_from: c == 'L',
                            dst: None,
                        });
                    }
                    Some('o') => {
                        if std::mem::take(&mut output_pending) {
                            if let Some(l) = args.link_converter.last_mut() {
                                l.dst = Some(PathBuf::from(arg));
                            }
                        }
                    }
                    Some('p') => args.proxy = Some(arg),
                    Some('g') => args.group = Some(arg),
                    Some('d') => args.proxy_delay = Some(arg),
                    Some('D') => args.group_delay = Some(arg),
                    // Two values: <group> <member>.
                    Some('s') => match select_group.take() {
                        None => {
                            select_group = Some(arg);
                            pending = Some('s');
                        }
                        Some(group) => args.select.push((group, arg)),
                    },
                    Some('S') => args.select_random.push(arg),
                    Some('c') => args.close_connection.push(arg),
                    // Two values: <name> <type>.
                    Some('q') => {
                        match args.dns_query.take() {
                            None => args.dns_query = Some((arg, String::new())),
                            Some((n, _)) => args.dns_query = Some((n, arg)),
                        }
                        pending = Some('q');
                    }
                    Some('u') => args.url = arg,
                    Some('t') => args.timeout_ms = arg.parse().unwrap_or(args.timeout_ms),
                    Some('a') => args.api = arg,
                    Some('T') => args.token = Some(arg),
                    _ => {}
                }
            }
        }
        if let Some(group) = select_group {
            args.select.push((group, String::new()));
        }

        args
    }

    pub fn build_singbox_clash_api_client(&self) -> crate::Result<singbox_clash_api::Client> {
        let mut builder = singbox_clash_api::Client::builder(&self.api);

        if let Some(ref t) = self.token {
            builder = builder.secret(t);
        }

        Ok(builder.build()?)
    }
}

const VERSION: &str = concat!(
    "sbcli ",
    env!("CARGO_PKG_VERSION"),
    " [https://github.com/nlkli/sbcli]"
);

fn help() -> String {
    format!(
        "\
{VERSION}

Usage: sbcli [OPTIONS]

  -a, --api <URL>                   Controller URL [env: SINGBOX_CLASH_API]
                                    [default: http://127.0.0.1:9090]
  -T, --token <TOKEN>               Bearer token (secret)
  -i, --interactive                 Interactive mode
Proxies
  -P, --proxies                     List proxies
  -p, --proxy <NAME>                Show a proxy
  -s, --select <GROUP> <NAME>       Select a group member
  -d, --proxy-delay <NAME>          Test a proxy delay
Groups
  -G, --groups                      List groups
  -g, --group <NAME>                Show a group
  -D, --group-delay <NAME>          Test a group delay
Delay test
  -u, --url <URL>                   Probe URL [default: gstatic 204]
  -t, --timeout <MS>                Probe timeout [default: 5000]
Rules and connections
  -R, --rules                       List rules
  -C, --connections                 List connections
  -c, --close-connection <ID>       Close a connection
  -X, --close-all-connections       Close all connections
DNS
  -q, --dns-query <NAME> <TYPE>     Query DNS (A, AAAA, TXT, ...)
  -N, --flush-dns-cache             Flush DNS cache
  -F, --flush-fakeip-cache          Flush fake-IP cache
Link converter
  -l, --links-to-outbounds <SRC>    Convert links to outbounds
  -L, --links-from-outbounds <SRC>  Convert outbounds to links
  -Z, --uuid-tag                    Rewrite tags to random UUIDs
  -o, --output <DST>                Output file for the preceding -l/-L
Other
  -U, --upgrade-ui                  
  -h, --help; -V, --version"
    )
}

// /// Every flag, offered when completing a word that starts with `-`.
// const FLAGS: &[&str] = &[
//     "-a",
//     "--api",
//     "-T",
//     "--token",
//     "-P",
//     "--proxies",
//     "-p",
//     "--proxy",
//     "-s",
//     "--select",
//     "-S",
//     "--select-rand",
//     "-d",
//     "--proxy-delay",
//     "-G",
//     "--groups",
//     "-g",
//     "--group",
//     "-D",
//     "--group-delay",
//     "-u",
//     "--url",
//     "-t",
//     "--timeout",
//     "-R",
//     "--rules",
//     "-C",
//     "--connections",
//     "-c",
//     "--close-connection",
//     "-X",
//     "--close-all-connections",
//     "-q",
//     "--dns-query",
//     "-N",
//     "--flush-dns-cache",
//     "-F",
//     "--flush-fakeip-cache",
//     "-l",
//     "--links-to-outbounds",
//     "-L",
//     "--links-from-outbounds",
//     "-o",
//     "--output",
//     "-U",
//     "--upgrade-ui",
//     "-h",
//     "--help",
//     "-V",
//     "--version",
// ];
//
// /// Record types offered after `--dns-query <NAME>`.
// const DNS_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"];
//
// /// Backend for `completion.sh`: `--complete <index> <word>...`.
// ///
// /// `word[0]` is the program name, `word[index]` the word being completed.
// /// Prints one candidate per line, or `@file` to ask the shell for file paths.
// /// The shell filters candidates by prefix.
// fn complete(args: &[String]) -> ! {
//     let idx: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
//     let words = args.get(1..).unwrap_or(&[]);
//     let word = |i: usize| words.get(i).map_or("", String::as_str);
//
//     let cur = word(idx);
//     let prev = idx.checked_sub(1).map_or("", word);
//     let prev2 = idx.checked_sub(2).map_or("", word);
//
//     if cur.starts_with('-') {
//         FLAGS.iter().for_each(|f| println!("{f}"));
//     } else if matches!(
//         prev,
//         "-l" | "--links-to-outbounds" | "-L" | "--links-from-outbounds" | "-o" | "--output"
//     ) {
//         println!("@file");
//     } else if matches!(prev2, "-q" | "--dns-query") {
//         DNS_TYPES.iter().for_each(|t| println!("{t}"));
//     }
//     std::process::exit(0);
// }
//
// # sbcli completion for bash and zsh: eval "$(sbcli --completions)"
// # Candidates come from `sbcli --complete <index> <words...>`.
// if [ -n "$ZSH_VERSION" ]; then
//     _singbox_cli() {
//         local -a c=( ${(f)"$("${words[1]}" --complete $((CURRENT - 1)) "${words[@]}" 2>/dev/null)"} )
//         if [[ $c[1] == @file ]]; then _files; else compadd -a c; fi
//     }
//     whence compdef >/dev/null || { autoload -Uz compinit; compinit; }
//     compdef _singbox_cli sbcli
// else
//     _singbox_cli() {
//         local out
//         out=$("${COMP_WORDS[0]}" --complete "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null)
//         if [[ $out == @file ]]; then out=$(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"); fi
//         COMPREPLY=( $(compgen -W "$out" -- "${COMP_WORDS[COMP_CWORD]}") )
//     }
//     complete -o filenames -F _singbox_cli sbcli
// fi
