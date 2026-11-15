mod cli;
mod link;
mod models;

use std::io::{BufRead, Write};
use std::time::Duration;

use singbox_clash_api::Client;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn main() -> Result<()> {
    let args = cli::Args::parse();

    for opt in args.link_converter.iter() {
        if opt.is_from {
            let file = std::fs::File::open(&opt.src)?;
            let mut outbounds: Vec<models::AnyOutbound> = serde_json::from_reader(file)?;

            let mut out: Box<dyn Write> = if let Some(ref dst) = opt.dst {
                Box::new(std::fs::File::create(dst)?)
            } else {
                Box::new(std::io::stdout())
            };

            for (n, o) in outbounds.iter_mut().enumerate() {
                if args.uuid_tag {
                    let uid = uuid::Uuid::new_v4();
                    *o.tag_mut() = uid.to_string();
                }
                match link::any_outbound_to_link(o) {
                    Ok(l) => writeln!(out, "{l}")?,
                    Err(err) => eprintln!("#{n} {err}"),
                }
            }
        } else {
            let file = std::fs::File::open(&opt.src)?;
            let reader = std::io::BufReader::new(file);
            let mut outbounds = Vec::new();

            for line in reader.lines() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match link::parse_any_link(trimmed) {
                    Ok(mut o) => {
                        if args.uuid_tag {
                            let uid = uuid::Uuid::new_v4();
                            *o.tag_mut() = uid.to_string();
                        }
                        outbounds.push(o);
                    }
                    Err(err) => eprintln!("{line} {err}"),
                }
            }

            let json = serde_json::to_string_pretty(&outbounds)?;

            if let Some(ref out_path) = opt.dst {
                std::fs::write(out_path, json)?;
            } else {
                println!("{json}");
            }
        }
    }

    let has_api_cmd = args.proxies
        || args.proxy.is_some()
        || args.select.is_some()
        || args.proxy_delay.is_some()
        || args.groups
        || args.group.is_some()
        || args.group_delay.is_some()
        || args.rules
        || args.connections
        || args.close_all_connections
        || args.close_connection.is_some()
        || args.dns_query.is_some()
        || args.flush_fakeip_cache
        || args.flush_dns_cache
        || args.upgrade_ui;

    // No API commands: exit without initializing Tokio
    if !has_api_cmd {
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(run_api(args))
}

async fn run_api(args: cli::Args) -> Result<()> {
    let mut builder = Client::builder(&args.api);

    if let Some(ref t) = args.token {
        builder = builder.secret(t);
    }

    let client = builder.build()?;

    if args.proxies {
        print_json(
            &client
                .proxies()
                .await?
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>(),
        )?;
    }
    if let Some(name) = args.proxy.as_deref() {
        print_json(&client.proxy(name).await?)?;
    }
    if let Some((group, member)) = args.select.as_ref() {
        if member.is_empty() {
            return Err("member name must not be empty".into());
        }

        client.select_proxy(group, member).await?;
    }
    if let Some(g) = args.select_random.as_ref() {
        let group = client.group(g).await?;
        let all = group.all.unwrap_or(vec![]);
        if !all.is_empty() {
            if let Some(member) = fastrand::choice(all.iter()) {
                client.select_proxy(g, member).await?;
            }
        }
    }
    if let Some(name) = args.proxy_delay.as_deref() {
        if !(1..=32767).contains(&args.timeout_ms) {
            return Err("probe timeout must be between 1 and 32767 milliseconds".into());
        }

        let d = client
            .proxy_delay(name, &args.url, Duration::from_millis(args.timeout_ms))
            .await?;

        print_json(&serde_json::json!({
            "name": name,
            "delay_ms": d.as_millis() as u64
        }))?;
    }
    if args.groups {
        print_json(&client.groups().await?)?;
    }
    if let Some(name) = args.group.as_deref() {
        print_json(&client.group(name).await?)?;
    }
    if let Some(name) = args.group_delay.as_deref() {
        if !(1..=i32::MAX as u64).contains(&args.timeout_ms) {
            return Err("probe timeout must be between 1 and 2147483647 milliseconds".into());
        }

        let map = client
            .group_delay(name, &args.url, Duration::from_millis(args.timeout_ms))
            .await?;

        let out: std::collections::BTreeMap<String, u64> = map
            .into_iter()
            .map(|(k, v)| (k, v.as_millis() as u64))
            .collect();

        print_json(&out)?;
    }
    if args.rules {
        print_json(&client.rules().await?)?;
    }
    if args.connections {
        print_json(&client.connections().await?)?;
    }
    if args.close_all_connections {
        client.close_all_connections().await?;
    }
    if let Some(id) = args.close_connection.as_deref() {
        client.close_connection(id).await?;
    }
    if let Some((name, ty)) = args.dns_query.as_ref() {
        if ty.is_empty() {
            return Err("record type must not be empty".into());
        }
        print_json(&client.dns_query(name, ty).await?)?;
    }
    if args.flush_fakeip_cache {
        client.flush_fakeip_cache().await?;
    }
    if args.flush_dns_cache {
        client.flush_dns_cache().await?;
    }
    if args.upgrade_ui {
        client.upgrade_ui().await?;
    }

    Ok(())
}
