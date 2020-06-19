#![crate_name = "internship_application_systems"]
use clap::crate_version;
use clap::{App, Arg, ArgMatches};
use fern::colors::{Color, ColoredLevelConfig};
use internship_application_systems::ping_core::Pinger;
use log::{debug, error, trace};
use std::process::exit;

fn set_up_logging(level: u64) {
    // configure colors for the whole line
    let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        // we actually don't need to specify the color for debug and info, they are white by default
        .info(Color::White)
        .debug(Color::White)
        // depending on the terminals color scheme, this is the same as the background color
        .trace(Color::BrightBlack);

    // configure colors for the name of the level.
    // since almost all of them are the some as the color for the whole line, we
    // just clone `colors_line` and overwrite our changes
    let colors_level = colors_line.clone().info(Color::Green);
    // here we set up our fern Dispatch
    let verbosity = match level {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{color_line}[{date}][{target}][{level}{color_line}] {message}\x1B[0m",
                color_line = format_args!(
                    "\x1B[{}m",
                    colors_line.get_color(&record.level()).to_fg_str()
                ),
                date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                target = record.target(),
                level = colors_level.color(record.level()),
                message = message,
            ));
        })
        // set the default log level. to filter out verbose log messages from dependencies, set
        // this to Warn and overwrite the log level for your crate.
        .level(verbosity)
        // change log levels for individual modules. Note: This looks for the record's target
        // field which defaults to the module path but can be overwritten with the `target`
        // parameter:
        // `info!(target="special_target", "This log message is about special_target");`
        .level_for("pretty_colored", log::LevelFilter::Trace)
        // output to stdout
        .chain(std::io::stdout())
        .apply()
        .expect("Failed setting up logging");
    trace!("finished setting up logging! yay!");
}

fn main() {
    let args = App::new("ping")
        .version(crate_version!())
        .about("Pings hosts :)")
        .arg(
            Arg::with_name("hostname")
                .index(1)
                .value_name("Hostname")
                .help("Sets hostname or ip address to ping")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("ttl")
                .help("Sets ttl")
                .required(false)
                .short("t")
                .long("--ttl")
                .help(" Set the IP Time to Live")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("timeout")
                .help("Sets timeout for echo reply. Time resolution is in ms.")
                .short("W")
                .long("--timeout")
                .takes_value(true)
                .default_value("1000"),
        )
        .arg(
            Arg::with_name("verbosity")
                .help("Sets verbosity")
                .long_help("1 v for Error, 2 for debug, 3 and more for tracing")
                .short("v")
                .multiple(true),
        )
        .get_matches();
    process(args);
}

fn process(args: ArgMatches) {
    let hostname = args.value_of("hostname").unwrap(); //It's required field, how 'll it fail?
    let ttl = if args.is_present("ttl") {
        match args.value_of("ttl").unwrap().parse::<u16>() {
            Ok(a) => {
                debug!("Ttl is set to {}", a);
                a
            }
            Err(e) => {
                error!("Failed parsing ttl : {}", e);
                std::process::exit(1);
            }
        }
    } else {
        64 //recommended ttl size
    };
    let verb_level = args.occurrences_of("verbosity");
    set_up_logging(verb_level);
    let timeout = match args.value_of("timeout").unwrap().parse::<u64>() {
        //default field, unwrapping it with a calm soul
        Ok(a) => {
            debug!("Set {} for timeout", a);
            a
        }
        Err(e) => {
            error!("Error parsing timeout: {}", e);
            exit(1);
        }
    };
    if ttl >= 255 {
        error!("Ttl cannot be bigger then 255");
        exit(1)
    } else if ttl == 0 {
        error!("Cannot set unicast time-to-live");
        exit(1);
    }
    let mut pinger = Pinger::new(
        hostname,
        ttl as u8,
        std::time::Duration::from_millis(timeout),
    );
    pinger.run();
}
