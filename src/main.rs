use clap::Parser;
use tokio::{
    signal,
    sync::mpsc::{self, Receiver, Sender},
};
use weirs::DriverFactory;
use weirs::{
    cli::{Cli, Command, UpArgs},
    config::Config,
    conn::{Connection, State},
};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let (tx, rx) = mpsc::channel::<State>(32);

    match cli.command {
        Command::Up(args) => {
            if let Err(e) = run_up(args, tx, rx).await {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Command::Down => todo!(),
    }
}

async fn run_up(
    args: UpArgs,
    tx: Sender<State>,
    mut rx: Receiver<State>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_args(args)?;
    let driver = DriverFactory::new(config.clone()).build()?;

    let mut conn = Connection::new(config, driver);
    conn.up(tx.clone()).await?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                conn.down(tx).await?;
                break;
            }
            Some(state) = rx.recv() => {
                match state {
                    State::Invalid(e) => {
                        eprintln!("Connection failed: {:?}", e);
                        break;
                    }
                    State::Disconnected => {
                        println!("{:?}", state);
                        break;
                    }
                    _ => println!("{:?}", state),
                }
            }
        }
    }

    Ok(())
}
