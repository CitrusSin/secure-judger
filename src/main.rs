mod secrun;
mod judger;
mod utils;

use std::env;
use std::path::PathBuf;
use std::time::Duration;
use judger::JudgeSession;

fn main() {
    let args: Vec<String> = env::args().into_iter().collect();
    if args.len() < 4 {
        println!("Usage: {} <stdin file> <standard answer file> <executable> [args...]", args[0]);
        return;
    }
    
    let exec_path = utils::find_path(&args[3]);
    let input_file_path = PathBuf::from(&args[1]);
    let std_ans_path = PathBuf::from(&args[2]);
    let exec_args: Vec<&str> = args.iter().skip(3).map(|x| x.as_str()).collect();
    let session = JudgeSession::new(
        exec_path,
        input_file_path,
        std_ans_path,
        Duration::from_secs(1),
        104857600
    );
    let result = match session.run_judge(&exec_args) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to run program");
            println!("Error: {e}");
            return;
        }
    };

    if result.accepted() {
        println!("Congratulations, accepted!");
    }
    println!("RESULT BEGIN>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    println!("{result}");
    println!("RESULT END>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
}
