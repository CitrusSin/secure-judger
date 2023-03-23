use std::error::Error;
use std::fmt::Display;
use std::fs::{File, self};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::ffi::OsStr;
use std::time::{Instant, Duration};
use core::mem::size_of;

use crate::secrun;

pub enum RuntimeErrorKind {
    FloatingPointError,
    SegmentationFault
}

impl Display for RuntimeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match &self {
            Self::FloatingPointError    => "FloatingPointError",
            Self::SegmentationFault     => "SegmentationFault"
        };
        f.write_str(str)?;
        Ok(())
    }
}

pub enum JudgeStatus {
    Accepted,
    WrongAnswer,
    TimeLimitExceeded,
    MemoryLimitExceeded,
    RuntimeError(RuntimeErrorKind),
    PresentationError,
    ReturnNonZero(i32)
}

impl JudgeStatus {
    fn abbr(&self) -> &'static str {
        match &self {
            Self::Accepted              => "AC",
            Self::WrongAnswer           => "WA",
            Self::TimeLimitExceeded     => "TLE",
            Self::MemoryLimitExceeded   => "MLE",
            Self::PresentationError     => "PE",
            Self::RuntimeError(_)       => "RE",
            Self::ReturnNonZero(_)      => "RNZ"
        }
    }
}

impl Display for JudgeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match &self {
            Self::Accepted              => "Accepted",
            Self::WrongAnswer           => "Wrong Answer",
            Self::TimeLimitExceeded     => "Time Limit Exceeded",
            Self::MemoryLimitExceeded   => "Memory Limit Exceeded",
            Self::PresentationError     => "Presentation Error",
            Self::RuntimeError(ek) => {
                f.write_fmt(format_args!("{}: Runtime Error ({ek})", self.abbr()))?;
                return Ok(());
            },
            Self::ReturnNonZero(ret_val) => {
                f.write_fmt(format_args!("{}: Return Value Not Zero ({ret_val})", self.abbr()))?;
                return Ok(());
            }
        };
        let abbr = self.abbr();
        f.write_fmt(format_args!("{abbr}: "))?;
        f.write_str(message)?;
        Ok(())
    }
}

pub struct JudgeResult {
    pub status: JudgeStatus,
    pub time_used: Duration,
    pub cpu_time_ms: u64,
    pub memory_used_bytes: u64
}

impl JudgeResult {
    pub fn accepted(&self) -> bool {
        match self.status {
            JudgeStatus::Accepted => true,
            _ => false
        }
    }
}

impl Display for JudgeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MEM_UNITS: [&'static str; 4] = ["B", "KiB", "MiB", "GiB"];
        let mut mem_display: f64 = self.memory_used_bytes as f64;
        let mut display_level: usize = 0;
        while mem_display > 1024.0 && display_level < 4 {
            mem_display /= 1024.0;
            display_level += 1;
        }
        f.write_fmt(format_args!("Status:  \t{}\n", self.status))?;
        f.write_fmt(format_args!("Used Real Time:\t{}ms\n", self.time_used.as_millis()))?;
        f.write_fmt(format_args!("Used CPU Time:\t{}ms\n", self.cpu_time_ms))?;
        f.write_fmt(format_args!("Used Memory:\t{:.2}{}", mem_display, MEM_UNITS[display_level]))?;
        Ok(())
    }
}

pub struct JudgeSession {
    exec: PathBuf,
    input_file: PathBuf,
    standard_ans_file: PathBuf,
    max_allowed_time: Duration,
    max_allowed_memory_bytes: u64
}

impl JudgeSession {
    pub fn new(
        exec: PathBuf,
        input_file: PathBuf,
        standard_ans_file: PathBuf,
        max_allowed_time: Duration,
        max_allowed_memory_bytes: u64
    ) -> Self {
        JudgeSession {
            exec,
            input_file,
            standard_ans_file,
            max_allowed_time,
            max_allowed_memory_bytes
        }
    }

    pub fn run_judge(self, args: &[&str]) -> Result<JudgeResult, Box<dyn Error>> {
        const WAIT_DURATION: Duration = Duration::from_micros(100);

        let mut tmp_out = PathBuf::from("/tmp/");
        tmp_out.push(format!(
            "{}.out", 
            self.input_file.file_name().unwrap_or(OsStr::new("tmp")).to_string_lossy()
        ));

        if tmp_out.exists() {
            if tmp_out.is_dir() {
                fs::remove_dir(&tmp_out)?;
            } else {
                fs::remove_file(&tmp_out)?;
            }
        }
        drop(File::create(&tmp_out)?);

        let (pid, begin_instant) = secrun::sandbox_run(
            &self.exec, 
            args, 
            &self.input_file, 
            &tmp_out
        )?;

        let mut return_value: i32 = 0;
        let stop_instant;
        let res_used;
        unsafe {
            // Initialize C-style struct rusage with zeros
            let mut res_used_buf: libc::rusage = std::mem::transmute([0u8;size_of::<libc::rusage>()]);
            loop {
                let p = libc::wait4(pid, &mut return_value, libc::WNOHANG, &mut res_used_buf);
                
                if p == pid {
                    // Record time as soon as the tested program exits
                    // Making result more percise.
                    stop_instant = Instant::now();
                    res_used = res_used_buf;
                    break;
                } else {
                    let duration = Instant::now().saturating_duration_since(begin_instant);
                    if self.max_allowed_time != Duration::MAX && duration > self.max_allowed_time {
                        libc::kill(pid, libc::SIGKILL);
                    } else {
                        std::thread::sleep(WAIT_DURATION);
                    }
                }
            }
        }

        let duration = stop_instant.saturating_duration_since(begin_instant);
        let memory_used_bytes = res_used.ru_maxrss as u64 * 1024;
        let cpu_time_ms = (res_used.ru_utime.tv_usec/1000) as u64;

        let status = if memory_used_bytes > self.max_allowed_memory_bytes {
            JudgeStatus::MemoryLimitExceeded
        } else if duration > self.max_allowed_time {
            JudgeStatus::TimeLimitExceeded
        } else if return_value != 0 {
            if libc::WIFSIGNALED(return_value) {
                match libc::WTERMSIG(return_value) {
                    libc::SIGFPE => JudgeStatus::RuntimeError(RuntimeErrorKind::FloatingPointError),
                    libc::SIGSEGV => JudgeStatus::RuntimeError(RuntimeErrorKind::SegmentationFault),
                    _ => JudgeStatus::ReturnNonZero(return_value)
                }
            } else {
                JudgeStatus::ReturnNonZero(return_value)
            }
        } else {
            let std_ans = File::open(&self.standard_ans_file)?;
            let test_ans = File::open(&tmp_out)?;
            let result = compare_content(std_ans, test_ans)?;
            fs::remove_file(&tmp_out)?;
            result
        };

        Ok(JudgeResult { status, time_used: duration, cpu_time_ms, memory_used_bytes })
    }
}

fn compare_content(mut content1: File, mut content2: File) -> io::Result<JudgeStatus> {
    content1.seek(SeekFrom::Start(0))?;
    content2.seek(SeekFrom::Start(0))?;
    let cf1 = BufReader::new(&content1);
    let cf2 = BufReader::new(&content2);
    match cf1.bytes().map(|ch| ch.unwrap_or_default()).eq(cf2.bytes().map(|ch| ch.unwrap_or_default())) {
        true => Ok(JudgeStatus::Accepted),
        false => {
            content1.seek(SeekFrom::Start(0))?;
            content2.seek(SeekFrom::Start(0))?;
            let cf1 = BufReader::new(&content1);
            let cf2 = BufReader::new(&content2);
            let processed_content1 = cf1.bytes()
                .map(|ch| ch.unwrap_or_default())
                .filter(|ch| !ch.is_ascii_whitespace())
                .map(|ch| ch.to_ascii_uppercase());
            let processed_content2 = cf2.bytes()
                .map(|ch| ch.unwrap_or_default())
                .filter(|ch| !ch.is_ascii_whitespace())
                .map(|ch| ch.to_ascii_uppercase());
            Ok(match processed_content1.eq(processed_content2) {
                true    => JudgeStatus::PresentationError,
                false   => JudgeStatus::WrongAnswer
            })
        }
    }
}