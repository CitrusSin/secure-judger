use seccompiler::*;
use libc;
use std::path::Path;
use std::result::Result;
use std::ffi::{CString, NulError};
use std::{io, fs};
use std::error::Error;
use std::time::Instant;

fn install_seccomp(execve_whitepath: &CString) -> Result<(), seccompiler::Error> {
    let filter = SeccompFilter::new(
        vec![
            (libc::SYS_open, vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::O_RDWR as u64),
                        libc::O_RDWR as u64
                    )?
                ])?,
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::O_WRONLY as u64),
                        libc::O_WRONLY as u64
                    )?
                ])?
            ]),
            (libc::SYS_openat, vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::O_RDWR as u64),
                        libc::O_RDWR as u64
                    )?
                ])?,
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::O_WRONLY as u64),
                        libc::O_WRONLY as u64
                    )?
                ])?
            ]),
            (libc::SYS_execve, vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Ne,
                        execve_whitepath.as_ptr() as u64
                    )?
                ])?
            ]),
            (libc::SYS_execveat, vec![]),
            (libc::SYS_socket, vec![]),
            (libc::SYS_fork, vec![]),
            (libc::SYS_vfork, vec![]),
            (libc::SYS_prctl, vec![]),
            (libc::SYS_ioctl, vec![]),
            (libc::SYS_clone, vec![]),
            (libc::SYS_mkdir, vec![]),
            (libc::SYS_rmdir, vec![]),
            (libc::SYS_creat, vec![]),
            (libc::SYS_chroot, vec![])
        ].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TargetArch::x86_64
    )?;

    let prog: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&prog)?;
    Ok(())
}

fn perror(err_src: &str) -> Result<(), NulError> {
    let cstr = CString::new(err_src)?;
    unsafe {
        libc::perror(cstr.as_ptr());
    }
    Ok(())
}

fn execv(path: &CString, args: &[CString]) -> ! {
    let mut strs: Vec<*const i8> = args.iter().map(|x| x.as_ptr()).collect();
    strs.push(0 as *const i8);
    unsafe {
        libc::execv(path.as_ptr(), strs.as_ptr());
    }
    perror("execv").unwrap();
    panic!("Unexpected execution");
}

fn fork() -> Result<i32, io::Error> {
    let pid: i32;
    unsafe {
        pid = libc::fork();
    }
    if pid < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to fork"
        ));
    }
    Ok(pid)
}

pub fn sandbox_run(filepath: &Path, args: &[&str], stdin_file: &Path, stdout_file: &Path) -> Result<(i32, Instant), Box<dyn Error>> {
    if !stdout_file.exists() {
        drop(fs::File::create(stdout_file)?);
    }

    let full_name_c = CString::new(filepath.to_string_lossy().as_bytes())?;
    let mut conv_args: Vec<CString> = Vec::new();
    for &s in args {
        conv_args.push(CString::new(s)?);
    }

    let inf = CString::new(stdin_file.to_string_lossy().as_bytes())?;
    let outf = CString::new(stdout_file.to_string_lossy().as_bytes())?;
    let inst = Instant::now();
    let pid = fork()?;
    if pid == 0 {
        // Sub process
        unsafe {
            let fd = libc::open(inf.as_ptr(), libc::O_RDONLY);
            libc::close(0);
            libc::dup2(fd, 0);
            libc::close(fd);
            let fd = libc::open(outf.as_ptr(), libc::O_WRONLY);
            libc::close(1);
            libc::dup2(fd, 1);
            libc::close(fd);
        }
        install_seccomp(&full_name_c).unwrap();
        execv(&full_name_c, &conv_args);
    }
    Ok((pid, inst))
}
