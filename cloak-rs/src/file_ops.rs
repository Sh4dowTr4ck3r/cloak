//! Shared file operations for ordinary copy and move workflows.
#[cfg(any(not(windows), test))]
use std::fs::File;
use std::fs::{self, FileTimes};
use std::io;
use std::path::Path;

pub fn copy_preserving_metadata(source: &Path, destination: &Path) -> io::Result<()> {
    match same_file::is_same_file(source, destination) {
        Ok(true) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Source and destination refer to the same file",
            ));
        }
        Ok(false) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::copy(source, destination)?;
    let metadata = fs::metadata(source)?;
    let times = FileTimes::new()
        .set_accessed(metadata.accessed()?)
        .set_modified(metadata.modified()?);
    #[cfg(not(windows))]
    File::open(destination)?.set_times(times)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_WRITE_ATTRIBUTES permits timestamp updates without requiring
        // write access to the file contents (including read-only copies).
        fs::OpenOptions::new()
            .access_mode(0x0100)
            .open(destination)?
            .set_times(times)?;
    }
    Ok(())
}

pub fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            copy_then_remove(source, destination)
        }
        Err(e) => Err(e),
    }
}

fn copy_then_remove(source: &Path, destination: &Path) -> io::Result<()> {
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, destination)?;
        #[cfg(windows)]
        if source.is_dir() {
            std::os::windows::fs::symlink_dir(target, destination)?;
        } else {
            std::os::windows::fs::symlink_file(target, destination)?;
        }
    } else {
        copy_preserving_metadata(source, destination)?;
    }
    // Never remove the source unless the destination was created successfully.
    fs::remove_file(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copy_move_fallback_preserves_contents_times_and_source_on_failure() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("cloak-copy-move-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        fs::write(&source, b"hello").unwrap();
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_times(FileTimes::new().set_modified(time))
            .unwrap();
        assert!(copy_then_remove(&source, &root.join("missing/out")).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"hello");
        let output = root.join("out");
        copy_then_remove(&source, &output).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&output).unwrap(), b"hello");
        assert_eq!(fs::metadata(output).unwrap().modified().unwrap(), time);
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink("absent", &link).unwrap();
            let moved = root.join("moved-link");
            copy_then_remove(&link, &moved).unwrap();
            assert_eq!(fs::read_link(&moved).unwrap(), Path::new("absent"));
            assert!(fs::symlink_metadata(link).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
