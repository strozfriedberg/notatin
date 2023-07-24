/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 use std::path::*;

pub fn parse_paths(paths: &str) -> (String, Option<Vec<String>>) {
    let mut logs = vec![];
    let mut primary = String::new();
    for component in paths.split(',') {
        let lower = component.trim().trim_matches('\'').to_ascii_lowercase();
        if lower.ends_with(".log1") || lower.ends_with(".log2") {
            logs.push(component.trim().trim_matches('\'').to_string());
        } else {
            primary = component.trim().trim_matches('\'').to_string();
        }
    }
    if logs.is_empty() {
        (primary, None)
    } else {
        (primary, Some(logs))
    }
}

pub fn check_add_log(base_folder: &Path, primary_name: &str, extension: &str, logs: &mut Vec<PathBuf>) {
    let log = get_log_name(base_folder, primary_name, extension);
    if log.is_file() {
        logs.push(log);
    }
}

fn get_log_name(base_folder: &Path, primary_name: &str, extension: &str) -> PathBuf {
    let log_name = match primary_name {
        "NTUSER.DAT" => "ntuser.dat",
        "UsrClass.DAT" => "UsrClass.dat",
        _ => primary_name,
    };
    let mut log = base_folder.join(log_name).into_os_string();
    log.push(".");
    log.push(extension);
    PathBuf::from(log)
}

pub fn get_log_files(skip_logs:bool, f: &str, path: &Path) -> Option<Vec<PathBuf>> {
    if skip_logs {
        None
    }
    else {
        let mut logs: Vec<PathBuf> = vec![];
        if let Some(folder) = path.parent() {
            check_add_log(folder, f, "LOG1", &mut logs);
            check_add_log(folder, f, "LOG2", &mut logs);
        }
        Some(logs)
    }
}

pub fn file_has_size(path: &Path) -> bool {
    match path.metadata() {
        Ok(md) => {
            if md.len() == 0 {
                println!("{:?} size is 0; skipping", path);
                false
            }
            else {
                true
            }
        }
        Err(e) => {
            println!("Unable to get size for {:?} ({:?})", path, e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_log_name() {
        assert_eq!(PathBuf::from("/mnt/d/tmp/ntuser.dat.LOG1"), get_log_name(&Path::new("/mnt/d/tmp"), "NTUSER.DAT", "LOG1"));
        assert_eq!(PathBuf::from("/mnt/d/tmp/UsrClass.dat.LOG2"), get_log_name(&Path::new("/mnt/d/tmp"), "UsrClass.DAT", "LOG2"));
        assert_eq!(PathBuf::from("/mnt/d/tmp/SYSTEM.LOG2"), get_log_name(&Path::new("/mnt/d/tmp"), "SYSTEM", "LOG2"));
    }
}
