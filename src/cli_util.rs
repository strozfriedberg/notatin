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
