/*
 * Copyright 2023 Aon Cyber Solutions
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
use crate::err::Error;
use crossterm::{cursor, QueueableCommand};
use std::io;
use std::io::{Stdout, Write};

pub fn new(update_console: bool) -> Box<dyn UpdateProgressTrait> {
    if update_console {
        Box::new(UpdateConsole {
            need_final_newline: false,
            stdout: io::stdout(),
        })
    } else {
        Box::new(UpdateNull {})
    }
}

pub trait UpdateProgressTrait {
    fn update_progress(&mut self, index: usize) -> Result<(), Error>;
    fn update(&mut self, msg: &str) -> Result<(), Error>;
    fn write(&mut self, msg: &str) -> Result<(), Error>;
}

struct UpdateConsole {
    need_final_newline: bool,
    stdout: Stdout,
}

impl UpdateProgressTrait for UpdateConsole {
    fn update_progress(&mut self, index: usize) -> Result<(), Error> {
        if index.is_multiple_of(1000) {
            self.stdout.write_all(".".as_bytes())?;
            self.stdout.flush()?;
        }
        Ok(())
    }

    fn update(&mut self, msg: &str) -> Result<(), Error> {
        self.stdout.queue(cursor::SavePosition)?;
        self.stdout.write_all(msg.as_bytes())?;
        self.stdout.queue(cursor::RestorePosition)?;
        self.stdout.flush()?;
        self.need_final_newline = true;
        Ok(())
    }

    fn write(&mut self, msg: &str) -> Result<(), Error> {
        self.stdout.write_all(msg.as_bytes())?;
        self.stdout.flush()?;
        Ok(())
    }
}

impl Drop for UpdateConsole {
    fn drop(&mut self) {
        if self.need_final_newline {
            self.stdout.write_all("\n".as_bytes()).unwrap_or_default();
            self.stdout.flush().unwrap_or_default();
        }
    }
}

struct UpdateNull {}

impl UpdateProgressTrait for UpdateNull {
    fn update_progress(&mut self, _index: usize) -> Result<(), Error> {
        Ok(())
    }

    fn update(&mut self, _msg: &str) -> Result<(), Error> {
        Ok(())
    }

    fn write(&mut self, _msg: &str) -> Result<(), Error> {
        Ok(())
    }
}
