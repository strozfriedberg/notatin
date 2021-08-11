#
# Copyright 2021 Aon Cyber Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

import datetime
import decimal

import pytest

from pathlib import Path

from asdf_notatin import PyRegParser, PyRegKey

@pytest.fixture
def sample_parser():# -> str:
    p = Path(__file__).parent.parent.parent / "test_data" / "NTUSER.DAT"
    assert p.exists()
    return p

@pytest.fixture
def sample_parser2():# -> str:
    p = Path(__file__).parent.parent.parent / "test_data" / "asdf_test_data" / "SYSTEM"
    assert p.exists()
    return p

def test_it_works(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        keys = 0
        values = 0

        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
                print("\t"+value.name + "\t" + str(value.raw_data_type))
        assert keys == 2853
        assert values == 5523

def test_get_key(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        sub = key.find_key(parser, "Keyboard Response")
        assert sub.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response"

def test_sub_keys(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel"
        keys = 0
        for sub_key in key.subkeys(parser):
            keys += 1
        assert keys == 14

def test_values(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        values = 0
        for value in key.values():
            values += 1
        assert values == 2

def test_key_get_value(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        value = key.value('MinimumHitRadius')
        assert value.name == "MinimumHitRadius"

def test_value_raw_data_type(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        value = key.value('MinimumHitRadius')
        assert value.name == "MinimumHitRadius"
        assert value.raw_data_type == 4

def test_value_value(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility\\MouseKeys")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\MouseKeys"
        value = key.value('MaximumSpeed')
        assert value.name == "MaximumSpeed"
        assert value.raw_data_type == 1
        val = value.value
        assert val == b'8\x000\x00\x00\x00'

def test_value_get_content2(sample_parser2):
    with open(sample_parser2, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("ControlSet001\\Enum\\SWD\\PRINTENUM\\{D943D8D8-F7EB-4400-8EEE-A8CFF8C894B5}\\Properties\\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}\\0002")
        value = key.value('')
        assert value.raw_data_type & 0x0fff == 16
        val = value.content
        assert val == 127953216000000000

def test_value_get_content(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility\\MouseKeys")
        value = key.value('MaximumSpeed')
        assert value.name == "MaximumSpeed"
        assert value.raw_data_type == 1
        val = value.content
        assert val == '80'

        key = parser.open("Control Panel\\Cursors")
        value = key.value('Arrow')
        assert value.raw_data_type == 2
        val = value.content
        assert val == '%SystemRoot%\\cursors\\aero_arrow.cur'

        key = parser.open("Control Panel\\Cursors")
        value = key.value('Arrow')
        assert value.raw_data_type == 2
        val = value.content
        assert val == '%SystemRoot%\\cursors\\aero_arrow.cur'

        key = parser.open("Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC")
        value = key.value('0')
        assert value.raw_data_type == 7
        val = value.content
        assert val == ['C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\Windows PowerShell.lnk', 'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe']

def test_value_pretty_name(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Cursors")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Cursors"
        for value in key.values():
            if value.name == '':
                assert value.pretty_name == "(default)"
            else:
                assert value.pretty_name == value.name