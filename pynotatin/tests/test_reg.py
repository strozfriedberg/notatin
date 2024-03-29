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

from notatin import PyNotatinParser, PyNotatinParserBuilder, PyNotatinDecodeFormat

test_directory = Path(__file__).parents[2] / "test_data"

@pytest.fixture
def sample_parser():
    p = test_directory / "NTUSER.DAT"
    assert p.exists()
    return p

@pytest.fixture
def sample_parser2():
    p = test_directory / "system"
    assert p.exists()
    return p

@pytest.fixture
def sample_parser3():
    p = test_directory / "win7_ntuser.dat"
    assert p.exists()
    return p

def test_it_works(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        keys = 0
        values = 0

        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
        assert keys == 2853
        assert values == 5523

def test_it_works_with_logs(sample_parser2):
    with open(sample_parser2, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        keys = 0
        values = 0
        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
                print("\t"+ value.name + "\t" + str(value.raw_data_type))
        assert keys == 45527
        assert values == 107925

        m.seek(0)
        builder = PyNotatinParserBuilder(m)
        log1 = open(test_directory / "system.log1", "rb")
        log2 = open(test_directory / "system.log2", "rb")
        builder.with_transaction_log(log1)
        builder.with_transaction_log(log2)
        parser = builder.build()
        log1.close()
        log2.close()
        keys = 0
        values = 0
        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
        assert keys == 45587
        assert values == 108178

        m.seek(0)
        builder = PyNotatinParserBuilder(m)
        log1 = open(test_directory / "system.log1", "rb")
        log2 = open(test_directory / "system.log2", "rb")
        builder.with_transaction_log(log1)
        builder.with_transaction_log(log2)
        builder.recover_deleted(True)
        parser = builder.build()
        log1.close()
        log2.close()
        keys = 0
        values = 0
        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
        assert keys == 45618
        assert values == 108422


def test_recovered_value(sample_parser2):
    with open(sample_parser2, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        keys = 0
        values = 0
        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            for value in key.values():
                values += 1
                print("\t"+ value.name + "\t" + str(value.raw_data_type))
        assert keys == 45527
        assert values == 107925

        m.seek(0)
        builder = PyNotatinParserBuilder(m)
        log1 = open(test_directory / "system.log1", "rb")
        log2 = open(test_directory / "system.log2", "rb")
        builder.with_transaction_log(log1)
        builder.with_transaction_log(log2)
        builder.recover_deleted(True)
        parser = builder.build()
        log1.close()
        log2.close()

        recovered = 0
        for key in parser.reg_keys():
            if key.pretty_path == "RegistryTest":
                for value in key.values():
                    if value.name == "Multibyte character 𐐷":
                        assert value.content == "Multibyte character 𐐷 - modified"
                        for recovered_val in value.versions():
                            recovered += 1
                            assert recovered_val.content == "Multibyte character 𐐷"
                break
        assert recovered == 1

def test_get_key(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        assert key.pretty_path == "Control Panel\\Accessibility"
        assert key.last_key_written_date_and_time == datetime.datetime(2015, 2, 9, 21, 41, 7, 497832, tzinfo=None)
        sub = key.find_key(parser, "Keyboard Response")
        assert sub.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\Keyboard Response"
        assert sub.pretty_path == "Control Panel\\Accessibility\\Keyboard Response"

def test_sub_keys(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel"
        keys = 0
        for sub_key in key.subkeys(parser):
            keys += 1
        assert keys == 14

def test_values(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParser(m)
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        values = 0
        for value in key.values():
            values += 1
        assert values == 2

def test_key_get_value(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        value = key.value('MinimumHitRadius')
        assert value.name == "MinimumHitRadius"

def test_value_raw_data_type(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel\\Accessibility")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility"
        value = key.value('MinimumHitRadius')
        assert value.name == "MinimumHitRadius"
        assert value.raw_data_type == 4

def test_value_value(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel\\Accessibility\\MouseKeys")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Accessibility\\MouseKeys"
        value = key.value('MaximumSpeed')
        assert value.name == "MaximumSpeed"
        assert value.raw_data_type == 1
        val = value.value
        assert val == b'8\x000\x00\x00\x00'

def test_value_get_content2(sample_parser2):
    with open(sample_parser2, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("ControlSet001\\Enum\\SWD\\PRINTENUM\\PrintQueues\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")
        value = key.value('')
        assert value.raw_data_type & 0x0fff == 16
        val = value.content
        assert val == 132727489235433111

def test_value_get_content(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyNotatinParserBuilder(m).build()
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
        parser = PyNotatinParserBuilder(m).build()
        key = parser.open("Control Panel\\Cursors")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Cursors"
        for value in key.values():
            if value.name == '':
                assert value.pretty_name == "(default)"
            else:
                assert value.pretty_name == value.name

def test_value_decode(sample_parser3):
    with open(sample_parser3, "rb") as m:
        parser = PyNotatinParser(m)
        key = parser.open("SOFTWARE\\7-Zip\\Compression\\")
        value = key.value('ArcHistory')
        assert value.name == "ArcHistory"
        val = value.decode(PyNotatinDecodeFormat.utf16_multiple, 0).content
        assert val == ['NAS_requested_data.7z', 'BlackHarrier_D7_i686_FDE_20141219.dd.7z', 'BlackHarrier_D7_amd64_20141217.7z', 'BlackHarrier_D7_amd64_FDE_20141217.7z', 'C:\\Users\\jmroberts\\Desktop\\USB_Research\\IEF.zip', 'Company_Report_10222013.vir.zip', 'LYNC.7z', 'viruses.zip', 'ALLDATA.txt.bz2']