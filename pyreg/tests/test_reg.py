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
        val = value.value()
        assert val == b'8\x000\x00\x00\x00'


def test_value_get_content2(sample_parser2):
    with open(sample_parser2, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("ControlSet001\\Enum\\SWD\\PRINTENUM\\{D943D8D8-F7EB-4400-8EEE-A8CFF8C894B5}\\Properties\\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}\\0002")
        value = key.value('')
        assert value.raw_data_type & 0x0fff == 16
        val = value.get_content()
        assert val == b'\x00\x80\x8c\xa3\xc5\x94\xc6\x01'

def test_value_get_content(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Accessibility\\MouseKeys")
        value = key.value('MaximumSpeed')
        assert value.name == "MaximumSpeed"
        assert value.raw_data_type == 1
        val = value.get_content()
        assert val == '80'

        key = parser.open("Control Panel\\Cursors")
        value = key.value('Arrow')
        assert value.raw_data_type == 2
        val = value.get_content()
        assert val == '%SystemRoot%\\cursors\\aero_arrow.cur'

        key = parser.open("Control Panel\\Cursors")
        value = key.value('Arrow')
        assert value.raw_data_type == 2
        val = value.get_content()
        assert val == '%SystemRoot%\\cursors\\aero_arrow.cur'

        key = parser.open("Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC")
        value = key.value('0')
        assert value.raw_data_type == 7
        val = value.get_content()
        assert val == ['C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\Windows PowerShell.lnk', 'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe']

def test_value_pretty_name(sample_parser):
    with open(sample_parser, "rb") as m:
        parser = PyRegParser(m)
        key = parser.open("Control Panel\\Cursors")
        assert key.path == "\\CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\\Control Panel\\Cursors"
        for value in key.values():
            if value.name == '':
                assert value.pretty_name() == "(Default)"
            else:
                assert value.pretty_name() == value.name

def test_timestamp():
    ticks = 131608517735659925
    epoch = datetime.datetime(1601, 1, 1)
    mode=decimal.ROUND_HALF_EVEN
    resolution = int(1e7)
    # python's datetime.datetime supports microsecond precision
    datetime_resolution = int(1e6)

    # convert ticks since epoch to microseconds since epoch
    intermediate = decimal.Decimal(ticks * datetime_resolution) / decimal.Decimal(resolution)
    us = int((decimal.Decimal(ticks * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))

    # convert to datetime
    date = epoch + datetime.timedelta(microseconds=us)

    ticks2 = 131608517735659935
    # convert ticks since epoch to microseconds since epoch
    us2 = int((decimal.Decimal(ticks2 * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))

    # convert to datetime
    date2 = epoch + datetime.timedelta(microseconds=us2)

    ticks3 = 131608517735659933
    # convert ticks since epoch to microseconds since epoch
    us3 = int((decimal.Decimal(ticks3 * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))
    # convert to datetime
    date3 = epoch + datetime.timedelta(microseconds=us3)

    ticks4 = 131608517735659937
    # convert ticks since epoch to microseconds since epoch
    us4 = int((decimal.Decimal(ticks4 * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))
    # convert to datetime
    date4 = epoch + datetime.timedelta(microseconds=us4)

    ticks5 = 130758241637640272
    # convert ticks since epoch to microseconds since epoch
    us5 = int((decimal.Decimal(ticks5 * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))
    # convert to datetime
    date5 = epoch + datetime.timedelta(microseconds=us5)
    t = 3

""" def test_iter_attributes(sample_mft_entry_single_file):
    with open(sample_mft_entry_single_file, "rb") as m:
        parser = PyRegParser(m)

        sample_record: PyMftEntry = next(parser.entries())
        l = list(sample_record.attributes())
        assert len(l) == 4


def test_datetimes_are_converted_properly(sample_mft):
    with open(sample_mft, "rb") as m:
        parser = PyMftParser(m)

        sample_record: PyMftEntry = next(parser.entries())

        attributes = sample_record.attributes()

        attribute = next(attributes) # x10
        content = attribute.attribute_content
        assert content.created.tzinfo == datetime.timezone.utc

        attribute = next(attributes) # x30
        content = attribute.attribute_content
        assert content.created.tzinfo == datetime.timezone.utc


def test_doesnt_yield_zeroed_entries(sample_mft):
    parser = PyMftParser(str(sample_mft))

    for entry in parser.entries():
        try:
            for attribute in entry.attributes():
                print(entry.entry_id)
        except RuntimeError as e:
            assert False, (e, entry.entry_id)


def test_get_data_runs(sample_mft):
    parser = PyMftParser(str(sample_mft))

    for entry in parser.entries():
        try:
            for attribute in entry.attributes():
                content = attribute.attribute_content
                if attribute.type_code == 0x80: # DATA
                    assert content.data_runs_json() == '[{"lcn_offset":205374,"lcn_length":4536,"run_type":"Standard"},{"lcn_offset":261023,"lcn_length":1288,"run_type":"Standard"},{"lcn_offset":230736,"lcn_length":336,"run_type":"Standard"},{"lcn_offset":399772,"lcn_length":384,"run_type":"Standard"}]'
                if attribute.type_code == 0xB0: # BITMAP
                    assert content.data_runs_json() == '[{"lcn_offset":205373,"lcn_length":1,"run_type":"Standard"}]'
            return

        except RuntimeError as e:
            assert False, (e, entry.entry_id)


def test_iter_index_root_entries(sample_mft_multiple_index_root_entries):
    with open(sample_mft_multiple_index_root_entries, "rb") as m:
        parser = PyMftParser(m)

        sample_record: PyMftEntry = next(parser.entries())
        l = list(sample_record.attributes())
        for attribute in sample_record.attributes():
            if attribute.type_code == 0x90: # IndexRoot
                assert attribute.attribute_content.collation_rule == 'CollationFilename'
                assert attribute.attribute_content.index_entry_number_of_cluster_blocks == 1
                assert attribute.attribute_content.index_entry_size == 4096
                assert attribute.attribute_content.index_node_allocation_length == 520
                assert attribute.attribute_content.index_node_length == 520
                assert attribute.attribute_content.is_large_index == True
                for index_entry in attribute.attribute_content.index_entries.index_entries():
                    assert index_entry.fname_info.flags == 'FILE_ATTRIBUTE_ARCHIVE'
                    assert index_entry.fname_info.logical_size == 8192
                    assert index_entry.fname_info.name == 'test_cfuncs.py'
                    assert index_entry.fname_info.parent_entry_id == 26359
                    assert index_entry.fname_info.physical_size == 8072
                    assert index_entry.mft_reference_entry_id == 26370
                    assert index_entry.mft_reference_entry_sequence == 1
                    break
        return
 """