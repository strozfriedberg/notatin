import datetime

import pytest

from pathlib import Path

from pyreg import PyRegParser, PyRegKey

@pytest.fixture
def sample_mft():# -> str:
    p = Path(__file__).parent.parent.parent / "test_data" / "NTUSER.DAT"
    assert p.exists()
    return p

def test_it_works(sample_mft):
    with open(sample_mft, "rb") as m:
        parser = PyRegParser(m)
        keys = 0
        values = 0

        for key in parser.reg_keys():
            print(key.path)
            keys += 1
            values += key.number_of_key_values
            for value in key.values():
                print("\t"+value.name)
        assert keys == 2288
        assert values == 5470

        #sample_record: PyMftEntry = next(parser.entries())

        #assert sample_record.entry_id == 0
        #assert sample_record.full_path == "$MFT"


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