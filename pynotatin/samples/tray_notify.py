from notatin import PyNotatinParserBuilder
from datetime import datetime
import codecs
import struct

TRAY_NOTIFY_HEADER_SIZE = 20
TRAY_NOTIFY_RECORD_SIZE = 1640

def handle_icon_stream(file, value, source):
    records = value.value[TRAY_NOTIFY_HEADER_SIZE:]
    struct_fmt = '<520s16s524s36sQ536s'
    for i in range(len(records) // TRAY_NOTIFY_RECORD_SIZE):
        record = records[(TRAY_NOTIFY_RECORD_SIZE * i):TRAY_NOTIFY_RECORD_SIZE * (i + 1)]
        exe, unk1, message, unk2, timestamp, unk3 = struct.unpack(struct_fmt, record)
        file.write(f"{source}\t")
        file.write(f"\"{codecs.encode(exe.decode('utf-16', errors='space_replace'), 'rot-13')}\"\t")
        file.write(f"\"{unk1}\"\t")
        file.write(f"\"{codecs.encode(message.decode('utf-16', errors='space_replace'), 'rot-13')}\"\t")
        file.write(f"\"{unk2}\"\t")
        if timestamp != 0:
            file.write(f"{datetime.utcfromtimestamp(float(timestamp) * 1e-7 - 11644473600)}\t")
        else:
            file.write('\t')
        file.write(f"\"{codecs.encode(unk3.decode('utf-16', errors='space_replace'), 'rot-13')}\"\n")


def find_icon_streams(parser):
    ICON_STREAMS_VALUE = 'IconStreams'
    for key in parser.reg_keys():
        if key.pretty_path == "Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify":
            for value in key.values():
                if value.name == ICON_STREAMS_VALUE:
                    with open("IconStreams1.tsv", "w") as file:
                        file.write("source\texe (rot13)\tunk1\tmessage (rot13)\tunk2\ttimestamp\tunk3 (rot13)\n")
                        handle_icon_stream(file, value, "Current")
                        recovered_index = 1
                        for recovered in value.versions():
                            if recovered.name == ICON_STREAMS_VALUE:
                                handle_icon_stream(file, recovered, f"Recovered {recovered_index}")
                                recovered_index += 1


with open("/mnt/d/evidence/TrayNotify/UsrClass.dat", "rb") as m, open("/mnt/d/evidence/TrayNotify/UsrClass.dat.LOG1", "rb") as log1, open("/mnt/d/evidence/TrayNotify/UsrClass.dat.LOG2", "rb") as log2:
    builder = PyNotatinParserBuilder(m)
    builder.with_transaction_log(log1)
    builder.with_transaction_log(log2)
    builder.recover_deleted(True)
    parser = builder.build()

    find_icon_streams(parser)
