#!/usr/bin/env python3

from pcapkit import extract
from sys import argv
import polars as pl
import re

aprs_regex = r"(?P<source>[A-Z0-9]+(?:-[0-9]+)?)>(?P<destination>[A-Z0-9]+(?:-[0-9]+)?),*(?P<ssid_list>[A-Z0-9-,*]*),(?P<q_construct>qA[OR])(?:,(?P<igate>[A-Z0-9-]+)):(?P<msg>.*)"

def parse(filename):
    extraction = extract(fin=filename, store=True)
    for frame in extraction.frame:
        if 'TCP' in frame:
            yield(frame.info.time, frame['TCP'].packet.payload)

def main():

    # Check command line arguments
    if len(argv) < 2:
        print(f"Usage: {argv[0]} INPUT")
        exit(-1)

    # Compile regex
    aprs_prog = re.compile(aprs_regex)

    # Parse TCP packets
    packets = []
    for timestamp, aprs_str in parse(argv[1]):
        try:
            aprs_str = aprs_str.decode('utf-8')
            # print(aprs_str, end='')
            result = aprs_prog.match(aprs_str)
        except UnicodeDecodeError:
            pass
        if result is not None:
            packet = [timestamp]
            packet.extend(result.groups())
            packets.append(packet)

    # Create dataframe from data
    df = pl.DataFrame(packets, schema=["timestamp", "source", "destination", "ssid_list", "q_construct", "igate", "msg"])
    df.write_parquet(argv[1].replace("pcap", "parquet"))
    # print(df)

if __name__ == "__main__":
    main()
