#!/usr/bin/env python3

from pcapkit import extract
from sys import argv
import polars as pl
import re

aprs_regex = r"(?P<source>[A-Z0-9]+(?:-[0-9]+)?)>(?P<destination>[A-Z0-9]+(?:-[0-9]+)?)(?:,(?P<relay>[A-Z0-9]+(?:-[0-9]+)?)\*?(?:,WIDE[0-9](?:-[0-9])?\*?)*)*(?:,qA[OR])?(?:,(?P<igate>[A-Z0-9]+(?:-[0-9]+)?))?:(?P<msg>.*)"

def parse(filename):
    extraction = extract(fin=filename, format='json', store=True)
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
            result = aprs_prog.match(aprs_str.decode('utf-8'))
        except UnicodeDecodeError:
            pass
        if result is not None:
            packet = [timestamp]
            packet.extend(result.groups())
            packets.append(packet)

    # Create dataframe from data
    df = pl.DataFrame(packets, schema=["timestamp", "source", "destination", "relay", "igate", "msg"])
    print(df)

if __name__ == "__main__":
    main()
