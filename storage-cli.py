#!/usr/bin/env python3
import sys

from main import list_get
from storage import Storage


def main():
    """
    commands
    - addnodes
    - list
    - numbers
    """
    command = list_get(sys.argv, 1, 'list')

    s = Storage()
    nodes = []
    sub_sat_count = 0
    for addr_str, fee_rate, _ in s.results():
        if fee_rate < 1000:
            sub_sat_count += 1
            nodes.append((addr_str, fee_rate))

    add_nodes = []
    for addr_str, fee_rate in sorted(nodes, key=lambda x: x[1]):
        add_nodes.append(f'bitcoin-cli addnode {addr_str} onetry')

    match command:
        case 'addnode':
            print('\n'.join(add_nodes))
        case 'nodes':
            for addr_str, fee_rate in nodes:
                print(addr_str, fee_rate)
        case 'csv':
            print(','.join(addr_str for addr_str, fee_rate in nodes))
        case 'stats':
            print(f'There are {s.last_seen_len()} address to process.')
            print(f'There are {s.processed_count()} processed addresses.')
            print(f'There are {s.results_count()} results.')
            print(f'There are {sub_sat_count} results under 1 sat/vbyte.')
        case _:
            print('Commands:')
            print('  addnode')
            print('  nodes')
            print('  csv')
            print('  stats')


if __name__ == '__main__':
    main()
