#!/usr/bin/env python3
"""
TODO
- better last seen data structure (now the information is destroyed)
- check single nodes
- verify stats
"""
import asyncio
import sys
from typing import Any

from bitcoin import nodes_loop, BitcoinNetwork, network_loop, host_port
from settings import Settings
from storage import Storage


def list_get(ls: list, index: int, default: Any) -> Any:
    if index < len(ls):
        return ls[index]
    return default


async def main():
    initial_nodes = sys.argv[1].split(',')
    net = list_get(sys.argv, 2, 'm')
    settings = Settings()
    if net == 't':
        network = BitcoinNetwork.TESTNET
    elif net == 'r':
        network = BitcoinNetwork.REGTEST
    else:
        network = BitcoinNetwork.MAINNET
    settings.network = network.as_bytes()

    # Commands: scan, check
    command = list_get(sys.argv, 3, 'scan')

    match command:
        case 'scan':
            s = Storage()
            s.last_seen_add({initial_nodes[0]: 0})
            async with asyncio.TaskGroup() as tg:
                for i in range(20):
                    tg.create_task(nodes_loop(i))
        case 'check':
            out = []
            for initial_node in initial_nodes:
                h, p = host_port(initial_node)
                log_prefix = f'ꙮ {h:15}'
                fee_rate, addresses = await network_loop(h, p, log_prefix)
                if fee_rate is not None:
                    out.append(f'{initial_node} {fee_rate}')
            print()
            print('\n'.join(out))
        case _:
            print('Commands:')
            print('  scan')
            print('  check')


if __name__ == "__main__":
    asyncio.run(main())
