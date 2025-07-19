import json
from typing import Iterable

import redis


class Storage:

    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379 + 1000, decode_responses=True, db=0)

    def last_seen_pop(self) -> tuple[str, int] | None:
        el: list[tuple[str, float]] = self.r.zrevrange('last_seen', 0, 0, True)
        if el:
            addr_str, last_seen = el[0]
            self.r.zrem('last_seen', addr_str)
            return addr_str, int(last_seen)

    def last_seen_add(self, mapping: dict[str, int]) -> None:
        if mapping:
            self.r.zadd('last_seen', mapping)

    def last_seen_len(self) -> int:
        return self.r.zcard('last_seen')

    def first_seen_get(self, key: str) -> int | None:
        value = self.r.hget('first_seen', key)
        if value:
            return int(value)

    def first_seen_set(self, mapping: dict[str, int]) -> None:
        """Set only the new elements."""
        new_elements = {k: v for k, v in mapping.items() if not self.r.hexists('first_seen', str(v))}
        if new_elements:
            self.r.hset('first_seen', mapping=new_elements)

    def result_push(self, address: str, element: dict) -> None:
        self.r.lpush('result:' + address, json.dumps(element))
        self.r.sadd('results_index', address)

    def results(self) -> Iterable[tuple[str, int, int]]:
        for addr_str in self.r.sscan_iter('results_index'):
            obj = json.loads(self.r.lrange('result:' + addr_str, 0, 0)[0])
            yield addr_str, obj['fee_rate'], obj['timestamp']

    def result_print(self, address: str) -> None:
        le = self.r.llen(address)
        for el in self.r.lrange(address, 0, le + 1):
            print('', json.loads(el))

    def processed_add(self, *addresses) -> None:
        if addresses:
            self.r.sadd('processed', *addresses)

    def processed_is(self, address: str) -> bool:
        return bool(self.r.sismember('processed', address))

    def processed_count(self) -> int:
        return self.r.scard('processed')

    def results_count(self) -> int:
        return self.r.scard('results_index')

    def m1(self):
        self.r.zadd('last_seen', {'173.25.252.155:8333': 1752391261, '43.134.33.57:8333': 1752401967})
        # get the last seen addr
        print(self.last_seen_pop())
        print(self.last_seen_pop())
        print(self.last_seen_pop())
        self.r.zadd('last_seen', {'173.25.252.155:8333': 1752391261, '43.134.33.57:8333': 1752401967})
        cur, res = self.r.zscan('last_seen')
        for el in res:
            print('    ', el)
        k = '173.25.252.155:8333'
        self.r.hset('first_seen', k, str(1752391261))
        self.r.hset('first_seen', mapping={k: str(1752391261), '43.134.33.57:8333': str(1752401967)})
        v = int(self.r.hget('first_seen', k))
        print('>', k, v)
        k = '43.134.33.57:8333'
        v = int(self.r.hget('first_seen', k))
        print('>', k, v)


def main():
    s = Storage()
    s.m1()


if __name__ == '__main__':
    main()
