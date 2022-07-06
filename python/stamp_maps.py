from configparser import MAX_INTERPOLATION_DEPTH
import sys
import os
import json
import argparse
import subprocess
import ipaddress
from time import sleep

# add the common eclat python modules to the PYTONPATH
sys.path.append(os.path.abspath(os.getcwd()))
# it works assuming that this python program is called from
# the main eclat-daemon folder (by default /opt/eclat-daemon)
# sys.path.append('/opt/eclat-daemon')

# Command Abstraction Layer
import cal
import hex_types as ht

# ETH_SRC = 0xf62842485e3b
ETH_SRC = 0x3b5e484228f6
# ETH_DST = 0x0a5d6baa9456
ETH_DST = 0x5694aa6b5d0a
# IP_SRC = 0xfcfb000a0003000e0000000000000001
IP_SRC = 0x01000000000000000e0003000a00fbfc
# IP_DST = 0xfcfb00070003000b0000000000000001
IP_DST = 0x01000000000000000b0003000700fbfc

ETH = 0x3b5e484228f65694aa6b5d0a
IP = 0x01000000000000000b0003000700fbfc01000000000000000e0003000a00fbfc

# SEG1 = 0xfc000000000000000000000000000002
SEG1 = 0x020000000000000000000000000000fc
# SEG2 = 0xfcfb00070003000b0000000000000001
SEG2 = 0x01000000000000000b0003000700fbfc
MAP_ETH = "map_eth"
MAP_IP = "map_ipv6"
MAP_SEGLIST = "map_seglist"
L23_MAPS = [
      {"name": MAP_ETH, "elem1": ETH_SRC, "elem2": ETH_DST},
      {"name": MAP_IP, "elem1": IP_SRC, "elem2": IP_DST},
      {"name": MAP_SEGLIST, "elem1": SEG1, "elem2": SEG2}
]

BASE_PATH =  '/sys/fs/bpf/maps'
PACKAGE = 'stamp'
PROGRAM = 'stamp'
MAP = 'map_time'
TIME_EXEC = "develop/t2"
map_as_array = []

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action='store_true', help="run only once")
    parser.add_argument("--pkg", metavar="pkg", default=PACKAGE, help="package name")
    parser.add_argument("--prog", metavar="prog", default=PROGRAM, help="program name")
    parser.add_argument("--map", metavar="map", default=MAP, help="map name")
    parser.add_argument("--l23", action='store_true', help="layer 2 and 3: addresses and segment list")
    parser.add_argument("--counter", action='store_true', help="delta is instead a counter initialised to 0")
    return parser.parse_args()

args = parse()
if args.l23:
      map_path = f"{BASE_PATH}/{args.pkg}/{args.prog}/"+MAP_ETH
      if not os.path.exists(map_path):
            print(f"path to {map_path} does not exist")
      try:
            cal.cal_map_update(map_path, ht.u8(0), ht.u96(ETH))
            map_as_array = json.loads(cal.bpftool_map_dump(map_path))
            print(f"updated map:\n{map_as_array}")
      except Exception as e:
            print(e)
            print(map_path)

      map_path = f"{BASE_PATH}/{args.pkg}/{args.prog}/"+MAP_IP
      if not os.path.exists(map_path):
            print(f"path to {map_path} does not exist")
      try:
            cal.cal_map_update(map_path, ht.u8(0), ht.u256(IP))
            map_as_array = json.loads(cal.bpftool_map_dump(map_path))
            print(f"updated map:\n{map_as_array}")
      except Exception as e:
            print(e)
            print(map_path)

      map_path = f"{BASE_PATH}/{args.pkg}/{args.prog}/"+MAP_SEGLIST
      if not os.path.exists(map_path):
            print(f"path to {map_path} does not exist")
      try:
            cal.cal_map_update(map_path, ht.u8(0), ht.u128(SEG1))
            cal.cal_map_update(map_path, ht.u8(1), ht.u128(SEG2))
            map_as_array = json.loads(cal.bpftool_map_dump(map_path))
            print(f"updated map:\n{map_as_array}")
      except Exception as e:
            print(e)
            print(map_path)





      # for map in L23_MAPS:
      #       map_path = f"{BASE_PATH}/{args.pkg}/{args.prog}/"+map["name"]
      #       if not os.path.exists(map_path):
      #             print(f"path to {map_path} does not exist")
      #       try:
      #             if map["name"] == MAP_ETH:
      #                   cal.cal_map_update(map_path, ht.u8(0), ht.u48(map["elem1"]))
      #                   cal.cal_map_update(map_path, ht.u8(1), ht.u48(map["elem2"]))
      #             else:
      #                   cal.cal_map_update(map_path, ht.u8(0), ht.u128(map["elem1"]))
      #                   cal.cal_map_update(map_path, ht.u8(1), ht.u128(map["elem2"]))
      #             map_as_array = json.loads(cal.bpftool_map_dump(map_path))
      #             print(f"updated map:\n{map_as_array}")
      #       except Exception as e:
      #             print(e)
      #             print(map_path)

map_path = f"{BASE_PATH}/{args.pkg}/{args.prog}/{args.map}"
if not os.path.exists(map_path):
      print(f"path to {map_path} does not exist")
elif args.counter:
      print("counter mode")
      cal.cal_map_update(map_path, ht.u8(0), 0)
      map_as_array = json.loads(cal.bpftool_map_dump(map_path))
      print(f"updated map:\n{map_as_array}")
elif not os.path.exists(TIME_EXEC):
      print(f"path to {TIME_EXEC} does not exist")
else:
      try :
            while(True):
                  ret = subprocess.run(TIME_EXEC, capture_output=True)
                  delta = int(ret.stdout)
                  print(f"delta: {delta}")
                  cal.cal_map_update(map_path, ht.u8(0), delta)
                  map_as_array = json.loads(cal.bpftool_map_dump(map_path))
                  print(f"updated map:\n{map_as_array}")
                  if args.once:
                        break
                  sleep(30)
      except Exception as e:
            print(e)
            print(map_path)
