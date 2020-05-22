#!/usr/bin/env python3

import pcap #PyPCAP
#libpcap-dev
import dpkt

import sys
import string
import time
import socket
import struct

import compat
import os.path
import os
import configparser
import igmpStorage
import datetime, time

from igmpHandler import *
from threads import FlowBalancer

storage = None
balancer = FlowBalancer()


def load_config():
    base = os.path.dirname(os.path.realpath(__file__))
    cfg_path = os.path.join(base, 'conf', 'config.ini')
    c_parser = configparser.ConfigParser()
    c_parser.read(cfg_path)
    return c_parser


def store_packet(packet):
    tstamp = packet[0]
    tstamp = datetime.datetime.fromtimestamp(tstamp)
    storage.add_igmp((tstamp, packet[1], packet[2], packet[3]))


balancer.set_consumer(store_packet)


def on_packet(tstamp, tp_ipaddr, tp_maddr, tp_igmp):
    # balancer.put((tstamp, tp_ipaddr, tp_maddr, tp_igmp))
    # i'll enable balancers later on
    store_packet((tstamp, tp_ipaddr, tp_maddr, tp_igmp))


def init_storage(cfg):
    global storage
    dbhost = cfg.get("storage", "server")
    dbuser = cfg.get("storage", "user")
    dbpass = cfg.get("storage", "password")
    dbname = cfg.get("storage", "database")
    try:
        db_commit_interval = cfg.get("storage", "commitsize")
    except:
        db_commit_interval = 100

    storage = igmpStorage.PacketStorage({"host": dbhost, "user": dbuser, "password": dbpass, "db": dbname})
    storage.set_commitsize(db_commit_interval)
    storage.autocommit(False)
    # Setup the database if that's needed
    if len(sys.argv) >= 2 and sys.argv[1] == "setup":
        storage.setup()


def on_complete():
    storage.close()
    print("Complete syncing. Press any key to exit")
    sys.exit()


if __name__ == '__main__':
    config = load_config()
    init_storage(config)
    source_filter = None
    try:
        source_filter = config.get("filters", "src")
    except:
        source_filter = None

    p = pcap.pcapObject()
    # dev = pcap.lookupdev()
    isLive = False
    targetFile = "igmp.pcap"
    targetDevice = "eth0"
    if len(sys.argv) >= 2:
        dev = sys.argv[1]
        if os.path.isfile(dev):
            isLive = False
            targetFile = dev
        else:
            isLive = True
            targetDevice = dev

    if isLive:
        net, mask = pcap.lookupnet(targetDevice)
        # note:  to_ms does nothing on linux
        isPromisc = 1
        p.open_live(dev, 1600000, isPromisc, 0)
        # p.dump_open('dumpfile')
        captureFilter = string.join(sys.argv[2:], ' ') if len(sys.argv) >= 3 else 'igmp'  # igmp
        p.setfilter(captureFilter, 0, 0)

        handler = IgmpHandler(p)
        handler.set_on_packet(on_packet)
        handler.set_src_filter(source_filter)

        balancer.run_consumer()
        handler.capture()
    elif os.path.isfile(targetFile):
        handler = IgmpHandler(p)
        handler.set_on_packet(on_packet)
        handler.set_src_filter(source_filter)
        balancer.run_consumer()
        handler.open_and_handle(targetFile)
        balancer.finalize(on_complete)
        input("Synchronizing pcap file..\n")

    storage.close()
