from sniffer import Sniffer
from queue import Queue
from typing import List
from gui import *

def get_ifaces() -> List:
    """Get all interfaces"""
    ifaces_list = list()
    ifaces_str = sniffer.show_all_ifaces(print_result=False)  # get all ifaces
    ifaces_str = str(ifaces_str).split('\n')

    for iface in ifaces_str:
        iface_column = list(filter(None, iface.split('  ')))
        for _ in iface_column:
            _ = _.strip()
        ifaces_list.append(iface_column)

    return ifaces_list
    
if __name__ == '__main__':
    sniffer = Sniffer()
    packet_watit_queue = Queue()  # shared queue, `sniffer`` stored the packet and `parse`` read
    ifaces_list = get_ifaces()
    print(ifaces_list)
    gui = GUI(sniffer, ifaces_list, packet_watit_queue)




