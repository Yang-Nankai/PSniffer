import threading
import scapy.all as scapy
from queue import Queue


class Sniffer:
    def __init__(self):
        self.iface = None
        self.socket = None

    def create_socket(self, index: int):
        """Ensure one interface according to the index and create a socket to bind for sniffing"""
        if index < 0:
            return False
        self.iface = scapy.IFACES.dev_from_index(index)
        # Bind for sniffing
        self.socket = scapy.conf.L2socket(iface=self.iface)
        return True
    
    def get_one_packet(self):
        """Capture one packet"""
        return self.socket.recv_raw()
    
    @staticmethod
    def show_all_ifaces(print_result: bool=True):
        """Print all interfaces"""
        return scapy.IFACES.show(print_result=print_result)


class SnifferThread(threading.Thread):
    """Defined a thread to sniff packets."""
    def __init__ (self, packet_queue: Queue, sniffer: Sniffer):
        super(SnifferThread, self).__init__()
        self.packet_queue = packet_queue
        self.sniffer = sniffer
        self.__flag = threading.Event()  # for pause
        self.__flag.set()
        self.__running = threading.Event()  # for stop
        self.__running.set()

    def run(self):
        while self.__running.isSet():
            self.__flag.wait()
            l2_type, l2_packet, time = self.sniffer.get_one_packet()
            if l2_packet is not None:
                self.packet_queue.put((l2_type, l2_packet, time))

    def pause(self):
        """Thread Pause."""
        self.__flag.clear()
    
    def resume(self):
        """Thread Resume."""
        self.__flag.set()
    
    def stop(self):
        """Thread Exit."""
        self.__flag.set()
        self.__running.clear()
    
    def is_set(self):
        return self.__running.isSet()
    


            
