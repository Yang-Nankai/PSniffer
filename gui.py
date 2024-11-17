import struct
import tkinter as tk
import tkinter.messagebox
import ttkbootstrap as ttkb  # 第三方库，用于增强Tkinter的视觉效果
import parse as Parse
from tkinter import ttk, filedialog
from sniffer import Sniffer, SnifferThread


def xx():
    tk.messagebox.showinfo('Notification', 'The function of the current option is not yet implemented')

class GUI:
    def __init__(self, sniffer, ifaces_list, packet_wait_queue):
        """GUI"""
        self.sniffer = sniffer
        self.ifaces_list = ifaces_list
        self.packet_wait_queue = packet_wait_queue

        self.after_capture_filter_id = 0
        self.reverse = True
        self.mode = 0
        self.sniffer_process = None
        self.parse_process = None
        self.packet_list_after_id = None

        # 初始化主窗口
        self.root = ttkb.Window(themename="cosmo")  # 使用 ttkbootstrap
        self.root.title("PSniffer - Packet Sniffer")
        self.root.geometry(f"{int(self.root.winfo_screenwidth() / 1.3)}x{int(self.root.winfo_screenheight() / 1.3)}")
        self.root.resizable(width=True, height=True)

        # 创建菜单
        self.create_menu()

        # 配置主面板
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # 初始化第一个面板
        self.first_panel = ttk.Frame(self.root, padding=10, style="TFrame")
        self.first_panel.grid(sticky="NSEW")
        self.first_panel.rowconfigure(0, weight=1)
        self.first_panel.columnconfigure(0, weight=1)

        # 创建文件打开面板和网卡选择面板
        self.create_open_file_panel()
        self.create_ifaces_panel(ifaces_list=ifaces_list)

        self.root.protocol("WM_DELETE_WINDOW", self.exit_application)
        self.root.mainloop()

    def create_menu(self):
        """Create top menu."""
        self.menu = tk.Menu(self.root)

        # 添加菜单项
        self.menu.add_command(label="💾 Save as", command=self.save_as)
        self.menu.entryconfigure("💾 Save as", state=tk.DISABLED)
        self.menu.add_command(label="⏹️ Stop capture", command=self.stop_capture)
        self.menu.entryconfigure("⏹️ Stop capture", state=tk.DISABLED)
        self.menu.add_command(label="▶️ Resume capture", command=self.start_capture)
        self.menu.entryconfigure("▶️ Resume capture", state=tk.DISABLED)
        self.menu.add_command(label="❌ Exit", command=self.exit_application)
        self.menu.entryconfigure("❌ Exit", state=tk.ACTIVE)

        self.root.config(menu=self.menu)

    def create_open_file_panel(self):
        """Create file open panel."""
        self.open_pcap_frame = ttk.Frame(self.first_panel, padding=10, style="TFrame")
        self.open_pcap_frame.grid(row=0, columnspan=2, sticky="NSEW")

        # 添加标签和按钮
        label = ttk.Label(self.open_pcap_frame, text="📂 Open", font=("Comic Sans MS", 20), foreground="gray")
        button = ttk.Button(
            self.open_pcap_frame,
            text="Choose File Path",
            command=self.open_pcap_file,
            style="primary.Outline.TButton",
        )
        label.pack(side=tk.TOP, fill=tk.X, pady=5)
        button.pack(side=tk.TOP, pady=10)

    def create_ifaces_panel(self, ifaces_list=None):
        """Create the network card selection panel."""
        self.ifaces_choose_frame = ttk.Frame(self.first_panel, padding=10, style="TFrame")
        self.ifaces_choose_frame.grid(row=1, columnspan=2, sticky="NSEW")

        # 添加网卡选择表格
        label = ttk.Label(self.ifaces_choose_frame, text="🌐 Network Interfaces", font=("Comic Sans MS", 20), foreground="gray")
        label.pack(side=tk.TOP, fill=tk.X, pady=5)

        self.iface_list_treeview = ttk.Treeview(
            self.ifaces_choose_frame,
            show="headings",
            columns=("Index", "Name", "IPv4 Address", "IPv6 Address", "MAC Address"),
            style="Treeview",
        )
        self.iface_list_treeview.heading("Index", text="Index")
        self.iface_list_treeview.heading("Name", text="Name")
        self.iface_list_treeview.heading("IPv4 Address", text="IPv4 Address")
        self.iface_list_treeview.heading("IPv6 Address", text="IPv6 Address")
        self.iface_list_treeview.heading("MAC Address", text="MAC Address")

        for iface in ifaces_list[1:]:
            self.iface_list_treeview.insert("", "end", values=iface)

        self.iface_list_treeview.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=10)


    def create_packet_bin_panel(self):
        """Create binary data preview panel for packets."""
        self.packet_bin_frame = tk.Frame(self.root, bg='lightgray')
        self.packet_bin_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.packet_bin = tk.Listbox(self.packet_bin_frame, font=('Consolas', 10))
        self.packet_bin_scroll_y = ttk.Scrollbar(
            self.packet_bin_frame, orient=tk.VERTICAL, command=self.packet_bin.yview
        )
        self.packet_bin_scroll_x = ttk.Scrollbar(
            self.packet_bin_frame, orient=tk.HORIZONTAL, command=self.packet_bin.xview
        )
        self.packet_bin.configure(
            xscrollcommand=self.packet_bin_scroll_x.set, yscrollcommand=self.packet_bin_scroll_y.set
        )

        self.packet_bin_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_bin_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_bin.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def create_packet_header_panel(self):
        """Create packet header information preview panel."""
        self.packet_header_frame = tk.Frame(self.root)
        self.packet_header_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.packet_header = ttk.Treeview(self.packet_header_frame, show='tree')
        self.packet_header_scroll_y = ttk.Scrollbar(
            self.packet_header_frame, orient=tk.VERTICAL, command=self.packet_header.yview
        )
        self.packet_header_scroll_x = ttk.Scrollbar(
            self.packet_header_frame, orient=tk.HORIZONTAL, command=self.packet_header.xview
        )
        self.packet_header.configure(
            xscrollcommand=self.packet_header_scroll_x.set, yscrollcommand=self.packet_header_scroll_y.set
        )

        self.packet_header_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_header_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_header.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


    def create_ifaces_panel(self, ifaces_list=None):
        """Create network card selection panel."""
        self.ifaces_panel = tk.Frame(self.first_panel)
        self.ifaces_panel.grid(row=1, columnspan=2, sticky='nsew')

        columns = ("Index", "Name", "IPv4 Address", "IPv6 Address", "MAC Address")
        self.iface_list_treeview = ttk.Treeview(
            self.ifaces_panel, show='headings', columns=columns
        )
        for col in columns:
            self.iface_list_treeview.heading(col, text=col, anchor="center")
            self.iface_list_treeview.column(col, anchor="center", width=200)

        self.iface_list_scroll_x = ttk.Scrollbar(
            self.ifaces_panel, orient=tk.HORIZONTAL, command=self.iface_list_treeview.xview
        )
        self.iface_list_scroll_y = ttk.Scrollbar(
            self.ifaces_panel, orient=tk.VERTICAL, command=self.iface_list_treeview.yview
        )
        self.iface_list_treeview.configure(
            xscrollcommand=self.iface_list_scroll_x.set, yscrollcommand=self.iface_list_scroll_y.set
        )

        label_title = tk.Label(self.ifaces_panel, text='Capture', font=('楷书', 20), fg='gray')
        label_filter = tk.Label(self.ifaces_panel, text='   Filter:  ')
        self.filter_str = tk.StringVar()
        filter_entry = tk.Entry(self.ifaces_panel, textvariable=self.filter_str)

        label_title.pack(side=tk.TOP, fill=tk.X)
        self.iface_list_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.iface_list_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.iface_list_treeview.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        label_filter.pack(side=tk.LEFT)
        filter_entry.pack(side=tk.TOP, fill=tk.X)

        for iface in ifaces_list[1:]:
            self.iface_list_treeview.insert("", "end", values=iface)
        self.iface_list_treeview.bind("<Double-1>", self.switch_capture_panel)


    def create_packet_list_panel(self):
        """Create real-time packet capture update panel."""
        self.packet_list_frame = tk.Frame(self.root)
        self.packet_list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = (
            "Serial", "Time", "Origin Address", "Origin Port",
            "Destination Address", "Destination Port", "Protocol Type", "DNS Stream"
        )
        self.packet_list_treeview = ttk.Treeview(
            self.packet_list_frame, show='headings', columns=columns
        )
        for col in columns:
            self.packet_list_treeview.heading(col, text=col, anchor="center")
            self.packet_list_treeview.column(col, anchor="center", width=100)

        self.packet_list_scroll_x = ttk.Scrollbar(
            self.packet_list_frame, orient=tk.HORIZONTAL, command=self.packet_list_treeview.xview
        )
        self.packet_list_scroll_y = ttk.Scrollbar(
            self.packet_list_frame, orient=tk.VERTICAL, command=self.packet_list_treeview.yview
        )
        self.packet_list_treeview.configure(
            xscrollcommand=self.packet_list_scroll_x.set, yscrollcommand=self.packet_list_scroll_y.set
        )

        label_filter = tk.Label(self.packet_list_frame, text='  Filter:   ')
        self.after_capture_filter_str = tk.StringVar()
        filter_entry = tk.Entry(self.packet_list_frame, textvariable=self.after_capture_filter_str)
        filter_button = tk.Button(self.packet_list_frame, text='  Click to filter ', command=self.after_capture_filter_packet)

        self.packet_list_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_list_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list_treeview.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        label_filter.pack(side=tk.LEFT)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        filter_button.pack(side=tk.RIGHT)

        self.packet_list_treeview.bind("<ButtonPress-1>", self.display_packet_info)

    
    def switch_capture_panel(self, event):
        """Switch to packet capture interface and start capturing packets upon double-clicking an interface."""

        # Parse and validate filter
        self.filter_id = self.parse_filter(self.filter_str.get())
        if self.filter_id < 0:
            tk.messagebox.showwarning('Filter Error', 'Invalid filter, please re-enter.')
            return

        # Get selected interface from the list
        item = self.iface_list_treeview.identify('item', event.x, event.y)
        iface = self.iface_list_treeview.item(item, 'values')
        if not iface:
            tk.messagebox.showwarning('Selection Error', 'No interface selected.')
            return

        index = int(iface[1])
        if index <= 1:
            tk.messagebox.showwarning('Interface Error', 'Please select a valid interface (index > 1).')
            return

        # Store selected interface and start capture
        self.iface = iface
        self.mode = 1  # Packet capture mode
        self.start_capture_panel()
        self.start_capture()

    def start_capture_panel(self):
        """Initialize packet capture interface components."""
        self.first_panel.destroy()
        self.create_packet_list_panel()
        self.create_packet_header_panel()
        self.create_packet_bin_panel()

    def start_capture(self):
        """Configure UI and start packet capture and processing threads."""
        # Update menu state
        self.menu.entryconfigure('⏹️ Stop capture', state=tk.ACTIVE)
        self.menu.entryconfigure('▶️ Resume capture', state=tk.DISABLED)
        self.menu.entryconfigure('💾 Save as', state=tk.DISABLED)

        # Clear previous packet list
        self.packet_list_treeview.delete(*self.packet_list_treeview.get_children())

        # Setup socket and threads for capturing packets
        self.sniffer.create_socket(int(self.iface[1]))
        self.packet_wait_queue.queue.clear()

        self.sniffer_process = SnifferThread(self.packet_wait_queue, self.sniffer)
        self.sniffer_process.start()

        self.parse_process = Parse.ParseThread(self.packet_wait_queue, self.filter_id, self.filter_str.get())
        self.parse_process.start()

        # Start periodic packet display
        self.packet_list_after_id = self.packet_list_treeview.after(500, self.update_packet_list)

    def stop_capture(self):
        """Stop packet capture and associated threads."""
        if self.sniffer_process:
            self.sniffer_process.stop()
        if self.parse_process:
            self.parse_process.stop()
        if self.packet_list_after_id:
            self.update_packet_list()  # Ensure the last update
            self.packet_list_treeview.after_cancel(self.packet_list_after_id)

        # Update menu state
        self.menu.entryconfigure('⏹️ Stop capture', state=tk.DISABLED)
        self.menu.entryconfigure('▶️ Resume capture', state=tk.ACTIVE)
        self.menu.entryconfigure('💾 Save as', state=tk.ACTIVE)

    def update_packet_list(self):
        """Periodically update the packet list from parsed data."""
        if self.parse_process:
            while len(self.parse_process.packet_info) > self.parse_process.packet_display_index:
                info = self.parse_process.packet_info[self.parse_process.packet_display_index]
                packet_head = self.parse_process.packet_head[self.parse_process.packet_display_index]
                if Parse.filter_packet(self.after_capture_filter_id, packet_head, info, self.after_capture_filter_str.get()):
                    self.packet_list_treeview.insert(
                        "", "end", value=(
                            info['num'], info['time'], info['src_addr'], info['src_port'], 
                            info['dst_addr'], info['dst_port'], info['type'], info['dns_stream']
                        )
                    )
                self.parse_process.packet_display_index += 1

        # Schedule the next update
        self.packet_list_treeview.after(500, self.update_packet_list)

    def display_packet_info(self, event):
        """Display packet details when a packet is selected."""
        if self.mode == 1 and not self.parse_process:
            return

        # Get selected packet info
        item = self.packet_list_treeview.identify('item', event.x, event.y)
        packet_info = self.packet_list_treeview.item(item, 'values')
        if not packet_info:
            return

        index = int(packet_info[0]) - 1

        # Fetch packet and header data
        if self.mode == 1:
            packet = self.parse_process.packet_list[index]
            packet_heads = self.parse_process.packet_head[index]
        else:
            packet = self.packet_list[index]
            packet_heads = self.packet_head[index]

        # Display data
        self.display_packet_binary(packet)
        self.display_packet_headers(packet_heads)

    def display_packet_binary(self, packet):
        """Show binary stream of a packet."""
        self.packet_bin.delete(0, tk.END)
        packet_address = 0
        i = 0
        line = ''

        for byte in packet:
            if i == 0:
                line = f"{packet_address:04x}:  "
                packet_address += 16
            line += f"{byte:02x} "
            i += 1
            if i == 8:
                line += '  '
            if i == 16:
                self.packet_bin.insert(tk.END, line)
                i = 0

        if i > 0:
            self.packet_bin.insert(tk.END, line)

    def display_packet_headers(self, packet_heads):
        """Show packet headers in tree view."""
        self.packet_header.delete(*self.packet_header.get_children())
        for layer, header_info in packet_heads.items():
            layer_id = self.packet_header.insert('', 'end', text=layer)
            for key, value in header_info.items():
                self.packet_header.insert(layer_id, 'end', text=f"{key}: {value}")

    def exit_application(self):
        """Safely terminate all processes and exit the application."""
        if self.sniffer_process and self.sniffer_process.is_set():
            if tk.messagebox.askokcancel('Exit Confirmation', 'Packet capture is active. Do you want to exit?'):
                self.stop_capture()
                self.root.quit()
        else:
            if tk.messagebox.askokcancel('Exit Confirmation', 'Do you want to exit?'):
                self.root.quit()

    def save_as(self):
        """Save captured packets to a file."""
        file_path = filedialog.asksaveasfilename(filetypes=[('PCAP files', '*.pcap'), ('All files', '*.*')])
        if file_path:
            if self.mode == 1:
                self.save_packet_as_pcap(file_path, packets=self.parse_process.packet_list, pkt_times=self.parse_process.packet_time)
            else:
                self.save_packet_as_pcap(file_path, pcap_head=self.pcap_head, packets=self.packet_list, pkt_times=self.packet_time)


    def save_packet_as_pcap(self, file_path, pcap_head=None, packets=None, pkt_times=None):
        """Save the current captured packet data as a file"""
        # pcap file header
        if pcap_head is None:
            data = struct.pack('!I', int('d4c3b2a1', 16))
            data += struct.pack('!H', int('0200', 16))
            data += struct.pack('!H', int('0400', 16))
            data += struct.pack('!I', int('00000000', 16))
            data += struct.pack('!I', int('00000000', 16))
            data += struct.pack('!I', int('00000400', 16))
            data += struct.pack('!I', int('01000000', 16))
        else:
            data = pcap_head

        for index in range(min(len(packets), len(pkt_times))):
            packet = packets[index]
            time_high, time_low = pkt_times[index]
            data += struct.pack('<I', time_high)
            data += struct.pack('<I', time_low)
            # Packet size, in bytes
            # Convert to little endian
            data += struct.pack('<I', len(packet))
            data += struct.pack('<I', len(packet))
            data += packet

        try:
            f = open(file_path, 'wb')
            f.write(data)
            f.close()
        # except Exception:
        except IOError:
            tk.messagebox.showwarning('Save', 'Failed to save file ')
            return
        tk.messagebox.showinfo('Save', 'Save succssfully')

    def open_pcap_file(self):
        file_path = tk.filedialog.askopenfilename(
            filetypes=[('pcap file', '*.pcap')]
        )
        if file_path:
            if file_path.split('.')[-1] != 'pcap':
                tk.messagebox.showwarning('Open', 'Can only parse files in pcap format!')
                return

            self.mode = 2
            self.pcap_head, self.packet_time, self.packet_list, self.packet_info, self.packet_head \
                = Parse.parse_pcap_file(file_path)

            self.start_capture_panel()

            self.menu.entryconfigure('⏹️ Stop capture', state=tk.DISABLED)
            self.menu.entryconfigure('▶️ Resume capture', state=tk.DISABLED)
            self.menu.entryconfigure('💾 Save as', state=tk.ACTIVE)

            index = 0
            while len(self.packet_info) != index:
                info = self.packet_info[index]
                index += 1
                self.packet_list_treeview.insert('', 'end', value=(info['num'], info['time'], info['src_addr'],
                                                                info['src_port'], info['dst_addr'],
                                                                info['dst_port'], info['type'],
                                                                info['dns_stream']))

    def treeview_sort(self, treeview, col, reverse):
        """
        Sort the treeview column when the header is clicked.
        """
        items = [(treeview.set(k, col), k) for k in treeview.get_children('')]

        def sort_numeric(item):
            value, _ = item
            return -1 if value == '-' else int(value)

        if col in {'1', '4', '6', '8', '9'}:  # Numeric columns
            items.sort(key=sort_numeric, reverse=reverse)
        else:  # Non-numeric columns
            items.sort(reverse=reverse)

        for idx, (_, k) in enumerate(items):
            treeview.move(k, '', idx)

        # Update the header to allow toggling sort order
        treeview.heading(col, command=lambda: self.treeview_sort(treeview, col, not reverse))


    def parse_filter(self, filter_str):
        """
        Parse the filter string to validate and return its corresponding ID.
        """
        if not filter_str.strip():
            return 0  # Default: no filter

        filter_mapping = {
            'tcp': 1,
            'udp': 2,
            'dns': 13
        }
        filter_id = filter_mapping.get(filter_str.strip().lower())
        if filter_id is not None:
            return filter_id

        # Advanced filters
        filter_str = filter_str.replace(' ', '')
        keyword, *args = filter_str.split('==')
        advanced_filters = {
            'ip': 3,
            'port': 4,
            'src.ip': 5,
            'dst.ip': 6,
            'src.port': 7,
            'dst.port': 8,
            'tcp.port': 9,
            'udp.port': 10,
            'tcp.stream': 11,
            'udp.stream': 12
        }
        return advanced_filters.get(keyword, -1)


    def after_capture_filter_packet(self):
        """
        Apply filters to packets after capturing.
        """
        filter_str = self.after_capture_filter_str.get()
        self.after_capture_filter_id = self.parse_filter(filter_str)

        if self.after_capture_filter_id < 0:
            tk.messagebox.showwarning('Filter', 'Unable to parse filter, please re-enter')
            return

        self.packet_list_treeview.delete(*self.packet_list_treeview.get_children())

        if self.mode == 1:  # Live capture
            self.parse_process.packet_display_index = 0
            self.update_packet_list()
        else:  # Post-capture analysis
            self.display_filtered_packets(filter_str)

    def display_filtered_packets(self, filter_str):
        """
        Display filtered packets during post-capture analysis.
        """
        for index, info in enumerate(self.packet_info):
            packet_head = self.packet_head[index]
            if Parse.filter_packet(self.after_capture_filter_id, packet_head, info, filter_str):
                self.packet_list_treeview.insert('', 'end', values=(
                    info['num'], info['time'], info['src_addr'], info['src_port'],
                    info['dst_addr'], info['dst_port'], info['type'], info['dns_stream']
                ))
