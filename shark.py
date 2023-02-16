import pyshark


class WiresharkAnalysis:
    def __init__(self, tshark_path, interface, bpf_filter, keep_packets, display_filter, ):
        self.tshark_path = tshark_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.keep_packets = keep_packets
        self.display_filter = display_filter
        # self.cap = pyshark.LiveCapture(interface=self.interface, tshark_path=self.tshark_path,
        #                              display_filter=self.display_filter)
        self.cap = pyshark.LiveCapture(tshark_path=self.tshark_path, display_filter="tls")
        self.cap.sniff(timeout=5)

    def print_ans(self):
        print("self.cap: ", self.cap)

        for tmp_packet in self.cap:
            print(tmp_packet)


if __name__ == "__main__":
    print("----- begin the test -----")
    print("--init--")
    test_shark = WiresharkAnalysis(tshark_path="D:\\software\\Wireshark\\tshark.exe", interface=None,
                                   bpf_filter=None, keep_packets=True, display_filter="TLS")
    print("--init end--")
    test_shark.print_ans()
    print("----- end of test -----")
