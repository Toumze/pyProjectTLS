import pyshark
import ja3


class WiresharkAnalysis:
    def __init__(self, tshark_path, interface, bpf_filter, keep_packets, display_filter, ):
        self.tshark_path = tshark_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.keep_packets = keep_packets
        self.display_filter = display_filter
        # self.cap = pyshark.LiveCapture(interface=self.interface, tshark_path=self.tshark_path,
        #                              display_filter=self.display_filter)
        # 进入实时监听模式
        self.cap = pyshark.LiveCapture(tshark_path=self.tshark_path,
                                       display_filter=self.display_filter)
        # 将监听数据进行保存
        self.cap.sniff(timeout=2)

    def print_ans(self):
        print("num of cap: ", len(self.cap))
        count = 0
        for tmp_packet in self.cap:
            print("NO.", count)
            count += 1
            print("源地址 : ", tmp_packet.ip.src)
            print("目的地址: ", tmp_packet.ip.dst)
            print("端口   : ", tmp_packet.tcp.port)
            print(tmp_packet.tls)
            # handshake_type 2 -> Server Hello
            # handshake_type 1 -> Client Hello
            # print("handshake_type", tmp_packet.tls.handshake_type)
            print("handshake", tmp_packet.tls.handshake)

            ja3_digest = ja3.JA3Digest(tmp_packet)
            ja3_string = ja3_digest.get_ja3()
            print("ja3_digest: ", ja3_digest)
            print("ja3_string: ", ja3_string)

            # print(dir(tmp_packet.tls))
            print("\n\n")


if __name__ == "__main__":
    print("----- begin the test -----")
    print("--init--")
    test_shark = WiresharkAnalysis(tshark_path="D:\\software\\Wireshark\\tshark.exe", interface=None,
                                   bpf_filter=None, keep_packets=True,
                                   display_filter="(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != "
                                                  "127.0.0.1")
    print("--init end--")
    test_shark.print_ans()
    print("----- end of test -----")
