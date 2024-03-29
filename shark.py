import pyshark
import pid_name
from pyshark.tshark.tshark import get_all_tshark_interfaces_names


def binary_ans(values):
    """get values binary data

    :param values:
    :return: binary data
    """
    hex_data = values.__next__().frame_raw.value
    binary_data = bytearray.fromhex(hex_data)
    return binary_data


class WiresharkAnalysis:
    def __init__(self, tshark_path, interface, bpf_filter, keep_packets, display_filter, ):
        """

        :param tshark_path:    tshark的安装地址
        :param interface:      接口 [仅用于LiveCapture] 进行嗅探的网络接口。如果没有给出，使用可用的第一个接口。
        :param bpf_filter:     捕获过滤器，过滤规则 [仅用于LiveCapture]
        :param keep_packets:   使用结束是否保存
        :param display_filter: 显示过滤器，过滤规则
        """
        self.tshark_path = tshark_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.keep_packets = keep_packets
        self.display_filter = display_filter
        self.list_get_infor = []
        self.cap = None

    def pyshark_file_capture(self, file_rode, display_filter_):
        """ 从文件读取数据

        :param file_rode: 要读取文件的路径  例如 'test11.py.pcap'
        :param display_filter_: 过滤规则
        :return:
        """
        self.cap = pyshark.FileCapture(tshark_path=self.tshark_path, input_file=file_rode,
                                       display_filter=display_filter_, keep_packets=False)

    def pyshark_live_capture(self, interface_, display_filter_):
        """实时监控接口数据

        :param interface_: 接口
        :param display_filter_: 过滤规则
        :return:
        """
        # 进入实时监听模式
        self.cap = pyshark.LiveCapture(interface=interface_,
                                       tshark_path=self.tshark_path,
                                       display_filter=display_filter_)
        # 将监听数据进行保存
        self.cap.sniff(packet_count=2000)

    def storage_tls_ja3(self, hh_type, source_ip, destination_ip, ja3_s_str, ja3_s):
        """storage_tls_ja3 in self.list_get_infor
        storage client_ip sever_ip port ja3 ja3s

        :param hh_type: str '1' is client hello, '2' is sever hello
        :param source_ip:
        :param destination_ip:
        :param ja3_s_str: ja3(s) string
        :param ja3_s: ja3 for client hello, ja3s for sever hello
        :return: True right , False error
        """

        if hh_type != "1" and hh_type != "2":  # 传入包 错误，不是 hello包 直接退出
            print("--hh_type != 1 / 2: error--")
            return False

        client_ip = ''
        sever_ip = ''
        if hh_type == "1":  # 将客户 IP 与服务器 IP进行分离
            client_ip = source_ip
            sever_ip = destination_ip
        elif hh_type == "2":
            client_ip = destination_ip
            sever_ip = source_ip

        for tmp in self.list_get_infor:
            if tmp["client_ip"] == client_ip and tmp["sever_ip"] == sever_ip:  # 本 ja3 曾经保存过
                print("搜索过了")
                if hh_type == "1":  # 发现， 并添加到 ja3 中，以字典格式 {ja3：ja3str}
                    if ja3_s in tmp["ja3"].keys():
                        pass
                    else:
                        tmp["ja3"][ja3_s] = ja3_s_str
                elif hh_type == "2":
                    if ja3_s in tmp["ja3s"].keys():
                        pass
                    else:
                        tmp["ja3s"][ja3_s] = ja3_s_str
                return True  # 添加成功
        # 并没有接受过该路径包，加入包
        dic = {"client_ip": '', "sever_ip": '', "port": [], "ja3": {}, "ja3s": {}}
        if hh_type == "1":
            dic["client_ip"] = source_ip
            dic["sever_ip"] = destination_ip
            dic["ja3"] = {ja3_s: ja3_s_str}
        elif hh_type == "2":
            dic["client_ip"] = destination_ip
            dic["sever_ip"] = source_ip
            dic["ja3s"] = {ja3_s: ja3_s_str}
        self.list_get_infor.append(dic)
        return True

    def count_file_ja3(self):
        ja3_dict = {}

        for tmp_packet in self.cap:
            try:
                if "tls" in tmp_packet.__dir__() and "record" in tmp_packet.tls.__dir__() \
                        and 'Client Hello' in tmp_packet.tls.record:  # client hello
                    ja3 = tmp_packet.tls.handshake_ja3_full
                    if ja3 in ja3_dict.keys():  # 如果该指纹已经存在
                        ja3_dict[ja3] = ja3_dict[ja3] + 1  # 自增一
                    else:
                        ja3_dict[ja3] = 1
            except AttributeError:
                print("-----------error------------")
                print("shark.WiresharkAnalysis.count_file_ja3")
                print("tmp_packet.tls", tmp_packet.tls)
                print("----------------------------")
                print()

        return ja3_dict

    def count_live_ja3(self):
        ja3_dict = {}
        information = {"TLS count": 0, "TCP count": 0, "all count": 0, "all Length": 0, "TLS Length": 0}

        for tmp_packet in self.cap:
            information["all count"] += 1
            information["all Length"] += int(tmp_packet.length)
            if 'tcp' in tmp_packet.__dir__():
                information["TCP count"] += 1
            try:
                if "tls" in tmp_packet.__dir__():
                    information["TLS count"] += 1
                    information["TLS Length"] += int(tmp_packet.length)
                if "tls" in tmp_packet.__dir__() and "record" in tmp_packet.tls.__dir__() \
                        and 'Client Hello' in tmp_packet.tls.record:  # client hello
                    ja3 = tmp_packet.tls.handshake_ja3_full
                    if ja3 in ja3_dict.keys():  # 如果该指纹已经存在
                        ja3_dict[ja3] = ja3_dict[ja3] + 1  # 自增一
                    else:
                        ja3_dict[ja3] = 1
            except AttributeError:
                print("-----------error------------")
                print("shark.WiresharkAnalysis.count_live_ja3")
                print("tmp_packet.tls", tmp_packet.tls)
                print("----------------------------")
                print()

        return ja3_dict, information

    def information_(self):
        """
        返回本次数据流相关信息
        :return: 一个字典information =
        {"TLS count": 0, "TCP count": 0, "all count": 0, "all Length": 0, "TLS Length": 0,
        "TLS 1.0": 0, "TLS 1.1": 0, "TLS 1.2": 0}}
        """
        information = {"TLS count": 0, "TCP count": 0, "all count": 0, "all Length": 0, "TLS Length": 0,
                       "TLS 1.0": 0, "TLS 1.1": 0, "TLS 1.2": 0, "TLS 1.3": 0}

        for tmp_packet in self.cap:
            information["all count"] += 1
            information["all Length"] += int(tmp_packet.length)
            if 'tcp' in tmp_packet.__dir__():
                information["TCP count"] += 1
                if "tls" in tmp_packet.__dir__() and "record" in tmp_packet.tls.__dir__() \
                        and 'Client Hello' in tmp_packet.tls.record:  # client hello:
                    information["TLS count"] += 1
                    information["TLS Length"] += int(tmp_packet.length)
                    if tmp_packet.tls.handshake_version == "0x0301":  # 1.0
                        information["TLS 1.0"] += 1
                    elif tmp_packet.tls.handshake_version == "0x0302":  # 1.1
                        information["TLS 1.1"] += 1
                    elif tmp_packet.tls.handshake_version == "0x0303":  # 1.2 or 1.3
                        flag = True
                        for typ in tmp_packet.tls.handshake_extension_type.all_fields:
                            if "supported_versions" in typ.showname_value:   # 有扩展 versions
                                flag = False
                                for vision in tmp_packet.tls.handshake_extensions_supported_version.all_fields:
                                    if "TLS 1.3" in vision.showname_value:
                                        information["TLS 1.3"] += 1
                                        break
                                    elif "TLS 1.2" in vision.showname_value:
                                        information["TLS 1.2"] += 1
                                        break
                                break  # 跳出循环结束
                        if flag:   # 如果没有触发过循环查找 扩展versions 则是 tls 1.2
                            information["TLS 1.2"] += 1

        return information

    def test_(self):
        print("num of cap: ", len(self.cap))

        count = 0
        for tmp_packet in self.cap:
            print("NO.", count)
            count += 1
            if count > 30:
                break
            print("源地址  : ", tmp_packet.ip.src)
            print("目的地址: ", tmp_packet.ip.dst)
            # print(dir(tmp_packet))
            print("layers", tmp_packet.layers)  # 查看都有哪些层

            if "tls" not in tmp_packet:  # 如果没有tls层 跳过
                print("not have tls")
                # print(tmp_packet)
                continue

            if "tcp" in tmp_packet:
                pass
            else:
                print("not tcp")
                continue

            # print(tmp_packet.tls)
            print(tmp_packet.tls.handshake_type)
            if tmp_packet.tls.handshake_type == "1":  # ja3 client hello
                print("JA3", tmp_packet.tls.handshake_ja3)
                print("JA3 Full string", tmp_packet.tls.handshake_ja3_full)
                # ------
                port_tcp = tmp_packet.tcp.srcport
                print("tcp端口: ", tmp_packet.tcp.port)
                print("tcp dst port", tmp_packet.tcp.dstport)
                print("tcp src port", tmp_packet.tcp.srcport)
                pid_port = pid_name.port_pid(port_tcp)
                if pid_port is not None:
                    print("pid:", pid_port)
                    print("name:", pid_name.pid_name(pid_port))
                else:
                    print("未找到对应的pid")
                # ------
                self.storage_tls_ja3(tmp_packet.tls.handshake_type, tmp_packet.ip.src, tmp_packet.ip.dst,
                                     tmp_packet.tls.handshake_ja3_full, tmp_packet.tls.handshake_ja3)
            elif tmp_packet.tls.handshake_type == "2":  # ja3 sever hello
                print("JA3S", tmp_packet.tls.handshake_ja3s)
                print("JA3S Full string", tmp_packet.tls.handshake_ja3s_full)
                self.storage_tls_ja3(tmp_packet.tls.handshake_type, tmp_packet.ip.src, tmp_packet.ip.dst,
                                     tmp_packet.tls.handshake_ja3s_full, tmp_packet.tls.handshake_ja3s)
            print("\n\n")

        for i in self.list_get_infor:
            print(i)

    def print_ans(self):
        """print test11.py information

        :return:
        """
        print("num of cap: ", len(self.cap))
        count = 0
        for tmp_packet in self.cap:
            print("NO.", count)
            count += 1
            print("源地址  : ", tmp_packet.ip.src)
            print("目的地址: ", tmp_packet.ip.dst)

            if "tcp" in tmp_packet:
                print("tcp端口: ", tmp_packet.tcp.port)
            elif "udp" in tmp_packet:
                print("udp端口: ", tmp_packet.udp.port)
            print(tmp_packet.tls)

            print("\n\n")

    def close(self):
        self.cap.close()

    def get_interface(self):
        all_interfaces = get_all_tshark_interfaces_names(self.tshark_path)
        return all_interfaces


if __name__ == "__main__":
    print("----- begin the test11.py -----")

    test_shark = WiresharkAnalysis(tshark_path="D:\\software\\Wireshark\\tshark.exe", interface=None,
                                   bpf_filter=None, keep_packets=True,
                                   display_filter="(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != "
                                                  "127.0.0.1")
    test_shark.pyshark_live_capture("(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != 127.0.0.1")
    print("--init end--")
    test_shark.test_()
    print("----- end of test11.py -----")
