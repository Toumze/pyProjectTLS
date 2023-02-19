import pyshark


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
        self.tshark_path = tshark_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.keep_packets = keep_packets
        self.display_filter = display_filter
        self.list_get_infor = []
        self.cap = None

    def pyshark_file_capture(self, file_rode, display_filter_):
        """ 从文件读取数据

        :param file_rode: 路径
        :param display_filter_: 过滤规则
        :return:
        """
        self.cap = pyshark.FileCapture(tshark_path=self.tshark_path, input_file=file_rode,
                                       display_filter=display_filter_)

    def pyshark_live_capture(self, display_filter_):
        """实时监控接口数据

        :param display_filter_: 过滤规则
        :return:
        """
        # 进入实时监听模式
        self.cap = pyshark.LiveCapture(tshark_path=self.tshark_path,
                                       display_filter=display_filter_)
        # 将监听数据进行保存
        self.cap.sniff(timeout=2)

        """
        ['', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', 
        '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', 
        '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', 
        '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', 
        '__setattr__', '__setstate__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', 
        '_all_fields', '_field_prefix', '_get_all_field_lines', '_get_all_fields_with_alternates', 
        '_get_field_or_layer_repr', '_get_field_repr', '_layer_name', '_pretty_print_layer_fields', 
        '_sanitize_field_name', 'compress_certificate_algorithm', 
        'compress_certificate_algorithms_length', 'extension_psk_ke_mode', 
        'extension_psk_ke_modes_length', 'field_names', 'get', 'get_field', 
        'get_field_by_showname', 'get_field_value', 'handshake', 'handshake_cipher_suites_length', 
        'handshake_ciphersuite', 'handshake_ciphersuites', 'handshake_comp_method', 'handshake_comp_methods', 
        'handshake_comp_methods_length', 'handshake_extension_data', 'handshake_extension_len', 
        'handshake_extension_type', 'handshake_extensions_alpn_len', 'handshake_extensions_alpn_list', 
        'handshake_extensions_alpn_str', 'handshake_extensions_alpn_str_len', 
        'handshake_extensions_alps_alpn_list', 'handshake_extensions_alps_alpn_str', 
        'handshake_extensions_alps_alpn_str_len', 'handshake_extensions_alps_len', 
        'handshake_extensions_ec_point_format', 'handshake_extensions_ec_point_formats', 
        'handshake_extensions_ec_point_formats_length', 'handshake_extensions_key_share_client_length', 
        'handshake_extensions_key_share_group', 'handshake_extensions_key_share_key_exchange', 
        'handshake_extensions_key_share_key_exchange_length', 'handshake_extensions_length', 
        'handshake_extensions_padding_data', 'handshake_extensions_reneg_info_len', 
        'handshake_extensions_server_name', 'handshake_extensions_server_name_len', 
        'handshake_extensions_server_name_list_len', 'handshake_extensions_server_name_type', 
        'handshake_extensions_status_request_exts_len', 'handshake_extensions_status_request_responder_ids_len', 
        'handshake_extensions_status_request_type', 'handshake_extensions_supported_group', 
        'handshake_extensions_supported_groups', 'handshake_extensions_supported_groups_length', 
        'handshake_extensions_supported_version', 'handshake_extensions_supported_versions_len', 
        'handshake_ja3', 'handshake_ja3_full', 'handshake_length', 'handshake_random', 
        'handshake_random_bytes', 'handshake_random_time', 'handshake_session_id', 
        'handshake_session_id_length', 'handshake_sig_hash_alg', 'handshake_sig_hash_alg_len', 
        'handshake_sig_hash_algs', 'handshake_sig_hash_hash', 'handshake_sig_hash_sig', 'handshake_type', 
        'handshake_version', 'has_field', 'layer_name', 'pretty_print', 'raw_mode', 'record', 
        'record_content_type', 'record_length', 'record_version']
        """
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

        if hh_type != "1" and hh_type != "2":   # 传入包 错误，不是 hello包 直接退出
            print("--hh_type != 1 / 2: error--")
            return False

        client_ip = ''
        sever_ip = ''
        if hh_type == "1":   # 将客户 IP 与服务器 IP进行分离
            client_ip = source_ip
            sever_ip = destination_ip
        elif hh_type == "2":
            client_ip = destination_ip
            sever_ip = source_ip

        for tmp in self.list_get_infor:
            if tmp["client_ip"] == client_ip and tmp["sever_ip"] == sever_ip:    # 本 ja3 曾经保存过
                print("搜索过了")
                if hh_type == "1":     # 发现， 并添加到 ja3 中，以字典格式 {ja3：ja3str}
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
            print("layers", tmp_packet.layers)

            if "tls" not in tmp_packet:
                print("not have tls")
                # print(tmp_packet)
                continue

            if "tcp" in tmp_packet:
                print("tcp端口: ", tmp_packet.tcp.port)
            else:
                print("not tcp")
                continue

            # print(tmp_packet.tls)
            print(tmp_packet.tls.handshake_type)
            if tmp_packet.tls.handshake_type == "1":       # ja3 client hello
                print("JA3", tmp_packet.tls.handshake_ja3)
                print("JA3 Full string", tmp_packet.tls.handshake_ja3_full)
                self.storage_tls_ja3(tmp_packet.tls.handshake_type, tmp_packet.ip.src, tmp_packet.ip.dst,
                                     tmp_packet.tls.handshake_ja3_full, tmp_packet.tls.handshake_ja3)
            elif tmp_packet.tls.handshake_type == "2":     # ja3 sever hello
                print("JA3S", tmp_packet.tls.handshake_ja3s)
                print("JA3S Full string", tmp_packet.tls.handshake_ja3s_full)
                self.storage_tls_ja3(tmp_packet.tls.handshake_type, tmp_packet.ip.src, tmp_packet.ip.dst,
                                     tmp_packet.tls.handshake_ja3s_full, tmp_packet.tls.handshake_ja3s)
            print("\n\n")

        for i in self.list_get_infor:
            print(i)

    def print_ans(self):
        """print test information

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


if __name__ == "__main__":
    print("----- begin the test -----")
    print("--init--")
    test_shark = WiresharkAnalysis(tshark_path="D:\\software\\Wireshark\\tshark.exe", interface=None,
                                   bpf_filter=None, keep_packets=True,
                                   display_filter="(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != "
                                                  "127.0.0.1")
    test_shark.pyshark_live_capture("(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != 127.0.0.1")
    print("--init end--")
    test_shark.test_()
    print("----- end of test -----")
