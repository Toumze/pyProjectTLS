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
        # self.cap = pyshark.LiveCapture(interface=self.interface, tshark_path=self.tshark_path,
        #                              display_filter=self.display_filter)
        # 进入实时监听模式
        self.cap = pyshark.LiveCapture(tshark_path=self.tshark_path,
                                       display_filter=self.display_filter)
        # 将监听数据进行保存
        self.cap.sniff(timeout=2)

    def test_(self):
        print("num of cap: ", len(self.cap))
        count = 0
        for tmp_packet in self.cap:
            print("NO.", count)
            count += 1
            if count > 10:
                break
            print("源地址  : ", tmp_packet.ip.src)
            print("目的地址: ", tmp_packet.ip.dst)
            if "tcp" in tmp_packet:
                print("tcp端口: ", tmp_packet.tcp.port)

            # print(tmp_packet.tls)
            print(tmp_packet.tls.handshake_type)
            if tmp_packet.tls.handshake_type == "1":       # ja client hello
                print("JA3", tmp_packet.tls.handshake_ja3)
                print("JA3 Full string", tmp_packet.tls.handshake_ja3_full)
            elif tmp_packet.tls.handshake_type == "2":     # ja3 sever hello
                print("JA3S", tmp_packet.tls.handshake_ja3s)
                print("JA3S Full string", tmp_packet.tls.handshake_ja3s_full)
            print("\n\n")
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
            print("packet    : ", type(tmp_packet))
            print("packet tls: ", type(tmp_packet.tls))
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
    print("--init end--")
    test_shark.test_()
    print("----- end of test -----")
