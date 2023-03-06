import psutil


def port_pid(port: int):
    """
    查找端口对应的pid
    :param port: int 端口号
    :return:  int pid号
    """

    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.laddr.port == port:
            return con_info.pid
    return None


def pid_name(pid_: int):
    """
    返回 pid 对应的应用名称
    :param pid_:
    :return:
    """
    return psutil.Process(pid=pid_).name()
