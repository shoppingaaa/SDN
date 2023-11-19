from flask import Flask, render_template
import random
from collections import defaultdict
from scapy.all import rdpcap

app = Flask(__name__)


class CountMinSketch:
    def __init__(self, width, depth):
        self.width = width
        self.depth = depth
        self.sketch = [[0] * width for _ in range(depth)]

    def update(self, flow_hash):
        for i in range(self.depth):
            hash_val = (flow_hash + i) % self.width
            self.sketch[i][hash_val] += 1

    def estimate(self, flow_hash):
        min_count = float('inf')
        for i in range(self.depth):
            hash_val = (flow_hash + i) % self.width
            min_count = min(min_count, self.sketch[i][hash_val])
        return min_count


def calculate_flow_frequency(dataset, width, depth):
    flow_counter = CountMinSketch(width, depth)
    for packet in dataset:
        if packet.haslayer("IP"):
            src_ip = packet.payload.src  # 获取源IP
            dst_ip = packet.payload.dst  # 获取目的IP
            src_port = packet.payload.payload.sport  # 获取源端口
            dst_port = packet.payload.payload.dport  # 获取目的端口
            protocol = packet.payload.payload.name  # 获取传输层协议
            flow_info = (src_ip, dst_ip, src_port, dst_port, protocol)
            flow_hash = hash(flow_info)  # 计算流的哈希值
            flow_counter.update(flow_hash)  # 更新Count-Min Sketch
    return flow_counter


@app.route('/')
def index():
    pcap_file = "sdn_2.pcap"
    dataset = rdpcap(pcap_file)  # 使用rdpcap函数读取pcap文件
    width = 1000  # Count-Min Sketch的宽度
    depth = 5  # Count-Min Sketch的深度
    flow_frequency = calculate_flow_frequency(dataset, width, depth)

    seen_flows = {}  # 用于跟踪已经处理过的流
    flow_estimates = []  # 保存流信息和频率估计值
    for packet in dataset:
        if packet.haslayer("IP"):
            src_ip = packet.payload.src  # 获取源IP
            dst_ip = packet.payload.dst  # 获取目的IP
            src_port = packet.payload.payload.sport  # 获取源端口
            dst_port = packet.payload.payload.dport  # 获取目的端口
            protocol = packet.payload.payload.name  # 获取传输层协议
            flow_info = (src_ip, dst_ip, src_port, dst_port, protocol)
            flow_hash = hash(flow_info)  # 计算流的哈希值
            if flow_hash not in seen_flows:
                flow_estimate = flow_frequency.estimate(flow_hash)  # 估计流的频率
                flow_estimates.append((flow_info, flow_estimate))
                seen_flows[flow_hash] = True  # 将该流标记为已处理

    return render_template('index.html', flow_estimates=flow_estimates)


if __name__ == '__main__':
    app.run()
