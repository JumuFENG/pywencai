import os
import time
import random
from functools import lru_cache
from fake_useragent import UserAgent


@lru_cache(maxsize=1)
def random_useragent():
    ua = UserAgent()
    return ua.random


class BinaryCodec:
    def __init__(self, base_fields):
        self.base_fields = base_fields
        # 初始化所有字段为0
        for i in range(len(base_fields)):
            setattr(self, str(i), 0)

    def to_buffer(self):
        """将字段转换为字节数组"""
        u = self.base_fields
        c = []
        s = -1

        for v in range(len(u)):
            l = getattr(self, str(v))  # this[v]
            p = u[v]  # field size
            s += p    # update offset
            d = s     # current position

            # JavaScript: (c[d] = l & 255), --p != 0; --d, (l >>= 8)
            while p > 0:
                if d >= len(c):
                    c.extend([0] * (d - len(c) + 1))
                c[d] = l & 255
                p -= 1
                if p > 0:
                    d -= 1
                    l >>= 8

        return c

    def decode_buffer(self, buffer):
        """从字节数组解码字段"""
        a = self.base_fields
        o = 0

        for u in range(len(a)):
            v = a[u]  # field size
            l = 0

            # JavaScript: l = (l << 8) + n[o++]; while (--v > 0)
            while v > 0:
                if o < len(buffer):
                    l = (l << 8) + buffer[o]
                o += 1
                v -= 1

            setattr(self, str(u), l & 0xFFFFFFFF)


class HexinEncoder:
    def __init__(self):
        self.b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    def simple_hash(self, data):
        """简单哈希函数"""
        e = 0
        for i in range(len(data)):
            e = (e << 5) - e + data[i]
        return e & 255

    def encrypt_data(self, src):
        """加密数据"""
        key = self.simple_hash(src)
        dst = [3, key]

        for i in range(len(src)):
            dst.append(src[i] ^ (key & 255))
            key = ~(key * 131) & 0xFFFFFFFF

        return dst

    def base64_encode(self, byte_array):
        """Base64编码"""
        result = []

        i = 0
        while i < len(byte_array):
            # 获取3个字节，不足的用0补充
            b1 = byte_array[i] if i < len(byte_array) else 0
            b2 = byte_array[i+1] if i+1 < len(byte_array) else 0
            b3 = byte_array[i+2] if i+2 < len(byte_array) else 0

            # 合并为24位整数
            chunk = (b1 << 16) | (b2 << 8) | b3

            # 分割为4个6位整数并映射到Base64字符
            result.append(self.b64chars[chunk >> 18])
            result.append(self.b64chars[(chunk >> 12) & 63])
            result.append(self.b64chars[(chunk >> 6) & 63])
            result.append(self.b64chars[chunk & 63])

            i += 3

        return ''.join(result)

    def encode(self, data):
        """编码数据"""
        encrypted = self.encrypt_data(data)
        return self.base64_encode(encrypted)


class TokenGenerator:
    def __init__(self, user_agent=None):
        self.cdec = None
        self.encoder = HexinEncoder()
        self.init(user_agent)

    def init(self, user_agent=None):
        """初始化"""
        self.cdec = BinaryCodec([4, 4, 4, 4, 1, 1, 1, 3, 2, 2, 2, 2, 2, 2, 2, 4, 2, 1])

        # 设置固定值
        setattr(self.cdec, '0', self.get_random())
        setattr(self.cdec, '1', self.get_server_time_now())
        user_agent = random_useragent() if user_agent is None else user_agent
        setattr(self.cdec, '3', self.str_hash(user_agent))
        setattr(self.cdec, '4', self.get_platform())
        setattr(self.cdec, '5', self.get_browser_index())
        setattr(self.cdec, '6', self.get_plugin_num())
        setattr(self.cdec, '13', self.get_browser_feature())
        setattr(self.cdec, '15', 0)
        setattr(self.cdec, '16', 0)
        setattr(self.cdec, '17', 3)

    def get_random(self):
        """生成随机数"""
        return random.randint(0, 0xFFFFFFFF)

    def get_server_time_now(self):
        return int(time.time())

    def time_now(self):
        """获取当前时间（秒）"""
        return int(time.time())

    def str_hash(self, s):
        """字符串哈希"""
        c = 0
        for v in range(len(s)):
            c = (c << 5) - c + ord(s[v])
            c = c & 0xFFFFFFFF  # JavaScript的 >>>= 0 操作
        return c

    def get_platform(self):
        return 0

    def get_browser_index(self):
        return 11

    def get_plugin_num(self):
        return 0

    def get_browser_feature(self):
        return 2848

    def update(self):
        """更新token"""
        # 更新计数器
        current_counter = getattr(self.cdec, '16')
        setattr(self.cdec, '16', (current_counter + 1) & 0xFFFF)

        # 更新时间戳
        setattr(self.cdec, '1', self.get_server_time_now())
        setattr(self.cdec, '2', self.time_now())
        setattr(self.cdec, '15', 0)

        # 模拟用户行为数据
        setattr(self.cdec, '7', random.randint(0, 10000))  # 鼠标移动次数
        setattr(self.cdec, '8', random.randint(0, 10000))  # 鼠标点击次数
        setattr(self.cdec, '9', random.randint(0, 10000))  # 鼠标滚轮次数
        setattr(self.cdec, '10', random.randint(0, 10000)) # 键盘按键次数
        setattr(self.cdec, '11', random.randint(0, 1920)) # 鼠标X坐标
        setattr(self.cdec, '12', random.randint(0, 1080)) # 鼠标Y坐标

        # 转换为字节数组并编码
        buffer = self.cdec.to_buffer()
        return self.encoder.encode(buffer)


@lru_cache(maxsize=1)
def get_token_generator(user_agent=None):
    return TokenGenerator(user_agent)


def get_token(user_agent):
    '''获取token'''
    return get_token_generator(user_agent).update()


def headers(cookie=None, user_agent=None):
    return {
        'hexin-v': get_token(user_agent),
        'User-Agent': random_useragent() if user_agent is None else user_agent,
        'cookie': cookie
    }
