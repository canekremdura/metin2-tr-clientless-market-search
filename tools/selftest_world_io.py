import ast
import socket
import time
import unittest
from pathlib import Path

# Yalniz IO fonksiyonunu yukle: hesap, sifre kutuphanesi veya ag baglantisi yok.
source = Path(__file__).resolve().parents[1] / 'src/clientless/world_login.py'
tree = ast.parse(source.read_text(encoding='utf-8'))
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'read_until')
ns = {'socket': socket, 'time': time}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), ns)

class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.reads = 0
    def settimeout(self, value):
        pass
    def recv(self, size):
        self.reads += 1
        return next(self.chunks, b'')

class BufferedReadTests(unittest.TestCase):
    def test_complete_initial_never_reads_socket(self):
        sock = FakeSocket([])
        self.assertEqual(ns['read_until'](sock, lambda b: len(b) >= 6,
                         time.time()+1, initial=b'abcdef'), (b'abcdef', True))
        self.assertEqual(sock.reads, 0)
    def test_fragmented_stream_preserves_extra_bytes(self):
        sock = FakeSocket([b'cd', b'efEXTRA'])
        self.assertEqual(ns['read_until'](sock, lambda b: len(b) >= 6,
                         time.time()+1, initial=b'ab'), (b'abcdefEXTRA', True))
    def test_partial_eof_is_failure(self):
        sock = FakeSocket([b'ab', b''])
        self.assertEqual(ns['read_until'](sock, lambda b: len(b) >= 37,
                         time.time()+1), (b'ab', False))
        self.assertTrue(ns['LAST_CLOSE'])

if __name__ == '__main__':
    unittest.main()
