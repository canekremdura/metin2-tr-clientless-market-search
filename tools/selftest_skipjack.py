"""Run the independently supplied Crypto++/NIST SKIPJACK known answers offline."""
import re
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/ecdh-lab'))
from skipjack_port import crypt
s=(ROOT/'src/ecdh-lab/cryptopp_src/test_skipjack.txt').read_text()
cases=re.findall(r'Key:\s*([0-9a-fA-F]+)\s*\nPlaintext:\s*([0-9a-fA-F]+)\s*\nCiphertext:\s*([0-9a-fA-F]+)',s)
if not cases:raise SystemExit('No independent known-answer cases found')
for k,p,c in cases:
 key=bytes.fromhex(k);plain=bytes.fromhex(p);cipher=bytes.fromhex(c)
 assert crypt(key,plain)==cipher
 assert crypt(key,cipher,True)==plain
print('SKIPJACK: %d independent known-answer vectors passed in both directions'%len(cases))
