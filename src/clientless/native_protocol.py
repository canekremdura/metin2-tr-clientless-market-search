"""Current-build packet framing and sequence state, backed by live 2026-11-13 evidence."""
import json
import struct
from dataclasses import dataclass
from pathlib import Path

DATA=Path(__file__).resolve().parent/'protocol_data'
TABLE={r['opcode']:r for r in json.loads((DATA/'server_packets.json').read_text(encoding='utf-8'))['entries']}
CONTROLS=json.loads((DATA/'startup_controls.json').read_text(encoding='utf-8'))

class FramingError(ValueError):
    pass

@dataclass(frozen=True)
class Packet:
    opcode:int
    data:bytes

class PacketStream:
    def __init__(self):
        self.buffer=bytearray()
        self.padding_bytes=0
    def feed(self,data):
        self.buffer.extend(data)
        packets=[]
        while self.buffer:
            op=self.buffer[0]
            if op==0: # native CheckPacket explicitly consumes zero padding
                del self.buffer[0];self.padding_bytes+=1;continue
            entry=TABLE.get(op)
            if entry is None:raise FramingError('unknown server opcode 0x%02x'%op)
            if op==0x8f:
                # Live handler: 4-byte header + 45-byte record for subtype zero.
                if len(self.buffer)<4:break
                n={0:49,1:4}.get(self.buffer[1])
                if n is None:raise FramingError('unknown 0x8f subtype %d'%self.buffer[1])
            elif op==0x47:
                # Wire is 11B in all three independent native captures. The
                # native map's 13B is not the wire layout for this build.
                n=11
            elif op==0x1e or entry['kind']!=0:
                width=4 if entry['kind']==2 and op!=0x1e else 2
                if len(self.buffer)<1+width:break
                n=int.from_bytes(self.buffer[1:1+width],'little')
                if n<entry['size'] or n>1048576:
                    raise FramingError('invalid size %d for opcode 0x%02x'%(n,op))
            else:n=entry['size']
            if len(self.buffer)<n:break
            packets.append(Packet(op,bytes(self.buffer[:n])));del self.buffer[:n]
        return packets

class SequenceState:
    def __init__(self,index=0):
        self.table=(DATA/'sequence_table.bin').read_bytes()
        if len(self.table)!=32768:raise ValueError('invalid native sequence table')
        self.index=index
    def append(self,body):
        if not body:raise ValueError('empty packet body')
        value=self.table[self.index%len(self.table)];self.index+=1
        return bytes(body)+bytes([value])

def version_body(version=None):
    raw=(version or CONTROLS['version']).encode('ascii')
    if not 1<=len(raw)<=16 or b'\0' in raw:raise ValueError('version must be 1..16 ASCII bytes without NUL')
    return b'\xfa'+raw.ljust(16,b'\0')

def main_character(packet):
    if len(packet)==75 and packet[0]==0x4b:
        # Native entry: name[25], music[25], volume float,
        # followed by the same position / empire / skill fields.
        actor=main_character(b'\x4d'+packet[1:32]+packet[61:])
        actor['music']=packet[32:57].split(b'\0',1)[0].decode('ascii','replace')
        actor['music_volume']=struct.unpack_from('<f',packet,57)[0]
        return actor
    if len(packet)!=46 or packet[0]!=0x4d:raise ValueError('expected native 4d/46B or 4b/75B main-character packet')
    _,vid,race,name,x,y,z,empire,skill_group=struct.unpack('<BIH25siiiBB',packet)
    return {'vid':vid,'race':race,'name':name.split(b'\0',1)[0].decode('cp1254','replace'),
            'x':x,'y':y,'z':z,'empire':empire,'skill_group':skill_group}
