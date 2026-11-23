"""One recorded normal search request; no pagination, item activation or purchase."""
import json
import struct
from pathlib import Path


def category_search_body(template, scope):
    """Current native wrapper RVA263b3e0 + sender RVA2663c50: first 3 struct bytes."""
    if len(template)!=56 or template[:7]!=bytes.fromhex('1f380000000000'):
        raise ValueError('unverified search template')
    values=[scope[k] for k in ('job','category','sub')]
    if any(type(v) is not int or not 0<=v<=255 for v in values):
        raise ValueError('invalid category identifiers')
    body=bytearray(template);body[7:10]=bytes(values)
    return bytes(body)

def recorded_search_body(source=None):
    if source is None:
        raise ValueError('a local decoded search recording is required')
    source=Path(source)
    candidates=[]
    for line in source.read_text(encoding='utf-8').splitlines():
        r=json.loads(line)
        if r['dir']=='OUT' and r.get('peer',{}).get('port')==12102 and r['n']==57:
            packet=bytes.fromhex(r['plain_hex'])
            if packet[0]==0x1f and struct.unpack_from('<H',packet,1)[0]==56 and packet[3:7]==b'\0'*4:
                candidates.append(packet[:-1])
    if len(candidates)!=1:raise ValueError('expected exactly one verified native search request')
    return candidates[0]

def parse_results(data):
    if len(data)<19 or data[0]!=0x35:return None
    size=struct.unpack_from('<H',data,1)[0]
    subtype,count,total,page=struct.unpack_from('<IIII',data,3)
    if subtype!=2:return None
    compact=19+count*187
    padded=(len(data)==19+11*187 and not any(data[compact:]))
    if size!=len(data) or count>11 or (len(data)!=compact and not padded):
        raise ValueError('search response does not match verified native layout')
    items=[]
    for i in range(count):
        raw=data[19+i*187:19+(i+1)*187]
        text=lambda off:raw[off:off+25].split(b'\0',1)[0].decode('cp1254','replace')
        u32=lambda off:struct.unpack_from('<I',raw,off)[0]
        attrs=[]
        for j in range(7):
            kind,value=struct.unpack_from('<Hh',raw,0x63+j*5)
            if kind and value:attrs.append({'type':kind,'value':value})
        items.append({'name':text(0x15),'seller':text(0x2e),'vnum':u32(0x11),
                      'count':u32(13),'yang':u32(9),'won':u32(0x8b),
                      'sockets':[u32(0x47+j*4) for j in range(7)],'attrs':attrs,
                      'seller_vid':u32(1),'change_look_vnum':u32(0x8f),
                      'set_value':u32(0xb3),'sungma_score':u32(0xb7),
                      'yin_yang_value':u32(0x86),'yin_yang_type':raw[0x8a],
                      'refine_element_raw':raw[0x93:0x9b].hex(),
                      'extra_bonuses':[{'type':struct.unpack_from('<H',raw,0x9b+j*6)[0],
                                        'value':u32(0x9d+j*6)} for j in range(4)]})
    return {'page':page,'count':count,'total':total,'items':items}
