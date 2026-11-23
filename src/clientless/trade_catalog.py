"""Own metin2-Mark sweep policy plus explicitly requested costume coverage."""
import json
from pathlib import Path

DATA=Path(__file__).with_name('protocol_data')


def build_scopes(tree):
    scopes=[]
    def add(job, category, sub, coverage=None):
        raw=tree['subtypes'][str(category)]
        name=(raw[str(job)] if category==2 else raw)[str(sub)]
        row={'job':job,'category':category,'sub':sub,
             'label':' / '.join([tree['jobs'][str(job)],tree['types'][str(category)],name])}
        if coverage:row['coverage']=coverage
        scopes.append(row)
    # User's shared sword policy: Ninja/Sura sword searches are excluded.
    for job,sub in [(0,0),(0,3),(1,1),(1,2),(3,4),(3,6),(4,5)]:add(job,2,sub)
    for job in range(5):
        for sub in [0,1]:add(job,3,sub)
        for sub in [1,2]:add(job,10,sub)
    for sub in [2,3]:add(0,3,sub)
    # Same common groups as own sweep; use native names/IDs rather than old OCR labels.
    for category,subs in [(1,range(4)),(4,range(6)),(5,range(4)),(6,range(3)),
                          (7,range(4)),(8,range(8)),(10,[0,3,4]),(11,range(2)),(12,range(8))]:
        for sub in subs:add(0,category,sub)
    # Native menu offers one weapon-appearance subtype, not seven weapon subtypes.
    # Four class queries cover the requested seven weapon families; shared swords may repeat.
    for job,coverage in [(0,['sword','two_handed']),(1,['sword','dagger','bow']),
                         (3,['bell','fan']),(4,['claw'])]:add(job,9,0,coverage)
    for job in range(5):add(job,9,2)
    # Costume body/head shared per user policy; no fabricated sex or helmet packet filter.
    for sub in [1,3,4,5]:add(0,9,sub)
    return scopes


def load_scopes():
    document=json.loads((DATA/'trade_categories.json').read_text(encoding='utf-8'))
    scopes=document['scopes']
    keys=[(s['job'],s['category'],s['sub']) for s in scopes]
    if not scopes or len(keys)!=len(set(keys)):
        raise ValueError('empty or duplicate active trade catalog')
    return scopes
