"""Verified native world entry and bounded/persistent keepalive. No movement or combat."""
import collections
import datetime
import json
import re
import random
import socket
import time
from pathlib import Path
from auth_client import build_login55,stream_from_triple,ProtocolError
from cipher_lab import derive_sessions
from native_protocol import PacketStream,SequenceState,version_body,main_character,CONTROLS


def run_native_world(log,host,port,name,login_key,client_key,outdir,expected_name=None,
                     slot=0,stay_seconds=30,version=None,open_session_fn=None,trade_search_once=False,
                     trade_search_source=None,trade_open_body=None,trade_all_pages=False,trade_scopes=None,
                     trade_request_jitter=None,trade_scope_complete_fn=None,
                     trade_search_body=None,trade_page_limit=None,stop_path=None,trade_scope_result_fn=None,
                     trade_pause_fn=None,confirm_selection=None):
    if slot!=0:raise ValueError('only slot 0 has a current native entry reference; no guessed slot packet is sent')
    if stay_seconds<0:raise ValueError('stay_seconds must be nonnegative; zero means persistent')
    if open_session_fn is None:
        from world_login import open_session as open_session_fn
    out=Path(outdir);out.mkdir(parents=True,exist_ok=True)
    state={'connected':False,'game_phase':False,'ready':False,'character':None,'expected_name':expected_name,
           'host':host,'port':port,'phases':[],'packets_in':0,'bytes_in':0,'packets_out':0,
           'server_3f_received':0,'post_version_control_sent':False,'version_sent':False,'controls_sent':False,'slot':slot,
           'ping_requests':0,'pong_sent':0,'sync_requests':0,
           'character_selected_by_native_direct_enter':False}
    counts=collections.Counter();sock=None;framer=PacketStream();seq=SequenceState();benchmark=None;pending_trade=None
    if trade_request_jitter is not None:
        if len(trade_request_jitter)!=2 or not 0<=trade_request_jitter[0]<=trade_request_jitter[1]<=10:
            raise ValueError('invalid request gap range')
    state_path=out/'world_state.json'
    def save():
        state['packet_counts']={hex(k):v for k,v in counts.items()}
        state['updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        tmp=state_path.with_suffix('.tmp');tmp.write_text(json.dumps(state,indent=2,ensure_ascii=False),encoding='utf-8');tmp.replace(state_path)
    save()
    try:
        log.step_start(11,'new game endpoint handshake, native login and direct entry')
        sock,shared,rest=open_session_fn(log,host,port,'game')
        der=derive_sessions(shared,True);dec=stream_from_triple(der['decoder']);enc=stream_from_triple(der['encoder'])
        if dec.crypt(rest[:2])!=b'\xff\x02':raise ProtocolError('game endpoint phase is not ff02')
        state.update(connected=True,encoder=der['encoder'][0],decoder=der['decoder'][0])
        def send(body,tag):
            pt=seq.append(body);ct=enc.crypt(pt);sock.sendall(ct)
            log.pkt('OUT',port,ct,tag,dec=pt);state['packets_out']+=1
        send(build_login55(name,login_key,client_key)[:-1],'game login55')
        selected=None
        def handle(packet):
            nonlocal selected,pending_trade
            data=packet.data;op=packet.opcode;counts[op]+=1;state['packets_in']+=1
            if op==0xff:
                phase=data[1];state['phases'].append(phase)
                if phase==0:raise ProtocolError('server requested close phase')
                if phase==5:
                    state['game_phase']=True
                    if not state['controls_sent']:
                        send(bytes.fromhex(CONTROLS['command_body']),'native startup command')
                        send(bytes.fromhex(CONTROLS['status_body']),'native startup status')
                        state['controls_sent']=True
            elif op==0x02:
                selected=data[7:32].split(b'\0',1)[0].decode('cp1254','replace')
                state['selection_slot0_name']=selected
            elif op in (0x4d,0x4b):
                actor=main_character(data)
                if expected_name and actor['name']!=expected_name:
                    raise ProtocolError('main character differs from requested character')
                state['character']=actor
                if not state['version_sent']:
                    send(version_body(version),'native version after main character')
                    state['version_sent']=True
                    # In the native wire recording 51 is sent AFTER version and
                    # BEFORE the receive containing 3f / GAME phase. Waiting for
                    # 3f here deadlocks world entry; its semantics are unproven.
                    send(b'\x51','native post-version control')
                    state['post_version_control_sent']=True
            elif op==0x3f:
                state['server_3f_received']=state.get('server_3f_received',0)+1
            elif op==0x03:
                state['ping_requests']+=1
                send(b'\xfe','periodic pong (native FE + sequence)')
                state['pong_sent']+=1
                log.info('PING/PONG: request=%d response=%d'%(state['ping_requests'],state['pong_sent']))
            elif op==0xfd:
                state['sync_requests']+=1
                log.info('525B sync received; reply transformation not yet verified')
            elif op==0x56 and len(data)>3 and data[3]==1 and state.get('trade_probe',{}).get('sent'):
                refs=[x.decode('ascii') for x in re.findall(rb'\[LS;\d+\]',data)]
                if refs:
                    state['trade_probe'].setdefault('information_messages',[]).append({
                        'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'refs':refs})
                    log.info('TRADE INFO: '+', '.join(refs))
                    if benchmark is not None:
                        current_page=benchmark.page if hasattr(benchmark,'page') else benchmark
                        if refs==['[LS;1208]'] and current_page.expected==1 and pending_trade is None:
                            next_body=benchmark.accept({'page':1,'count':0,'total':0,'items':[],
                                'source':'server_information_LS1208_no_matching_item'})
                            state['trade_benchmark']=benchmark.summary
                            state['trade_probe'].update(outcome='no_matching_items',response={'page':1,'count':0,'total':0,'items':[]})
                            if next_body is not None:raise ProtocolError('unexpected next page for empty category')
                        else:
                            raise ProtocolError('server information received during pagination: '+', '.join(refs))
            elif op==0x35 and state.get('trade_probe',{}).get('sent'):
                from trade_probe import parse_results
                (out/'trade_probe_response.bin').write_bytes(data)
                result=parse_results(data)
                if result is not None:
                    state['trade_probe'].update(outcome='search_results_received',response=result)
                    log.info('TRADE RESULT: page=%d count=%d total=%d'%(result['page'],result['count'],result['total']))
                    if benchmark is not None:
                        next_body=benchmark.accept(result)
                        state['trade_benchmark']=benchmark.summary
                        if next_body is not None:
                            if trade_request_jitter:
                                gap=random.uniform(*trade_request_jitter)
                                pending_trade=(time.monotonic()+gap,next_body)
                                state['request_gap_seconds_total']=state.get('request_gap_seconds_total',0)+gap
                                current_page=benchmark.page if hasattr(benchmark,'page') else benchmark
                                current_page.summary['intentional_gap_seconds']+=gap
                            else:send(next_body,'next verified trade page')
                else:state['trade_probe']['outcome']='unclassified_trade_response'
            state['ready']=bool(state['game_phase'] and state['character'] and state['controls_sent'])
        def feed(ct):
            if not ct:return
            pt=dec.crypt(ct);state['bytes_in']+=len(pt)
            # A bounded initial plaintext snapshot provides reproducible entry evidence.
            if getattr(log, 'diagnostics', True) and state['bytes_in']<=262144:
                with (out/'world_initial_pt.bin').open('ab') as f:f.write(pt)
            for packet in framer.feed(pt):handle(packet)
        feed(rest[2:]);sock.settimeout(0.5);deadline=time.monotonic()+20
        while selected is None or 3 not in state['phases']:
            if time.monotonic()>deadline:raise ProtocolError('game selection phase/list timeout')
            try:chunk=sock.recv(1048576)
            except socket.timeout:continue
            if not chunk:raise ProtocolError('game connection closed before selection')
            feed(chunk)
        if not selected:raise ProtocolError('slot 0 is empty; no character entry sent')
        if expected_name and selected!=expected_name:raise ProtocolError('slot 0 is not requested character; no entry sent')
        if confirm_selection is not None and not confirm_selection(selected):
            raise ProtocolError('character selection cancelled; no character entry sent')
        state['expected_name']=expected_name or selected
        expected_name=state['expected_name']
        send(b'\x0f','native direct-enter, slot0 reference')
        state['character_selected_by_native_direct_enter']=True
        log.step_ok('game ff02 + selection ff03 + direct-enter 0f')
        log.step_start(12,'wait for framed main character and native GAME phase')
        deadline=time.monotonic()+35
        while not state['ready']:
            if time.monotonic()>deadline:raise ProtocolError('world entry timeout before main character / GAME phase')
            try:chunk=sock.recv(1048576)
            except socket.timeout:continue
            if not chunk:raise ProtocolError('game connection closed during world entry')
            feed(chunk);save()
        state['entered_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
        log.step_ok('GAME phase 5, main character %s / VID %s'%(state['character']['name'],state['character']['vid']))
        actor=state['character']
        log.info('KONUM: %s; sunucu koordinati x=%d y=%d z=%d'%(actor['name'],actor['x'],actor['y'],actor['z']))
        if trade_search_once or trade_all_pages:
            while trade_pause_fn and trade_pause_fn():
                if stop_path is not None and Path(stop_path).exists():
                    raise ProtocolError('requested stop during nightly trade pause')
                try:chunk=sock.recv(1048576)
                except socket.timeout:continue
                if not chunk:raise ProtocolError('server closed world connection')
                feed(chunk)
            from trade_probe import recorded_search_body
            body=bytes(trade_search_body) if trade_search_body is not None else recorded_search_body(trade_search_source)
            if len(body)!=56 or body[:7]!=bytes.fromhex('1f380000000000'):
                raise ValueError('invalid verified search body')
            state['trade_probe']={'sent':False,'activation_sent':False,'outcome':'pending','category':'Warrior / Weapons / One-handed',
                                  'item_entitlement':'not independently verified'}
            if trade_open_body is not None:
                if len(trade_open_body)!=4 or trade_open_body[0]!=0x4f:
                    raise ValueError('invalid native-recorded item-use control')
                send(trade_open_body,'same-character native-recorded glass activation')
                state['trade_probe']['activation_sent']=True
                time.sleep(1)
            if trade_scopes:
                from full_scan import FullScan
                from trade_probe import category_search_body
                benchmark=FullScan(out,body,trade_scopes,category_gap=trade_request_jitter or (.05,.15),
                                   scope_complete_fn=trade_scope_complete_fn,page_limit=trade_page_limit,
                                   scope_result_fn=trade_scope_result_fn)
                body=category_search_body(body,trade_scopes[0])
                state['trade_benchmark']=benchmark.summary
            elif trade_all_pages:
                from trade_benchmark import PageBenchmark
                benchmark=PageBenchmark(out,page_limit=trade_page_limit)
                state['trade_benchmark']=benchmark.summary
            send(body,'one native-recorded trade search; current sequence')
            state['trade_probe'].update(sent=True,outcome='awaiting_response');save()
        log.step_start(13,'world connection observation (no movement or combat)')
        start=time.monotonic();last_save=start;last_report=start
        while stay_seconds==0 or time.monotonic()-start<stay_seconds:
            if (out/'STOP').exists() or (stop_path is not None and Path(stop_path).exists()):
                state['stop_reason']='requested via STOP file';break
            if trade_pause_fn and trade_pause_fn():
                sock.settimeout(.5)
            elif pending_trade is not None:
                sock.settimeout(max(.001,min(.5,pending_trade[0]-time.monotonic())))
            elif benchmark is not None and getattr(benchmark,'wait_until',None) is not None:
                sock.settimeout(max(.001,min(.5,benchmark.wait_until-time.monotonic())))
            else:sock.settimeout(.5)
            try:chunk=sock.recv(1048576)
            except socket.timeout:chunk=None
            if chunk==b'':raise ProtocolError('server closed world connection')
            if chunk:feed(chunk)
            paused=bool(trade_pause_fn and trade_pause_fn())
            state['trade_paused']=paused
            if paused and benchmark is not None:
                current_page=benchmark.page if hasattr(benchmark,'page') else benchmark
                current_page.sent_at=time.monotonic()
                save()
                time.sleep(.05)
                continue
            if benchmark is not None:
                if pending_trade is not None and time.monotonic()>=pending_trade[0]:
                    send(pending_trade[1],'next verified trade page after randomized request gap')
                    current_page=benchmark.page if hasattr(benchmark,'page') else benchmark
                    current_page.sent_at=time.monotonic()
                    pending_trade=None
                if hasattr(benchmark,'poll'):
                    next_body=benchmark.poll()
                    if next_body is not None:
                        log.info('CATEGORY: '+benchmark.summary['current_scope']['label'])
                        send(next_body,'next catalog category')
                if pending_trade is None:benchmark.check_timeout()
                if benchmark.done:
                    state['stop_reason']='planned trade pagination completed';break
            state['world_seconds']=round(time.monotonic()-start,2)
            if time.monotonic()-last_save>=1:save();last_save=time.monotonic()
            if time.monotonic()-last_report>=15:
                log.info('BAGLANTI ACIK: %.0f sn; alinan paket=%d; son kontrol=%s'%(state['world_seconds'],state['packets_in'],datetime.datetime.now().strftime('%H:%M:%S')))
                last_report=time.monotonic()
        if benchmark is not None and not benchmark.done:
            raise ProtocolError('pagination ended before the final verified page')
        state['success']=True
        if state.get('trade_probe',{}).get('outcome')=='awaiting_response':
            state['trade_probe']['outcome']='no_classified_response_in_observation_window'
        state.setdefault('stop_reason','configured observation completed')
        log.step_ok('world observed %.1fs, server 3f packets=%d'%(state.get('world_seconds',0),state['server_3f_received']))
        return state
    except BaseException as e:
        state['error']=type(e).__name__+': '+str(e);state['success']=False
        log.step_fail(state['error'])
        if isinstance(e,KeyboardInterrupt):state['stop_reason']='keyboard interrupt'
        return state
    finally:
        if sock:sock.close()
        state['connected']=False;state['unparsed_bytes']=len(framer.buffer);save()
