#!/usr/bin/env python3
"""Rebuild the original data files from the uploaded parts and verify every SHA-256.
Parts are found by content hash, so renamed, duplicated or stale copies do not matter. Parts without a recorded
hash (UNSW 2025 v1) are found by name and the joined file is checked against its recorded hash.
pcap parts: the 24-byte global header of every part but the first is dropped. zip and parquet parts: plain concatenation.
A part stored gzip-compressed (protocols.zip.part004.gz) is matched by the hash of its decompressed content.
Usage: join.py <manifest_dir> <out_dir> <dir with parts>...
  manifest_dir holds manifest.json, manifest_hvac.json, manifest_unsw2025.json and manifest_extra.json (or manifest_ek.json)"""
import sys, os, json, gzip, hashlib, re, shutil
mdir, out = sys.argv[1:3]; roots = sys.argv[3:]
os.makedirs(out, exist_ok=True)

def load(*names):
    for n in names:
        p = os.path.join(mdir, n)
        if os.path.exists(p): return json.load(open(p))
    return {}
man = {}
for n, i in load('manifest.json').items(): man[n] = i
for n, i in load('manifest_hvac.json').items(): man[n] = i
for n, i in load('manifest_unsw2025.json').items(): man[n] = i
ek = load('manifest_extra.json', 'manifest_ek.json')
for sec in ('owltron_lan', 'protocols', 'unsw2025_v1'):
    for n, i in ek.get(sec, {}).items(): man[n] = i
single = {}          # files that were uploaded whole: copied under their own name when the hash matches
for sec in ('cic_interactions_lan_birlesmis', 'cic_power_recon', 'homes_devices'):
    single.update({n: i for n, i in ek.get(sec, {}).items() if isinstance(i, dict)})

sizes = set()
for i in man.values():
    for p in i['parts']:
        if isinstance(p, dict): sizes.add(p['bytes'])
for i in single.values(): sizes.add(i['bytes'])
by_hash = {}; by_name = {}
def norm(s):
    """File name without the decorations that upload tools add: a leading 8-digit id, a leading
    'project-file-<uuid>-', and an 8-digit id before the extension."""
    s = re.sub(r'^project-file-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}-', '', s)
    s = re.sub(r'^[0-9a-f]{8}-', '', s)
    s = re.sub(r'-[0-9a-f]{8}(\.[A-Za-z0-9]+)$', r'\1', s)
    return re.sub(r'[^A-Za-z0-9]', '', s).lower()
for r in roots:
    for d, _, fs in os.walk(r):
        for f in fs:
            p = os.path.join(d, f); by_name.setdefault(norm(f), p)
            data = None
            if f.endswith('.gz'):
                try: data = gzip.open(p, 'rb').read()
                except Exception: data = None
            if data is None:
                if os.path.getsize(p) not in sizes: continue
                data = open(p, 'rb').read()
            if len(data) in sizes: by_hash.setdefault(hashlib.sha256(data).hexdigest(), (p, f.endswith('.gz')))
def read(hit): return gzip.open(hit[0], 'rb').read() if hit[1] else open(hit[0], 'rb').read()

ok_all = True
for name, info in man.items():
    target = os.path.join(out, name); h = hashlib.sha256(); size = 0; missing = []
    with open(target, 'wb') as o:
        for idx, p in enumerate(info['parts']):
            if isinstance(p, dict):
                hit = by_hash.get(p['sha256']); data = read(hit) if hit else None
            else:
                q = by_name.get(norm(p)); data = open(q, 'rb').read() if q else None
            if data is None: missing.append(p['file'] if isinstance(p, dict) else p); continue
            pay = data[24:] if info.get('type') == 'pcap' and idx else data
            o.write(pay); h.update(pay); size += len(pay)
    good = not missing and size == info['bytes'] and h.hexdigest() == info['sha256']
    if not good:
        os.remove(target); ok_all = False
        print('MISSING' if missing else 'FAIL   ', name, ('(%d of %d parts not found, first: %s)' % (len(missing), len(info['parts']), missing[0])) if missing else '')
    else:
        print('OK     ', name, size)
for name, info in single.items():
    if os.path.exists(os.path.join(out, name)): continue
    hit = by_hash.get(info['sha256'])
    if hit: shutil.copy(hit[0], os.path.join(out, name)); print('OK     ', name, info['bytes'])
    else: ok_all = False; print('MISSING', name)
print('all verified' if ok_all else 'some files are missing or failed verification')
