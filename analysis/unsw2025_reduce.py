#!/usr/bin/env python3
"""Reduce the UNSW 2025 IoT flow data (Dryad 10.5061/dryad.7h44j1098) to the columns the analysis needs.

Usage (in the folder that holds DATA2025v1.tar.gz and DATA2025v2.tar.gz):
    pip install pyarrow
    python unsw2025_reduce.py DATA2025v1.tar.gz DATA2025v2.tar.gz

Output: folder 'unsw2025_parts' with .bin parts of 19 MB and manifest_unsw2025.json (join.py rebuilds the files).
Only the needed columns are kept, packet contents (C_000..C_2999) are dropped. The archives are read as streams.
"""
import sys, os, io, json, tarfile, hashlib
import pyarrow as pa, pyarrow.parquet as pq, pyarrow.compute as pc

KEEP = ['Device', 'FirstSeen', 'RemIP', 'Proto', 'DevPort', 'RemPort', 'TotalFlowSize', 'PacketCount']
TYPES = {'Device': pa.string(), 'FirstSeen': pa.float64(), 'RemIP': pa.string(), 'Proto': pa.int32(), 'DevPort': pa.int32(),
         'RemPort': pa.int32(), 'TotalFlowSize': pa.int64(), 'PacketCount': pa.int64(), 'FirstDir': pa.int8(),
         'DevBytes10': pa.int32(), 'SrcFile': pa.string()}
PART = 19_000_000
OUT = 'unsw2025_parts'


def reduce_table(t, day_file):
    names = {n.lower(): n for n in t.schema.names}
    cols = {}
    for k in KEEP:
        if k.lower() in names:
            cols[k] = t[names[k.lower()]]
    n = t.num_rows
    # direction of the first packet (1 = from the device) and bytes the device sent within the first 10 packets
    d0 = names.get('p00_d')
    if d0:
        cols['FirstDir'] = pc.cast(t[d0], pa.int8(), safe=False)
    sent = None
    for i in range(10):
        d, s = names.get(f'p{i:02d}_d'), names.get(f'p{i:02d}_ps')
        if d and s:
            x = pc.multiply(pc.cast(pc.fill_null(t[d], 0), pa.float64(), safe=False),
                            pc.cast(pc.fill_null(t[s], 0), pa.float64(), safe=False))
            sent = x if sent is None else pc.add(sent, x)
    if sent is not None:
        cols['DevBytes10'] = pc.cast(sent, pa.int32(), safe=False)
    cols['SrcFile'] = pa.array([os.path.basename(day_file)] * n, pa.string())
    out = {}
    for k, v in cols.items():                       # remove type differences between files
        want = TYPES.get(k, pa.string())
        try:
            out[k] = pc.cast(v, want, safe=False)
        except Exception:
            out[k] = pc.cast(v, pa.string())
    return pa.table(out)


def main(archives):
    os.makedirs(OUT, exist_ok=True)
    manifest = {}
    for arc in archives:
        base = os.path.basename(arc).split('.')[0]
        out_path = os.path.join(OUT, base + '_flows.parquet')
        writer = None; rows = 0; files = 0; shown = False; seen = {}
        with tarfile.open(arc, 'r|*') as tf:
            for m in tf:
                if not m.isfile():
                    continue
                ext = os.path.splitext(m.name)[1].lower() or '(uzantisiz)'
                seen[ext] = seen.get(ext, 0) + 1
                fobj = tf.extractfile(m)
                head = fobj.read(4)
                if head != b'PAR1':                 # not parquet: skip without reading the content
                    continue
                data = head + fobj.read()
                try:
                    pf = pq.ParquetFile(io.BytesIO(data))
                    allc = pf.schema_arrow.names
                    want = {k.lower() for k in KEEP} | {f'p{i:02d}_d' for i in range(10)} | {f'p{i:02d}_ps' for i in range(10)}
                    t = pf.read(columns=[c for c in allc if c.lower() in want])   # packet content columns are never read
                except Exception as e:
                    print('  skipped:', m.name, e); continue
                if not shown:
                    print(f'{arc}: first file {m.name}, {len(allc)} columns. First columns: {allc[:12]}')
                    shown = True
                    missing = [k for k in KEEP if k.lower() not in {c.lower() for c in allc}]
                    if missing:
                        print('  WARNING: expected columns missing:', missing, '| all column names (first 40):', allc[:40])
                r = reduce_table(t, m.name)
                if writer is None:
                    schema = r.schema
                    writer = pq.ParquetWriter(out_path, schema, compression='zstd', compression_level=9)
                else:
                    try:
                        r = r.select(schema.names).cast(schema)
                    except Exception as e:
                        print('  skipped (different columns):', m.name, e); continue
                writer.write_table(r)
                rows += r.num_rows; files += 1
                if files % 10 == 0:
                    print(f'  {files} files, {rows:,} flows', flush=True)
        if writer is None:
            print(f'{arc}: no parquet file found. File types in the archive: {seen}'); continue
        writer.close()
        size = os.path.getsize(out_path)
        print(f'{arc}: {files} files, {rows:,} flows, output {size / 1e6:.1f} MB')
        # split into parts of 19 MB
        h = hashlib.sha256(); parts = []
        with open(out_path, 'rb') as f:
            i = 0
            while True:
                chunk = f.read(PART)
                if not chunk:
                    break
                i += 1; h.update(chunk)
                pn = f'{base}_flows.parquet.part{i:03d}.bin'
                with open(os.path.join(OUT, pn), 'wb') as o:
                    o.write(chunk)
                parts.append({'file': pn, 'bytes': len(chunk), 'sha256': hashlib.sha256(chunk).hexdigest()})
        os.remove(out_path)
        manifest[base + '_flows.parquet'] = {'type': 'raw', 'bytes': size, 'sha256': h.hexdigest(), 'rows': rows, 'parts': parts}
    with open(os.path.join(OUT, 'manifest_unsw2025.json'), 'w') as f:
        json.dump(manifest, f, indent=1)
    print(f"Done. The files are in '{OUT}'.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1:])

