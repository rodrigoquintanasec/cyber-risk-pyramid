"""Dev helper: count pages and real hyperlink annotations (/URI) inside a PDF (no dependencies). Usage: python scripts/pdf-links.py file.pdf"""
import re, sys, zlib
data = open(sys.argv[1], 'rb').read()
chunks = [data]
for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', data, re.S):
    try:
        chunks.append(zlib.decompress(m.group(1)))
    except Exception:
        pass
blob = b'\n'.join(chunks)
pages = len(re.findall(rb'/Type\s*/Page[^s]', blob))
uris = re.findall(rb'/URI\s*\((.*?)\)', blob)
subtype_links = len(re.findall(rb'/Subtype\s*/Link', blob))
print('pages:', pages, '| link annotations:', subtype_links, '| /URI actions:', len(uris), '| distinct:', len(set(uris)))
for u in sorted(set(uris))[:int(sys.argv[2]) if len(sys.argv) > 2 else 12]:
    print('  ', u.decode('latin1'))
bad = [u for u in set(uris) if not re.match(rb'https?://', u)]
print('non-http(s) URIs:', len(bad))
