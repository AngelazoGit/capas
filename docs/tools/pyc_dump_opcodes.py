import dis, opcode, sys, json, importlib.util
v = "%d.%d" % sys.version_info[:2]
names = list(opcode.opname)[:256]
ice = getattr(opcode, "_inline_cache_entries", None)
if isinstance(ice, dict):
    cache = [ice.get(n, 0) for n in names]
elif isinstance(ice, list):
    cache = list(ice)[:256] + [0]*(256-len(ice))
else:
    cache = [0]*256
def L(n): return sorted(set(getattr(opcode, n, []) or getattr(dis, n, []) or []))
out = dict(v=v, magic=int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little"),
  names=names, have_arg=opcode.HAVE_ARGUMENT, cache=cache,
  hasconst=L("hasconst"), hasname=L("hasname"), haslocal=L("haslocal"), hasfree=L("hasfree"),
  hasjrel=L("hasjrel"), hasjabs=L("hasjabs"), hascompare=L("hascompare"), cmp_op=list(opcode.cmp_op))
print(json.dumps(out))
