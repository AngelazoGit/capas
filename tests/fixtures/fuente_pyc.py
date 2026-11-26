def comp():
    return [i ** 2 for i in range(10) if i % 2 == 0]
def cadena(a, b, c):
    return a < b <= c
def trye(x):
    try:
        r = x()
    except (KeyError, IndexError) as e:
        print(e)
        r = None
    return r
def tryf(x):
    try:
        x()
    finally:
        print("fin")
def conj(d):
    return {k: v for k, v in d.items()}, (n for n in d)
