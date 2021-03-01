def test(A):
    if min(A) < -1000000 or min(A) > 1000000:
        raise Exception("Range out of value")
    start = min(A)+1
    while(start in A):
        start = start + 1
    print(start)

test([-1,2,3])