import gmpy2  # pip install gmpy2

n = 292927367433510948901751902057717800692038691293351366163009654796102787183601223853665784238601655926920628800436003079044921928983307813012149143680956641439800408783429996002829316421340550469318295239640149707659994033143360850517185860496309968947622345912323183329662031340775767654881876683235701491291
c = 40791470236110804733312817275921324892019927976655404478966109115157033048751614414177683787333122984170869148886461684367352872341935843163852393126653174874958667177632653833127408726094823976937236033974500273341920433616691535827765625224845089258529412235827313525710616060854484132337663369013424587861

def fermat_factors(n):
    assert n % 2 != 0
    x = gmpy2.isqrt(n)
    y2 = x**2 - n
    while not gmpy2.is_square(y2):
        print("hey")
        x += 1
        y2 = x**2 - n
    factor1 = x + gmpy2.isqrt(y2)  # a = x + y
    factor2 = x - gmpy2.isqrt(y2)  # b = x - y
    return int(factor1), int(factor2)

p, q = fermat_factors(n)

print(f"p: {p}, q: {q}")