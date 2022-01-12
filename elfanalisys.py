# TODO: add more verbose output while executing this description

class envBase:
    '''
    base class for exploring libs & funcs
    '''

    def __init__(self, elf, out):
        '''
        elf - name of file to be explored
        out - name of output file
        return: no
        '''
        self.elf = elf
        self.out = out

    def printlines(self, s):
        '''
        formatted output to file
        s - string to be printed
        return: no
        '''
        f = open(self.out, 'a')
        from re import split
        s = split(r'\n', s)
        k = -1
        for l in s[:-1]:
            if k != s.index(l) + 1:
                f.write(str(s.index(l) + 1) + ': (' + self.elf + ':' + l + '\n')
            k = s.index(l) + 1
        f.write('\n-------------------------------------------------\n')
        f.close()

    def isElf(self):
        '''
        check if the self.elf is really an elf executable
        return: true/false
        '''
        from subprocess import Popen, PIPE
        from re import findall
        try:
            p = Popen(['file', self.elf], stdout=PIPE)
            line = p.stdout.readline()
            line = line.decode(encoding='utf-8')
            if findall(r'ELF', line) and (findall(r'executable', line) or findall(r'shared object', line)):
                return 1
            else:
                return 0
        except Exception as err:
            pass


class envFuncs(envBase):
    '''
    class for exploring funcs
    '''

    def __init__(self, elf, out, pl):
        '''
        elf, out - inherited from envBase
        binds - list of bindings between imported libs and funcs
        return: no
        '''
        super().__init__(elf, out)
        self.binds = []
        self.prevLine = pl

    def sort(self, s, b):
        '''
        sorts and formats strings
        s - string
        b - string contains exported/imported functions (true/false)
        return: formatted s
        '''
        s.sort(key = lambda x: x[0])
        sn = ''
        for l in s:
            if b:
                sn += ' export)'
            else:
                sn += ' import)'
            sn += '\tfunc: ' + l[0] + '\n'
        return sn

    def getBinds(self):
        '''
        makes bindings between imported functions and libraries
        return: no
        '''
        from subprocess import PIPE, Popen, STDOUT
        try:
            p = Popen(['bash','-c', 'LD_DEBUG=bindings ldd -r ' + self.elf], stdout=PIPE, stderr=STDOUT)
            while 1==1:
                line = p.stdout.readline()
                line = line.decode(encoding='utf-8')
                if line != '':
                    self.binds.append(line)
                else:
                    break
        except Exception:
            pass

    def evaluate(self):
        '''
        evaluates exported and imported functions (not all the imported symbols)
        return: no
        '''
        if self.isElf() == 0:
            return 0
        import sys
        tmpl = '\ranalyzing func import in file: '
        if self.prevLine:
            sys.stdout.write('\r' + ' ' * len(tmpl + self.prevLine))
            sys.stdout.flush()

        str = tmpl + self.elf
        sys.stdout.write(str)
        sys.stdout.flush()
        self.getBinds()
        from subprocess import Popen, PIPE, DEVNULL
        from re import findall, split
        try:
            imp = []
            exp = []
            p = Popen(['readelf', '-W', '--syms', self.elf], stdout=PIPE, stderr=DEVNULL)
            while True:
                line = p.stdout.readline()
                line = line.decode(encoding='utf-8')
                if line != '':
                    if findall(r'I*FUNC    GLOBAL DEFAULT  UND', line):
                        cols = split(r'UND', line)
                        func = cols[-1][:-1].replace('@@', '@')
                        if findall(r'\s*\(\d+\)', func):
                            t = func
                            func = split(r'\s*\(\d+\)', func)[0]
                            # print('splitted ' + func + ' | ' + t)
                        ffunc = split(r'@', func)[0][1:]
                        lib = '___'
                        for l in self.binds:
                            if findall(r"`" + ffunc + r"'", l):
                                lib = findall(r'to [^\[]+', l)[0][3:]
                                break
                        imp.append([func + ' lib: ' + lib])
                    if findall(r'I*FUNC    GLOBAL DEFAULT \s*[\[\d]+', line):
                        cols = split(r' +', line)
                        func = cols[-1][:-1].replace('@@', '@')
                        exp.append([func])
                else:
                    break
            if imp != []:
                imp = self.sort(imp, 0)
                self.printlines(imp)
            if exp != []:
                exp = self.sort(exp, 1)
                self.printlines(exp)

        except Exception as err:
            print('Exception "' + str(err) + '" in envFuncs class, evaluate method')
        return 1


class envLibs(envBase):
    '''
    class for exploring libs
    '''

    def __init__(self, elf, out, pl):
        '''
        elf, out - inherited from envBase
        return: no
        '''
        super().__init__(elf, out)
        self.prevLine = pl

    def sort(self, s):

        '''
        sorts and formats strings
        s - string
        return: formatted s
        '''
        s.sort(key = lambda x: x[0])
        sn = ''
        for l in s:
            sn += ' lib import)\t: ' + l[1:-1] + '\n'
        return sn

    def evaluate(self):
        '''
        evaluates imported libs
        return: no
        '''
        if self.isElf() == 0:
            return 0
        import sys
        tmpl = '\ranalyzing lib import in file: '
        if self.prevLine:
            sys.stdout.write('\r' + ' ' * len(tmpl + self.prevLine))
            sys.stdout.flush()

        str = tmpl + self.elf
        sys.stdout.write(str)
        sys.stdout.flush()
        # ----------------
        from subprocess import Popen, PIPE
        from re import findall
        try:
            libs = []
            p = Popen(['readelf', '-W', '-d', self.elf], stdout=PIPE)
            while True:
                line = p.stdout.readline()
                line = line.decode(encoding='utf-8')
                if line != '':
                    if findall(r'\(NEEDED\)\s+Shared library', line):
                        s = 1
                        try:
                            s = findall(r'\[[\w\._-]+\]', line)[0]
                            libs.append(s)
                        except Exception as err:
                            pass
                else:
                    break
            if libs != []:
                libs = self.sort(libs)
                self.printlines(libs)

        except Exception as err:
            print('Exception "' + str(err) + '" in envLibs class, evaluate method')
        return 1


class reInstance:
    '''
    class for applying regular expressions
    '''

    def __init__(self, out):
        '''
        out - name of output file
        return: no
        '''
        self.out = out

    def regexps(self, re):
        '''
        applying regexp to file with functions
        return: no
        '''
        d, f = getNames(self.out)
        # ---------------
        from subprocess import Popen, PIPE
        p = Popen(['grep', re, d + 'func_' + f], stdout=PIPE)
        lines = []
        try:
            while True:
                    line = p.stdout.readline()
                    line = line.decode(encoding='utf-8')
                    if line != '':
                        lines.append(line)
                    else:
                        break
            lines.sort(key = lambda x: x[0])
            f = open(d + 're_' + f, 'w')
            for l in lines:
                f.write(l)
            f.close()
        except Exception as err:
            print('Exception "' + str(err) + '" in reInstance class, regexps method')


def getNames(s):
    # split directory and file name
    from re import split, sub
    p = split(r'\/', s)
    f = p[-1]
    d = sub(f, r'', s)
    return d, f


class dirWalker:
    '''
    class for directory walking
    '''

    def __init__(self, out, b):
        '''
        self.out - output file
        self.libsnotfuncs - enumerate parameter
            0 - list external libs
            1 - list functions
        '''
        self.out = out
        self.libsnotfuncs = b
        self.prevLine = ''

    def enumObjects(self, d):
        '''
        enumerates objects in current directory
        d - current directory
        return: no
        '''
        from os import listdir
        from os.path import isdir, join
        onlydirs = [f for f in listdir(d) if isdir(join(d, f))]
        for dir in onlydirs:
            self.getPaths(join(d, dir))

    def getPaths(self, d):
        '''
        if there are any files in current dir, tries to explore it with envLibs, envFuncs
        if there are any dirs in current dir, enters there with enumObjects
        d - current directory
        return: no
        '''
        self.enumObjects(d)
        from os import listdir
        from os.path import isfile, join
        onlyfiles = [f for f in listdir(d) if isfile(join(d, f))]
        for file in onlyfiles:
            di, fi = getNames(self.out)
            if self.libsnotfuncs:
                el = envLibs(join(d, file), di + 'lib_' + fi, self.prevLine)
                if el.evaluate() == 1:
                    self.prevLine = join(d, file)
            else:
                ef = envFuncs(join(d, file), di + 'func_tmp.txt', self.prevLine)
                if ef.evaluate() == 1:
                    self.prevLine = join(d, file)


class defineUndefined:

    def __init__(self, l, ll, lt):
        self.log = l
        self.liblog = ll
        self.totallog = lt

    def __del__(self):
        try:

            pass
        except Exception as err:
            print('Exception "' + str(err) + '" in defineUndefined class, __del__ method')

    def defineWithLibs(self, func, ilibs):
        from re import findall
        rlibs = []
        fr = open(self.log, 'r')
        b = 0
        j = 1
        while True:
            # -----
            line = fr.readline()
            if (func not in line and b) or line == '':
                break
            if 'export' in line:
                for lib in ilibs:
                    r0 = findall(r'\b' + func + r'\b', line)
                    if (lib in line) and (len(r0) == 1):
                        rlibs.append(lib)
                        b = 1
            # -----
        fr.close()
        return rlibs

    def getImport(self, file):
        from re import findall
        fr = open(self.liblog, 'r')
        ilibs = []
        b = 0
        while True:
            # -----
            line = fr.readline()
            if (file not in line and b) or line=='':
                break
            if file in line:
                lib = findall(r':\s[^\(\s]+.so', line)[0][2:]
                ilibs.append(lib)
                b = 1
            # -----
        fr.close()
        return ilibs

    def defineThis(self):
        from re import findall
        fr = open(self.log, 'r')
        fw = open(self.totallog, 'w')
        cache = dict()
        import sys
        prevLine = ''
        # ------------------
        while True:
            # -----
            line = fr.readline()
            if line == '':
                break
            if findall(r'lib: ___', line):
                file = findall(r'\(\S+:', line)[0][1:-1]
                tmpl = '\rtrying to define import in file: '
                if prevLine:
                    sys.stdout.write('\r' + ' ' * len(tmpl + prevLine))
                    sys.stdout.flush()
                str = tmpl + file
                sys.stdout.write(str)
                sys.stdout.flush()
                prevLine = file
                ilibs = []
                if file in cache.keys():
                    ilibs = cache[file]
                else:
                    ilibs = self.getImport(file)
                    cache.update({file: ilibs})
                func = findall(r'func:  \S+', line)[0][7:]
                libs = self.defineWithLibs(func, ilibs)
                if len(libs) == 1:
                    line = line.replace('___', libs[0])
            # -----
            fw.write(line)
        # ------------------
        fw.close()
        fr.close()


if __name__ == '__main__':
    import argparse
    from subprocess import Popen
    parser = argparse.ArgumentParser(
        description='An utility for analysing imports and exports of executable Linux binaries',
        epilog='Example: python3 elfAnalisys.py -td /home/user/binaries/ -o /home/user/o.txt (explores all executable files in /home/user/binaries/ folder: creates files /home/user/func_o.txt - functions info - and /home/user/lib_o.txt - libraries info)')
    parser.add_argument('-tf', type=str, help="Elf file to be explored (can't be combined with -td)")
    parser.add_argument('-td', type=str, help="Directory to be explored (can't be combined with -tf)")
    parser.add_argument('-o', type=str, help="Output file")
    params = parser.parse_args()

    try:
        if params.tf and params.td:
            from sys import exit
            raise Exception("-tf and -td can't be set at the same time")
        d, f = '', ''
        try:
            d, f = getNames(params.o)
        except:
            pass
        if params.td:
            from os.path import isdir
            if isdir(params.td) == 0:
                raise Exception("You've set name of file for -td parameter")
            directory = params.td
            dw = dirWalker(params.o, 0)
            print('Function analisys:')
            dw.getPaths(directory)
            dw = dirWalker(params.o, 1)
            print('\nLibrary analisys:')
            dw.getPaths(directory)

        if params.tf:
            from os.path import isfile
            if isfile(params.tf) == 0:
                raise Exception("You've set name of directory for -tf parameter")
            tf = params.tf
            output = params.o
            ef = envFuncs(tf, d + 'func_tmp.txt')
            ef.evaluate()
            el = envLibs(tf, d + 'lib_' + f)
            el.evaluate()


        dU = defineUndefined(d + 'func_tmp.txt', d + 'lib_' + f, d + 'func_' + f)
        print('\nResolving undefined import functions:')
        dU.defineThis()
        p = Popen(['rm', d + 'func_tmp.txt'])

    except Exception as err:
            print('Exception: ' + str(err))
            exit(-1)
