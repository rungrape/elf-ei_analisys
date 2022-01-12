
def argparser():
    import argparse
    parser = argparse.ArgumentParser(
        description='An utility for parsing log with functions, that is produced by elf analyser',
        epilog='Example: python3 logparse.py -f /home/user/funcs.txt -o /home/user/func_parse.txt -w /home/user/res.xml')

    parser.add_argument('-f', type=str, help="The log file is being to parse (usually its name looks like /.../func_out.txt)")
    parser.add_argument('-o', type=str, help="File with undocumented and documented functions to be written into")
    parser.add_argument('-w', type=str, help="XML file to be written into")
    return parser.parse_args()

class logparser:

    def __init__(self, f, o):
        self.inner = '/tmp/lp_log.txt'
        self.log = f
        self.out = o
        self.funcs_d = []
        self.funcs_u = []

    def sort(self):
        self.funcs_u.sort()
        self.funcs_d.sort()

    def is_documented(self, f):
        from subprocess import Popen, DEVNULL, PIPE
        try:
            p = Popen(['man', f], stdout=PIPE, stderr=DEVNULL)
            line = p.stdout.readline()
            line = line.decode(encoding='utf-8')
            f = open(self.inner, 'a')
            f.write(line + '\n')
            f.close()
            if line:
                return 1
            else:
                return 0
        except Exception as err:
                pass

    def printres(self):
        f = open(self.out, 'w')
        f.write('Undocumented functions:\n')
        f.write('--------------------------------------------\n')
        for i in self.funcs_u:
            f.write(i + '\n')
        f.write('--------------------------------------------\n')
        f.write('Documented functions:\n')
        f.write('--------------------------------------------\n')
        for i in self.funcs_d:
            f.write(i + '\n')
        f.write('--------------------------------------------\n')
        f.close()
        # return total number of functions
        return len(self.funcs_u) + len(self.funcs_d)

    def runthrough(self):
        from re import findall, split
        import sys
        f = open(self.log, 'r')
        prevLine = ''
        while True:
            line = f.readline()
            funcNlib = ''
            try:
                if line != '':
                    if findall(r'import', line):
                        funcNlib = findall(r'func:\s+\S+', line)[0][6:]
                        func = funcNlib
                        if func[0] == ' ':
                            func = func[1:]
                        if prevLine:
                            sys.stdout.write('\r' + ' ' * len(prevLine))
                            sys.stdout.flush()
                        if len(func) <= 30:
                            line = '\rExploring function: '+ func
                            sys.stdout.write(line)
                            sys.stdout.flush()
                            prevLine = line
                        if '@' in func:
                            func = split(r'@', func)[0]
                        if func not in self.funcs_d and func not in self.funcs_u:
                            b = self.is_documented(func)
                            if b:
                                if func not in self.funcs_d:
                                    self.funcs_d.append(func)
                            else:
                                if func not in self.funcs_u:
                                    self.funcs_u.append(func)
                else:
                    break
            except Exception as err:
                print('Exception ' + str(err) + ' in logparser class, runthrough method')
                print('caused by line:\n' + line + '; vars: funcNlib=' + funcNlib)
        f.close()


class formato:

    def __init__(self, i, o, l):
        # i - functions list is being read
        # o - output files
        # l - log file (source for i)
        import xml.etree.ElementTree as xml
        self.ino = i
        self.out = o
        self.log = l
        self.root = xml.Element("root")

    def evalFunc(self, f):
        fr = open(self.log, 'r')
        exp = []
        imp = []
        while True:
            line = fr.readline()
            try:
                if line == '':
                    break
                from re import findall
                impo = findall(r':\s+import\)', line)
                expo = findall(r':\s+export\)', line)
                funo = findall(r'\b' + f + r'\b', line)
                if funo:
                    if expo:
                        lib = findall(r'\(\S+:\s', line)[0][1:-2]
                        if lib not in exp:
                            exp.append(lib)
                    elif impo:
                        elf = findall(r'\(\S+:\s', line)[0][1:-2]
                        lib = findall(r'lib:\s+\S+\s+', line)[0][4:-1]
                        if elf not in imp:
                            imp.append(elf)
                        if lib!= '___' and lib not in exp:
                            exp.append(lib)
            except Exception as err:
                print('Exception "' + str(err) + '" in format class, evalFunc method')
                print('caused by line:\n' + line)
        fr.close()
        # ------------------
        if imp:
            self.createXML(f, 'import', imp)
        if exp:
            self.createXML(f, 'export', exp)

    def run(self, nfuncs):
        import sys
        from re import split
        f = open(self.ino, 'r')
        i = 1
        prevLine = ''
        while True:
            line = f.readline()
            try:
                if line == '':
                    break
                func = line[:-1]
                if 'Undocumented' not in line and '----------' not in line:
                    # -------------------------
                    self.evalFunc(func)
                    i += 1
                    progress = 100 * (float(i) / float(nfuncs))
                    progress = round(progress, 2)
                    if prevLine:
                        sys.stdout.write('\r' + ' ' * len(prevLine))
                        sys.stdout.flush()

                    t = split(r'\.', str(progress))
                    progress = t[0] + '.' + t[1][0]
                    line = '\r' + str(progress) +'% of functions have been already discovered'
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    prevLine = line

            except Exception as err:
                print('Exception "' + str(err) + '" in format class, run method')
                print('caused by line:\n' + line)
        f.close()
        # -------------
        import xml.etree.ElementTree as xml
        tree = xml.ElementTree(self.root)
        with open(self.out, "a") as fh:
            tree.write(fh, encoding='unicode')
            fh.close()

    def createXML(self, name, type, execos):
        """
        create xml-file
        """
        import xml.etree.ElementTree as xml
        item = xml.Element("item")
        self.root.append(item)
        # ------------------
        funcName = xml.SubElement(item, "funcName")
        funcName.text = name
        flowType = xml.SubElement(item, "Type")
        flowType.text = type
        execs = xml.SubElement(item, "Executables")
        execs.text = ''
        for e in execos:
            execs.text += (e + '\n')



if __name__ == '__main__':
    params = argparser()
    if params.f and params.o and params.w:
        lp = logparser(params.f, params.o)
        print('Function documentation analysis:')
        lp.runthrough()
        nfuncs = lp.printres()
        print('\nBuilding xml:')
        fo = formato(params.o, params.w, params.f)
        fo.run(nfuncs)
        print('\n')
    else:
        print('Fill all parameters')
