import code

if __name__ == '__main__':
    import os
    import sys    
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='run.py [-n <process name>] [-p <process id>] [<presets>, ...]')
    parser.add_argument("-n", "--process_name", dest = "process_name", default = "", metavar = "PROCESS_NAME", help = "Set process name to start")
    parser.add_argument('-p', dest = "process_id", default = 0, type = auto_int)
    parser.add_argument('script_filenames', metavar='SCRIPT_FILENAMES', nargs='+', help = "Set script file names")
    args = parser.parse_args()

    script_text = ''
    for script_filename in args.script_filenames:
        with open(script_filename, 'r') as fd:
            script_text += fd.read() + '\n'

    code_instrumenter = code.Instrumenter(script_text)

    if args.process_name:
        code_instrumenter.run(args.process_name)
    else:
        code_instrumenter.instrument(args.process_id)

    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
