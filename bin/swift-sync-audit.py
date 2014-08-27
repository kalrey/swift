__author__ = 'kalrey'

import os, sys, time, datetime

def get_last_lines_n(path, n, max_blk_size = 4096):
    lines_n = []
    with open(path, 'r') as fp:
        fp.seek(0, os.SEEK_END)
        cur_pos = fp.tell()
        while cur_pos > 0 and len(lines_n) < n:
            blk_size = min(max_blk_size, cur_pos)
            fp.seek(cur_pos - blk_size, os.SEEK_SET)
            cur_pos = fp.tell()
            blk_data = fp.read(blk_size)
            lines = blk_data.split(os.linesep)
            if len(lines) > 1 and len(lines[0]) > 0:
                lines_n[0:0] = lines[1:]
                cur_pos += len(lines[0])
            else:
                lines_n[0:0] = lines
    if len(lines_n) > 0 and len(lines_n[-1]) == 0:
        del lines_n[-1]
    return lines_n[-n:]

import pkg_resources
def run_script(*argv):
    requirment = 'swift==1.9.1'
    script = 'swift-init'
    del sys.argv[1:]
    sys.argv[1:] = argv
    pkg_resources.run_script(requirment, script)



if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'argument is too few'
    path = sys.argv[1]
    interval = int(sys.argv[2])
    argv = sys.argv[3:]
    lines = get_last_lines_n(path, 1)
    if len(lines) == 0:
        modify_time = os.path.getmtime(path)
        time_span = time.time() - modify_time
    else:
        time_str = lines[0][0:19]
        last_time = datetime.datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
        last_time = time.mktime(last_time.timetuple())
        time_span = time.time() - last_time
    if time_span > interval:
        run_script(*argv)




