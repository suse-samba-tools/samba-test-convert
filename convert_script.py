#!/usr/bin/python3
import re, sys, argparse

def convert_data(f, test_suite_name):
    data = ''
    fnums = []
    data = f.read()
    if 'smb_raw_exit' in data:
        sys.stderr.write('WARNING: smb_raw_exit() was deprecated in lanman1, and has no smb2 equivalent.\n')
    if 'smb_raw_pathinfo' in data:
        sys.stderr.write('WARNING: smb_raw_pathinfo() has no equivalent in smb2, try using smb2_getinfo_fs with a smb2_handle instead\n')
    cli = re.findall('struct smbcli_state \*([^,;\)\(]+)[,;\)]', data)
    data = re.sub('struct smbcli_state', 'struct smb2_tree', data)
    data = re.sub('\s*struct smbcli_session_options\s*.*;', r'', data)
    data = re.sub('struct smbcli_session', 'struct smb2_session', data)
    data = re.sub('\s*lpcfg_smbcli_session_options\(\w+->lp_ctx, &\w+\);', r'', data)
    torture = re.findall('struct torture_context \*([^\);,]+)', data)
    if len(torture) == 0:
        torture = re.findall('torture_setting_string\(([^,]+),', data)
    if len(torture) > 0:
        data = re.sub('torture_setting_string\(%s, "host", NULL\)' % torture[0], '@TEMPHOST@', data)
    data = re.sub('smbcli_full_connection\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*', r'smb2_connect(\1, \3, \4, \5, \9, \8, \2, \10, \11, \7, ', data)
    if len(torture) > 0:
        data = re.sub('@TEMPHOST@', 'torture_setting_string(%s, "host", NULL)' % torture[0], data)
    data = data.replace('smbcli_tdis', 'smb2_tdis')
    data = re.sub('smb1cli_session_set_id\(([^,]+),\s*([^\)]+)\)', r'smb2cli_session_set_id_and_flags(\1, \2, smb2cli_session_get_flags(\1))', data)
    data = data.replace('smb1cli_session_current_id', 'smb2cli_session_current_id')

    # Session Setup conversion
    setup = re.findall('struct smb_composite_sesssetup ([^,;]+)', data)
    for s in setup:
        # Erase the smb_composite_sesssetup
        data = re.sub('\s*struct smb_composite_sesssetup %s.*' % s, '', data)

        # Erase the session setup initialization
        data = re.sub('\s*%s.in.sesskey\s*=\s*.*' % s, '', data)
        data = re.sub('\s*%s.in.capabilities\s*=\s*.*' % s, '', data)
        data = re.sub('\s*%s.in.workgroup\s*=\s*.*' % s, '', data)

        # Stash then erase the creds
        creds = re.findall('%s.in.credentials\s*=\s*(.*)\;' % s, data)
        if len(creds) == 0:
            creds = 'popt_get_cmdline_credentials()'
        else:
            creds = creds[0]
        data = re.sub('\s*%s.in.credentials\s*=\s*.*' % s, '', data)

        # Check then erase gensec_settings
        gensec_settings = re.findall('%s.in.gensec_settings\s*=\s*(.*)\;' % s, data)
        for i in range(0, len(gensec_settings)):
            if 'lpcfg_gensec_settings' not in gensec_settings[i]:
                rep = re.findall('\s+%s\s*=\s*(.*)\;' % gensec_settings[i], data)
                if len(rep) == 1 and 'lpcfg_gensec_settings' in rep[0]:
                    continue
                raise Exception('The credentials setting needs to be set in smb2_session_init')
        data = re.sub('\s*%s.in.gensec_settings\s*=\s*.*' % s, '', data)

        # Replace the smb_composite_sesssetup
        data = re.sub('smb_composite_sesssetup\(([^,]+),\s*([^\)]+)\)', r'smb2_session_setup_spnego(\1, %s, 0)' % creds, data)

    if len(torture) > 0:
        data = re.sub('smbcli_session_init\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'smb2_session_init(\1, lpcfg_gensec_settings(%s, %s->lp_ctx), \2)' % (torture[0], torture[0]), data)

    data = re.sub('struct\s+smbcli_request', 'struct smb2_request', data)

    lock = re.findall('union\s+smb_lock\s+([^,;]+)', data)
    for l in lock:
        # Replace the definition
        data = re.sub('union\s+smb_lock', 'struct smb2_lock', data)

        # Remove the lock level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % l, '', data)

        # Replace the lockx's with smb2_lock's
        res = []
        res.append(re.compile('%s\.lockx\.in\.lock_cnt\s*=\s*(\d+)\s*;\s*%s\.lockx\.in\.ulock_cnt\s*=\s*0\s*;(.+?(?=smb_raw_lock))smb_raw_lock\(([^,]+),\s*([^\)]+)\)' % (l, l), re.DOTALL))
        res.append(re.compile('%s\.lockx\.in\.ulock_cnt\s*=\s*0\s*;\s*%s\.lockx\.in\.lock_cnt\s*=\s*(\d+)\s*;(.+?(?=smb_raw_lock))smb_raw_lock\(([^,]+),\s*([^\)]+)\)' % (l, l), re.DOTALL))
        for r in res:
            data = re.sub(r, r'%s.in.lock_count = \1;\2smb2_lock(\3, \4)' % l, data)

        # Replace the lockx's with smb2_lock's + SMB2_LOCK_FLAG_UNLOCK flag
        r = re.compile('%s\.lockx\.in\.locks\s*=\s*[\*&]?([^;]+)' % l)
        rlocks = re.findall(r, data)
        if len(rlocks) != 1 and not all(e == rlocks[0] for e in rlocks):
            raise Exception('Failed to find the lock for %s' % l)
        res = []
        res.append(re.compile('%s\.lockx\.in\.lock_cnt\s*=\s*0\s*;\s*%s\.lockx\.in\.ulock_cnt\s*=\s*(\d+)\s*;(.+?(?=\n\s+\w+\s*=\s*smb_raw_lock))\n(\s+)(\w+)\s*=\s*smb_raw_lock\(([^,]+),\s*([^\)]+)\)' % (l, l), re.DOTALL))
        res.append(re.compile('%s\.lockx\.in\.ulock_cnt\s*=\s*(\d+)\s*;\s*%s\.lockx\.in\.lock_cnt\s*=\s*0\s*;(.+?(?=\n\s+\w+\s*=\s*smb_raw_lock))\n(\s+)(\w+)\s*=\s*smb_raw_lock\(([^,]+),\s*([^\)]+)\)' % (l, l), re.DOTALL))
        for r in res:
            data = re.sub(r, r'%s.flags = SMB2_LOCK_FLAG_UNLOCK;\n\3%s.in.lock_count = \1;\2\n\3\4 = smb2_lock(\5, \6);\n\3%s.flags = 0' % (rlocks[0], l, rlocks[0]), data)

        # Erase timeout/mode
        data = re.sub('\n.*%s\.lockx\.in\.timeout\s*=\s*\d+\s*;' % l, '', data)
        data = re.sub('\n.*%s\.lockx\.in\.mode\s*=\s*\d+\s*;' % l, '', data)

        # Replace the lock inputs/outputs
        data = re.sub('%s\.lockx\.in' % l, '%s.in' % l, data)
        data = re.sub('%s\.lockx\.out' % l, '%s.out' % l, data)

    lock_elements = re.findall('struct\s+smb_lock_entry\s+\*?([^\[;]+)', data)
    for le in lock_elements:
        # Rewrite count to length
        data = re.sub('(\n.*%s\[\d+\])\.count\s*=\s*(\d+)\s*;' % le, r'\1.length = \2;', data)

        # Erase the pid
        data = re.sub('\n.*%s\[\d+\]\.pid\s*=\s*\d+\s*;' % le, '', data)

    data = data.replace('smb_lock_entry', 'smb2_lock_element')
    data = data.replace('smb_raw_lock', 'smb2_lock')
    data = data.replace('smbcli_unlock', 'smb2_util_unlock')
    data = re.sub('smbcli_lock\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'smb2_util_lock(\1, \2, \3, \4, \6==WRITE_LOCK)', data) # Dumb hack, compare the lock type to WRITE_LOCK to see if we're requesting an exclusive lock

    if len(torture) > 0:
        data = re.sub('torture_setup_dir\(([^,]+),\s*([^\)]+)\)', r'smb2_util_setup_dir(%s, \1, \2)' % torture[0], data)

    data = data.replace('smbcli_deltree', 'smb2_deltree')
    data = data.replace('smbcli_close', 'smb2_util_close')

    sopen = re.findall('union\s+smb_open\s+([^,;]+)', data)
    for o in sopen:
        # Replace the definition
        data = re.sub('union\s+smb_open', 'struct smb2_create', data)
        data = re.sub('struct\s+smb2_create\s+(\w+);', r'struct smb2_create \1 = {0};', data)

        # Remove the open level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % o, '', data)

        # Remove deprecated option root_fid
        data = re.sub('\n.*%s\.ntcreatex\.in\.root_fid\.fnum\s*=\s*\w+;' % o, '', data)

        # Handle ntcreatex specific conversions
        data = re.sub('%s\.ntcreatex\.in\.flags' % o, '%s.in.create_flags' % o, data)
        data = re.sub('%s\.ntcreatex\.in\.access_mask' % o, '%s.in.desired_access' % o, data)
        data = re.sub('%s\.ntcreatex\.in\.file_attr' % o, '%s.in.file_attributes' % o, data)
        data = re.sub('%s\.ntcreatex\.in\.open_disposition' % o, '%s.in.create_disposition' % o, data)
        data = re.sub('%s\.ntcreatex\.in\.impersonation' % o, '%s.in.impersonation_level' % o, data)

        # Replace the open inputs/outputs
        data = re.sub('%s\.ntcreatex\.in' % o, '%s.in' % o, data)
        data = re.sub('%s\.ntcreatex\.out' % o, '%s.out' % o, data)

    data = re.sub('smb_raw_open\s*\(', 'smb2_create(', data)
    data = re.sub('smb_raw_open_send\s*\(', 'smb2_create_send(', data)
    data = re.sub('smb_raw_open_recv\s*\(', 'smb2_create_recv(', data)
    data = re.sub('smb_raw_ulogoff\s*\(', 'smb2_logoff(', data)
    data = re.sub('smbcli_unlink\s*\(', 'smb2_util_unlink(', data)

    echo = re.findall('struct\s+smb_echo\s+([^,;]+)', data)
    for e in echo:
        # Erase the echo struct
        data = re.sub('\s*struct\s+smb_echo %s.*' % e, '', data)

        # Replace the smb_raw_echo call with an smb2_keepalive
        data = re.sub('smb_raw_echo\s*\(([^,]+),\s*([^\)]+)\)', r'smb2_keepalive(\1)', data)

        # Erase the echo struct initializations
        data = re.sub('\n.*%s[^;]*;' % e, '', data)

    # Replace smbcli_nt_create_full with smb2_create
    data = re.sub('(\n\s*)(.*)smbcli_nt_create_full\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\);', r'\1struct smb2_create io;\n\1io.in.fname = \4;\1io.in.create_flags = \5;\1io.in.desired_access = \6;\1io.in.file_attributes = \7;\1io.in.share_access = \8;\1io.in.create_disposition = \9;\1io.in.create_options = \10;\1io.in.security_flags = \11;\1status = smb2_create(\3, \3, &io);\n\1\2io.out.file.handle;', data)

    def conditional_open_replace(m):
        ans = ''
        ans += '%sstruct smb2_create cio = {0};' % m.group(1)
        ans += '%scio.in.fname = %s;' % (m.group(1), m.group(4))
        o = m.group(5).split('|')
        access_mask = []
        create_disposition = 'NTCREATEX_DISP_CREATE'
        for opt in o:
            if opt.strip() == 'O_RDWR':
                access_mask.append('SEC_FILE_READ_DATA')
                access_mask.append('SEC_FILE_WRITE_DATA')
            elif opt.strip() == 'O_CREAT':
                if 'O_EXCL' not in o:
                    create_disposition = 'NTCREATEX_DISP_OPEN_IF'
                else:
                    create_disposition = 'NTCREATEX_DISP_CREATE'
            elif opt.strip() == 'O_EXCL' and 'O_CREAT' in o:
                if 'O_CREAT' in o:
                    create_disposition = 'NTCREATEX_DISP_CREATE'
                else:
                    raise Exception('If O_EXCL is set and O_CREAT is not set, the result is undefined.')
            else:
                raise Exception('Unknown option "%s"' % opt)
        if len(access_mask) > 0:
            ans += '%scio.in.desired_access = %s;' % (m.group(1), ' | '.join(access_mask))
        ans += '%scio.in.file_attributes = FILE_ATTRIBUTE_NORMAL;' % m.group(1)
        share_access = None
        if m.group(6).strip() == 'DENY_NONE':
            share_access = 'NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE'
        elif m.group(6).strip() == 'DENY_ALL':
            share_access = '0'
        elif m.group(6).strip() == 'DENY_WRITE':
            share_access = 'NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_DELETE'
        elif m.group(6).strip() == 'DENY_READ':
            share_access = 'NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE'
        elif m.group(6).strip() == '0':
            share_access = None
        else:
            raise Exception('Invalid share access "%s"' % m.group(6).strip())
        if share_access:
            ans += '%scio.in.share_access = %s;' % (m.group(1), share_access)
        ans += '%scio.in.create_disposition = %s;' % (m.group(1), create_disposition)
        ans += '%sstatus = smb2_create(%s, %s, &cio);' % (m.group(1), m.group(3), m.group(3))
        ans += '%s%scio.out.file.handle' % (m.group(1), m.group(2))
        return ans
    # Replace smbcli_open with smb2_create
    data = re.sub('(\n[ \t\f\v]*)(.*?(?=smbcli_open))smbcli_open\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', conditional_open_replace, data)

    data = data.replace('smbcli_tree', 'smb2_tree')

    close = re.findall('union\s+smb_close\s+([^,;\)]+)', data)
    for c in close:
        # Erase the close union
        data = re.sub('\s*union\s+smb_close\s+%s.*' % c, '', data)

        # Erase the level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % c, '', data)

        # Replace the fnum and smb_raw_close lines with a single smb2_util_close
        data = re.sub('%s\.close\.in\.file\.fnum\s*=\s*([^;]+);(\s*%s\.close\.[^;]+;)*\s+(.*)smb_raw_close\(([^,]+),\s*([^\)]+)\)' % (c, c), r'\3smb2_util_close(\4, \1)', data)

        # Erase any remaining close options
        data = re.sub('\n.*%s\.\w+\.in\.\w+\s*=\s*\w+;' % c, '', data)
    fnums.extend(re.findall('smb2_util_close\([^,]+,\s*([^\)\(]+)\)', data))

    tcons = re.findall('union\s+smb_tcon\s+([^,;\)]+)', data)
    for tcon in tcons:
        # Erase the tcon union
        data = re.sub('\s*union\s+smb_tcon\s+%s.*' % tcon, '', data)

        # Erase the tcon level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % tcon, '', data)

        # Replace tree init/tcon with torture_smb2_tree_connect
        data = re.sub('(\s*)([^\s]*)\s*=\s*smb2_tree_init\(([^,]+),\s*([^,]+),\s*([^\)]+)\);(\s*%s\.\w+\.in\.[^;]+;)*\s+([^\s]*)\s*=\s*smb_raw_tcon\(([^,]+),\s*([^,]+),\s*([^\)]+)\)' % tcon, r'\1\7 = torture_smb2_tree_connect(\4, \3, \4, &\2)', data)

    writes = re.findall('union\s+smb_write\s+([^,;\)]+)', data)
    for w in writes:
        # Catch the file handles
        fnums.extend(re.findall('%s\.\w+\.in\.file\.fnum\s*=\s*([^;]+)', data))

        # Rewrite the smb_write to smb2_write
        data = re.sub('union\s+smb_write\s+%s' % w, 'struct smb2_write %s' % w, data)

        # Rewrite the write options
        data = re.sub('%s\.\w+\.in\.file\.fnum' % w, '%s.in.file.handle' % w, data)
        data = re.sub('%s\.\w+\.in\.data' % w, '%s.in.data' % w, data)
        data = re.sub('%s\.\w+\.in\.offset' % w, '%s.in.offset' % w, data)

        # Erase the smb_write level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % w, '', data)

        # Erase the deprecated options
        data = re.sub('\n.*%s\.\w+\.in\.\w+\s*=\s*\w+;' % w, '', data)

        # Rewrite the smb_raw_write to a smb2_write
        data = data.replace('smb_raw_write', 'smb2_write')

    fnums.extend(re.findall('in.file.fnum\s+=\s+([^;]+);', data))
    for fnum in reversed(sorted(fnums)):
        if '.' in fnum:
            continue

        # Try to change the fnum int to a handle
        data = re.sub('int\s+%s(\s*=\s*[\-\d]+)*\s*;' % fnum, 'struct smb2_handle %s = {{0}};' % fnum, data)

        # Change function arg fnums
        data = re.sub('int\s+%s\s*,' % fnum, 'struct smb2_handle %s,' % fnum, data)

        # Search for multiple int defs with our handle in it
        defs = re.findall('(int\s+[^;]*[^\w]%s[^;]*;)' % fnum, data)
        for d in defs:
            # Make sure we didn't match on a name that's a sub-string
            if len(re.findall(r'[^\w]%s[,;]' % fnum, d)) != 1:
                break
            n = re.sub('(\s+%s,?)' % fnum, '', d).replace(',;', ';')
            data = re.sub('\n(\s+)%s' % d, r'\n\1%s\n\1struct smb2_handle %s = {{0}};' % (n, fnum), data)

    # Rewrite out fnums to handles
    data = data.replace('out.file.fnum', 'out.file.handle')
    data = data.replace('in.file.fnum', 'in.file.handle')

    data = data.replace('torture_suite_add_1smb_test', 'torture_suite_add_1smb2_test')

    data = re.sub('\n(\s+)(\w+)\s*=\s*create_complex_file\(([^,]+),\s*([^,]+),\s*([^\)]+)\);', r'\n\1status = smb2_create_complex_file(\4, \3, \5, &\2);', data)

    data = data.replace('smb_raw_fileinfo', 'smb2_getinfo_file')

    data = re.sub('(\w+->session->transport)->negotiate.capabilities', r'smb2cli_conn_server_capabilities(\1->conn)', data)
    data = re.sub('smbcli_errstr\([\w\-\>]+\)', r'nt_errstr(status)', data)

    data = re.sub('(\n[ \t\r\f\v]*)(\w+)\s*=\s*smbcli_request_simple_recv\(([^\)]+)\);', r'\1smb2_request_receive(\3);\1\2 = smb2_request_destroy(\3);', data)

    # Rewrite raw includes
    data = data.replace('#include "libcli/raw/libcliraw.h"', '#include "libcli/smb2/smb2.h"')
    data = data.replace('#include "libcli/raw/raw_proto.h"', '#include "libcli/smb2/smb2_calls.h"')
    data = data.replace('#include "torture/raw/proto.h"', '#include "torture/smb2/proto.h"')
    data = data.replace('#include "torture/basic/proto.h"', '#include "torture/smb2/proto.h"')

    data = data.replace('smbcli_mkdir', 'smb2_util_mkdir')

    firsts = re.findall('union\s+smb_search_first\s+(\w+);', data)
    nexts = re.findall('union\s+smb_search_next\s+(\w+);', data)
    for f in firsts:
        # Erase the level
        data = re.sub('\n.*%s\.t2ffirst\.level\s*=\s*\w+;' % f, '', data)

        data = re.sub('%s\.t2ffirst\.in' % f, '%s.in' % f, data)
        data = re.sub('%s\.t2ffirst\.out' % f, '%s.out' % f, data)

    for n in nexts:
        # Erase the level
        data = re.sub('\n.*%s\.t2fnext\.level\s*=\s*\w+;' % n, '', data)

        data = re.sub('%s\.t2fnext\.in' % n, '%s.in' % n, data)
        data = re.sub('%s\.t2fnext\.out' % n, '%s.out' % n, data)

    data = re.sub('union\s+smb_search_first', 'struct smb2_find', data)
    data = re.sub('union\s+smb_search_next', 'struct smb2_find', data)

    data = data.replace('smb_raw_fsinfo', 'smb2_getinfo_fs')

    data = re.sub('smbcli_write\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'smb2_util_write(\1, \2, \4, \5, \6)', data)

    data = re.sub('(\n[ \t\f\v]*)(.+?(?=smbcli_read))smbcli_read\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)([^;]*)', r'\1struct smb2_read rio = {0};\1rio.in.file.handle = \4;\1rio.in.offset = \6;\1rio.in.length = \7;\1status = smb2_read(\3, %s, &rio);\1\2rio.out.data.length\8;\1\5 = rio.out.data.data' % (torture[0] if len(torture) > 0 else '\\3'), data, re.DOTALL)

    if len(torture) > 0:
        data = re.sub('torture_open_connection\(([^,]+),\s*([^\)]+)\)', r'torture_smb2_connection(%s, \1)' % torture[0], data)
    else:
        sys.write.stderr('Couldn\'t convert torture_open_connection because no torture context was found\n')

    notifys = re.findall('union\s+smb_notify\s+(\w+);', data)
    for n in notifys:
        # Erase the level
        data = re.sub('\n.*%s\.\w+\.level\s*=\s*\w+;' % n, '', data)

        data = re.sub('%s\.nttrans\.in' % n, '%s.in' % n, data)
        data = re.sub('%s\.nttrans\.out' % n, '%s.out' % n, data)
    data = re.sub('union\s+smb_notify', 'struct smb2_notify', data)

    data = data.replace('smb_raw_changenotify_send', 'smb2_notify_send')
    data = data.replace('smb_raw_changenotify_recv', 'smb2_notify_recv')

    data = data.replace('smbcli_rmdir', 'smb2_util_rmdir')

    data = re.sub('smbcli_setatr\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'smb2_util_setatr(\1, \2, \3)', data)

    data = re.sub('(\n[ \t\f\v]*)(.*?(?=smbcli_rename))smbcli_rename\(([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'\1struct smb2_handle rh = {{0}};\1union smb_setfileinfo rsinfo = {0};\1torture_smb2_testfile(\3, \4, &rh);\1rsinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;\1rsinfo.rename_information.in.file.handle = rh;\1rsinfo.rename_information.in.new_name = \5;\1\2smb2_setinfo_file(\3, &rsinfo);\1smb2_util_close(\3, rh)', data, re.DOTALL)
    data = re.sub('(\n[ \t\f\v]*)(.*?(?=smbcli_fsetatr))smbcli_fsetatr\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'\1union smb_setfileinfo sinfo = {0};\1sinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFO;\1sinfo.basic_info.in.file.handle = \4;\1sinfo.basic_info.in.attrib = \5;\1sinfo.basic_info.in.create_time = \6;\1sinfo.basic_info.in.access_time = \7;\1sinfo.basic_info.in.write_time = \8;\1sinfo.basic_info.in.change_time = \9;\1\2smb2_setinfo_file(\3, &sinfo)', data, re.DOTALL)
    data = re.sub('(\n[ \t\f\v]*)(.*?(?=smbcli_ftruncate))smbcli_ftruncate\(([^,]+),\s*([^,]+),\s*([^\)]+)\)', r'\1union smb_setfileinfo sinfo = {0};\1sinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFO;\1sinfo.end_of_file_info.in.file.handle = \4;\1sinfo.end_of_file_info.in.size = \5;\1\2smb2_setinfo_file(\3, &sinfo)', data, re.DOTALL)

    data = data.replace('smbcli_getatr', 'smb2_util_getatr')
    data = data.replace('smbcli_transport_dead', 'smb2_transport_dead')
    data = data.replace('smbcli_transport_idle_handler', 'smb2_transport_idle_handler')
    data = re.sub('struct\s+smbcli_transport', 'struct smb2_transport', data)

    data = re.sub('smb_raw_ntcancel\(([^\)]+)\)', r'tevent_req_cancel(\1->subreq)', data)

    data = data.replace('torture_suite_add_2smb_test', 'torture_suite_add_2smb2_test')
    name_match = re.compile('struct\s+torture_suite\s+\*torture_[a-zA-Z0-9]+(_[a-zA-Z0-9]+)\(TALLOC_CTX (\*\w+)\)')
    if test_suite_name:
        data = re.sub(name_match, r'struct torture_suite *torture_smb2_%s(TALLOC_CTX \2)' % test_suite_name, data)
        data = re.sub('torture_suite_create\((\w+),\s+"\w+"\)', r'torture_suite_create(\1, "%s")' % test_suite_name, data)
    else:
        data = re.sub(name_match, r'struct torture_suite *torture_smb2\1(TALLOC_CTX \2)', data)

    if 'wire_bad_flags' in data:
        header = ''
        if not 'libcli/smb/smbXcli_base.h' in data:
            header = '#include "libcli/smb/smbXcli_base.h"\n'
        # Insert the static wire_bad_smb2_flags def
        include_end = list(re.finditer('#include\s+.*\n', data))[-1].end()
        data = data[:include_end] + header + '\n/**\n  check that a wire string matches the flags specified\n  not 100% accurate, but close enough for testing\n*/\nstatic bool wire_bad_smb2_flags(struct smb_wire_string *str, int flags,\n\t\t\t\tstruct smb2_transport *transport)\n{\n\tbool server_unicode;\n\tint len;\n\tif (!str || !str->s) return true;\n\tlen = strlen(str->s);\n\tif (flags & STR_TERMINATE) len++;\n\n\tserver_unicode = smbXcli_conn_use_unicode(transport->conn);\n\tif (getenv("CLI_FORCE_ASCII") || !transport->options.unicode) {\n\t\tserver_unicode = false;\n\t}\n\n\tif ((flags & STR_UNICODE) || server_unicode) {\n\t\tlen *= 2;\n\t} else if (flags & STR_TERMINATE_ASCII) {\n\t\tlen++;\n\t}\n\tif (str->private_length != len) {\n\t\tprintf("Expected wire_length %d but got %d for \'%s\'\\n",\n\t\t       len, str->private_length, str->s);\n\t\treturn true;\n\t}\n\treturn false;\n}\n' + data[include_end:]

        # Replace the wire_bad_flags
        data = data.replace('wire_bad_flags', 'wire_bad_smb2_flags')

    if 'smb_raw_chkpath' in data:
        # Insert the static smb2_chkpath def
        include_end = list(re.finditer('#include\s+.*\n', data))[-1].end()
        data = data[:include_end] + '\nstatic NTSTATUS smb2_chkpath(struct smb2_tree *tree, union smb_chkpath *parms)\n{\n\tstruct smb2_create io = {0};\n\tNTSTATUS status;\n\n\tio.in.desired_access = SEC_RIGHTS_DIR_ALL;\n\tio.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;\n\tio.in.create_disposition = NTCREATEX_DISP_OPEN;\n\tio.in.share_access = NTCREATEX_SHARE_ACCESS_READ |\n\t\t\t     NTCREATEX_SHARE_ACCESS_WRITE |\n\t\t\t     NTCREATEX_SHARE_ACCESS_DELETE;\n\tio.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;\n\tio.in.fname = parms->chkpath.in.path;\n\n\tstatus = smb2_create(tree, tree, &io);\n\n\tif (NT_STATUS_IS_OK(status)) {\n\t\tsmb2_util_close(tree, io.out.file.handle);\n\t}\n\t\n\treturn status;\n}\n' + data[include_end:]

        # Replace the smb_raw_chkpath
        data = data.replace('smb_raw_chkpath', 'smb2_chkpath')

    # Strip white space at end of the line
    data = re.sub('[ \t\r\f\v]+\n', r'\n', data)

    data = data.replace('smb_tree_disconnect', 'smb2_tdis')

    for fnum in reversed(sorted(fnums)):
        if '.' in fnum:
            continue

        # Change the fnum checks to status checks
        data = re.sub('\(\s*%s\s*==\s*-1\s*\)' % fnum, r'(NT_STATUS_IS_ERR(status))', data)
        data = re.sub('\(\s*%s\s*!=\s*-1\s*\)' % fnum, r'(NT_STATUS_IS_OK(status))', data)

    for c in cli:
        t = re.sub('([a-zA-Z]+)', 'tree', c)
        data = re.sub('%s->transport' % c, '%s->session->transport' % t, data)
        data = re.sub('%s->tree' % c, t, data)
        data = re.sub('([^\w]+)(%s)([^\w]+)' % c, r'\1%s\3' % t, data)

    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple script for converting samba's smb1 torture tests to smb2")

    parser.add_argument('file')
    parser.add_argument('--test-suite-name', help='Alternate name for the test suite')

    args = parser.parse_args()

    data = ''
    with open(args.file, 'r') as f:
        data = convert_data(f, args.test_suite_name)
    with open(args.file, 'w') as f:
        f.write(data)
