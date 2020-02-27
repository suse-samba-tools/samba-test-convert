#!/usr/bin/python3
import re, sys

data = ''
with open(sys.argv[1], 'r') as f:
    data = f.read()
    cli = re.findall('struct smbcli_state \*([^,;\)\(]+)[,;\)]', data)
    data = re.sub('struct smbcli_state', 'struct smb2_tree', data)
    data = re.sub('\s*struct smbcli_session_options session_options;', r'', data)
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

        # Replace the lock inputs/outputs
        data = re.sub('%s\.\w+\.in' % l, '%s.in' % l, data)
        data = re.sub('%s\.\w+\.out' % l, '%s.out' % l, data)

    if len(torture) > 0:
        data = re.sub('torture_setup_dir\(([^,]+),\s*([^\)]+)\)', r'smb2_util_setup_dir(%s, \1, \2)' % torture[0], data)

    data = data.replace('smbcli_deltree', 'smb2_deltree')
    data = data.replace('smbcli_close', 'smb2_util_close')

    sopen = re.findall('union\s+smb_open\s+([^,;]+)', data)
    for o in sopen:
        # Replace the definition
        data = re.sub('union\s+smb_open', 'struct smb2_create', data)

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
        data = re.sub('%s\.\w+\.in' % o, '%s.in' % o, data)
        data = re.sub('%s\.\w+\.out' % o, '%s.out' % o, data)

    data = re.sub('smb_raw_open\s*\(', 'smb2_create(', data)
    data = re.sub('smb_raw_open_send\s*\(', 'smb2_create_send(', data)
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
    data = re.sub('\n(\s*)(.*)smbcli_nt_create_full\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\);', r'\1struct smb2_create io;\n\1io.in.fname = \4;\1io.in.create_flags = \5;\1io.in.desired_access = \6;\1io.in.file_attributes = \7;\1io.in.share_access = \8;\1io.in.create_disposition = \9;\1io.in.create_options = \10;\1io.in.security_flags = \11;\1smb2_create(\3, \3, &io);\n\1\2io.out.file.handle;', data)

    data = data.replace('smbcli_tree', 'smb2_tree')

    for c in cli:
        t = re.sub('([a-zA-Z]+)', 'tree', c)
        data = re.sub('%s->transport' % c, '%s->session->transport' % t, data)
        data = re.sub('%s->tree' % c, t, data)
        data = re.sub('([^\w]+)(%s)([^\w]+)' % c, r'\1%s\3' % t, data)

with open(sys.argv[1], 'w') as f:
    f.write(data)
