# -*- coding: UTF-8 -*-

from idaapi import *
from idc import *
from ida_kernwin import *
from ida_segment import *
from PyQt5.Qt import QApplication

import os
import worm_base as base

Choose2 = Choose if IDA_SDK_VERSION >= 740 else Choose2
askfile_c = ask_file if IDA_SDK_VERSION >= 740 else askfile_c

def copyto_clipboard(data):
    print('[WormTools] Copied: ' + data)
    QApplication.clipboard().setText(data)

def jumpto_offset(*args):
    addr = ask_addr(BADADDR, 'RVA:')
    if addr:
        jumpto(get_imagebase() + addr)

try: SegName
except NameError: SegName = lambda ea: get_segm_name(getseg(ea))

# load a *.map file
def load_map(*args):
    path = askfile_c(False, '*.map', 'Open a *.map file')
    if path == None:
        return
    path = path if os.path.exists(path) else path.decode('utf-8').encode('gb2312')
    if not os.path.exists(path):
        print('File Not Exists')

    print('+------------- Load Map: Begin --------------')
    collision = {}
    for line in open(path, 'r'):
        t = line.split()
        if len(t) > 3 and '0' in t[0]:
            ea = int(t[2], 16)
            if ea != 0:
                # ignore the function in then .idata segment
                if SegName(ea) == '.idata':
                    name = get_name(ea)
                    if name:
                        print('| Ignore Import Name: ' + name)
                        continue
                function_name = t[1].replace('<','_').replace('>','_').replace('\\','_')
                if collision.has_key(function_name):
                    collision[function_name].append(ea)
                    set_name(ea, function_name + '_' + str(len(collision[function_name])), SN_NOWARN)
                else:
                    collision[function_name] = []
                    set_name(ea, function_name, SN_NOWARN)
    print('+------------- Load Map: End --------------')

def map_names(*args):
    import json
    rule_path = askfile_c(False, '*.json', 'Open Map Rules')
    if rule_path == None:
        return

    print('[NameMap] Loading json rules: ' + rule_path)
    rules = json.load(open(rule_path))
    print('[NameMap] Begin replace %d functions' % len(rules))

    for (k, v) in rules.items():
        k = str(k); v = str(v)
        addr = LocByName(k)
        if os.environ.get('LOG_DEBUG') == 'ON':
            print('[NameMap] %s: %s -> %s' % (hex(addr), k, v))
        if addr != BADADDR:
            set_name(addr, v)
            MakeComm(addr, k)

    print('[NameMap] DONE')

class SettingsForm(Form):
    def __init__(self):
        self.title = 'WormTools'
        Form.__init__(self, r'''STARTITEM 0
Settings for WormTools

{FormChangeCb}
<#Hint1#模块名:{edit_modulename}>
    ''', {
            'edit_modulename': Form.StringInput(tp = Form.FT_ASCII),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

    def OnFormChange(self, fid):
        if fid == -1:           # Init
            self.SetControlValue(self.edit_modulename, base.idb_get('MODULE_NAME', os.path.basename(get_input_file_path())))
        elif fid == -2:         # OK
            module = self.GetControlValue(self.edit_modulename)
            base.idb_set('MODULE_NAME', module)
            print('[WormTools] Set MODULE_NAME ' + module)
            self.Close(0)

def show_settings(*args):
    form = SettingsForm()
    form.Compile(); form.Execute(); form.Free()

class WormForm(Form):
    def __init__(self):
        self.title = 'WormTools'
        Form.__init__(self, r"""STARTITEM 0
WormTools

复制：
    <##(~W~)单词:{btn_word}> <##(~A~)地址:{btn_address}> <##(~R~)偏移:{btn_offset}> <##(~F~)函数名 :{btn_funcname}> <##(~D~)模块+偏移:{btn_modoff}>
跳转：
    <##(~H~)函数头:{btn_funchead}> <##(~T~)函数尾:{btn_functail}>
其他：
    <## Load~M~ap :{btn_loadmap}> <## Map~N~ame :{btn_mapname}> <##(~1~)PatchNOP:{btn_patchnop}> <## ~S~ettings :{btn_settings}>
        """, {
            'btn_word': Form.ButtonInput(self.on_word),
            'btn_address': Form.ButtonInput(self.on_address),
            'btn_offset': Form.ButtonInput(self.on_offset),
            'btn_funcname': Form.ButtonInput(self.on_funcname),
            'btn_modoff': Form.ButtonInput(self.on_modoff),
            'btn_funchead': Form.ButtonInput(self.on_funchead),
            'btn_functail': Form.ButtonInput(self.on_functail),
            'btn_loadmap': Form.ButtonInput(self.on_loadmap),
            'btn_mapname': Form.ButtonInput(self.on_mapname),
            'btn_settings': Form.ButtonInput(self.on_settings),
            'btn_patchnop': Form.ButtonInput(self.on_patchnop),
        })

    def on_word(self, code = 0):
        try:
            copyto_clipboard(get_highlight(get_current_viewer())[0])
        except:
            pass
        self.Close(0)

    def on_address(self, code = 0):
        copyto_clipboard('0x%x' % here())
        self.Close(0)

    def on_offset(self, code = 0):
        copyto_clipboard('0x%x' % (here() - get_imagebase()))
        self.Close(0)

    def on_funcname(self, code = 0):
        copyto_clipboard(get_func_name(here()))
        self.Close(0)

    def on_modoff(self, code = 0):
        name = base.idb_get('MODULE_NAME', os.path.basename(get_input_file_path()))
        copyto_clipboard('%s+0x%x' % (name, here() - get_imagebase()))
        self.Close(0)

    def on_funchead(self, code = 0):
        addr = get_func_attr(here(), FUNCATTR_START)
        if addr == BADADDR:
            print('FUNCATTR_START NOT FOUND')
        else:
            jumpto(addr)
        self.Close(0)

    def on_functail(self, code = 0):
        addr = get_func_attr(here(), FUNCATTR_END)
        if addr == BADADDR:
            print('FUNCATTR_END NOT FOUND')
        else:
            jumpto(addr)
        self.Close(0)

    def on_loadmap(self, code = 0):
        self.Close(0)
        load_map()

    def on_mapname(self, code = 0):
        self.Close(0)
        map_names()

    def on_settings(self, code = 0):
        self.Close(0)
        show_settings()

    def on_patchnop(self, code = 0):
        from ida_bytes import patch_bytes
        patch_bytes(here(), '\x90' * get_item_size(here()))
        self.Close(0)

def show_wormtools(*args):
    form = WormForm()
    form.Compile(); form.Execute(); form.Free()

class JumpChooser(Choose2):
    def __init__(self, title, cols, items, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            cols,
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.items = items
        self.selcount = 0

    def OnSelectLine(self, n):
        self.selcount += 1
        jumpto(self.items[n][-1])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

def local_xref(ctx):
    func = get_func(here())
    start_ea, end_ea = func.start_ea, func.end_ea

    xrefs = []
    # refto = get_first_dref_from(here())
    refto = get_highlight(get_current_viewer())
    if not refto: return

    refto = LocByName(refto[0])
    if refto == BADADDR: return

    for ref in XrefsTo(refto):
        if ref.frm >= start_ea and ref.frm < end_ea:
            # print(hex(ref.frm))
            xrefs.append([str(ref.type), atoa(ref.frm), ref.frm])
    JumpChooser('local xref to ' + get_name(refto), [['Type', 10], ['Address', 30|Choose2.CHCOL_HEX]], xrefs).Show(True)

class WormTools(plugin_t):
    flags         = PLUGIN_KEEP | PLUGIN_FIX
    wanted_hotkey = ''
    wanted_name   = "WormTools"
    comment       = "https://github.com/metaworm/worm-ida"
    help          = "https://github.com/metaworm/worm-ida"

    def init(self):
        base.add_menu_item('Jump/', 'Jump to Offset', 'worm:jumptooffset',
                base.ActionHandler(jumpto_offset, enable = AST_ENABLE_FOR_IDB), 'Shift+G', 'Jump To Offset')
        base.add_menu_item('Edit/', 'WormTools', 'worm:wormtools',
                base.ActionHandler(show_wormtools, enable = lambda: True), 'W', 'WormTools')
        base.add_menu_item('Edit/', 'Name Mappings(~f~)', 'worm:namemap',
                base.ActionHandler(map_names), tooltip = 'Rename symbols by a table')

        base.add_menu_item('File/Load file/', '~M~ap file...', 'worm:loadmap',
                base.ActionHandler(load_map), tooltip = 'Load *.map file')
        base.add_menu_item('Jump/', 'Jump to local xrefs', 'worm:local_xref',
                base.ActionHandler(local_xref), 'Shift+X')

        msg("[WormTools] Plugin Initialized.\n")
        return PLUGIN_OK

    def term(self):
        msg('[WormTools] Plugin Terminated.\n')

    def run(self, arg):
        show_settings()

def PLUGIN_ENTRY():
    return WormTools()