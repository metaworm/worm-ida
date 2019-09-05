
from ida_kernwin import *
from netnode import Netnode

class ActionHandler(action_handler_t):
    def __init__(self, handler, disable = None, enable = None):
        action_handler_t.__init__(self)
        self.disable = disable
        self.enable = enable
        self.handler = handler

    # Say hello when invoked.
    def activate(self, ctx):
        return self.handler(ctx)

    # This action is always available.
    def update(self, ctx):
        if self.enable:
            if type(self.enable) is int:
                return self.enable
            return AST_ENABLE if self.enable() else AST_DISABLE
        if self.disable:
            return AST_DISABLE if self.disable() else AST_ENABLE
        return AST_ENABLE_ALWAYS

def add_menu_item(menu_path, label, action_name, handler, shortcut = '', tooltip = ''):
    # Register the action
    r = register_action(action_desc_t(
        action_name,    # The action name. This acts like an ID and must be unique
        label,          # The action text.
        handler,        # The action handler
        shortcut,       # Optional: the action shortcut
        tooltip,        # Optional: the action tooltip (available in menus/toolbar)
                        # Optional: the action icon (shows when in menus/toolbars) use numbers 1-255
    ))
    return attach_action_to_menu(menu_path, action_name, SETMENU_APP)

def idb_get(key, val = None):
    return Netnode('WormTools').get(key, val)

def idb_set(key, val):
    Netnode('WormTools')[key] = val