#!/usr/bin/env python3
"""mystra-compiler.py -- Mystra Compiler (tree-sitter)

Walks the tree-sitter CST and emits .tbin v3 binary directly.
No intermediate AST dataclasses.

Usage:
    python3 mystra-compiler.py input.tsl [-o output.tbin] [--dump] [--verbose]
"""

import sys, copy, struct, argparse, ctypes, warnings
from pathlib import Path
from collections import defaultdict

warnings.filterwarnings('ignore', category=DeprecationWarning)
from tree_sitter import Language, Parser

# ---- Constants (match C++ taint-interpreter.h) ----

# Actions
ACTION_PROPAGATE    = 0
ACTION_FORWARD      = 1
ACTION_CLEAR        = 2
ACTION_SINK   = 3
ACTION_PRESERVE     = 4
ACTION_COLLAPSE     = 5
ACTION_TAINT_SOURCE = 6
ACTION_INJECT       = 7
ACTION_EXTRACT      = 8
ACTION_SET           = 9

# Var value types (match C++ VarValueType)
VAR_NUMBER = 0; VAR_STRING = 1; VAR_BOOL = 2; VAR_TAINT = 3; VAR_REF = 4
VAR_TYPE_MAP = {'number': VAR_NUMBER, 'string': VAR_STRING, 'bool': VAR_BOOL,
                'taint': VAR_TAINT, 'ref': VAR_REF}

# Var structures
VAR_SCALAR = 0; VAR_MAP1 = 1; VAR_MAP2 = 2

# Value source types (for SET keys and values)
VSRC_LOC_TAINT = 0  # @base.taint -> extract taint_id
VSRC_LOC_REF   = 1  # @base.ref   -> extract identity hash
VSRC_LOC_VALUE = 2  # @base.value -> extract runtime value
VSRC_LITERAL   = 3  # compile-time literal

# Guard expression type for var lookup
GEXPR_VAR_LOOKUP = 3

# Base entities
BASE_SELF           = 0
BASE_ARG            = 1
BASE_ARG_RANGE      = 2
BASE_RETURN         = 3
BASE_GLOBAL         = 4
BASE_CALLBACK_PARAM = 5
BASE_CALLBACK_RETURN= 6
BASE_VAR_LOOKUP     = 7

# Offset types
OFF_NONE            = 0
OFF_ELEM_SHALLOW    = 1
OFF_PROP_SHALLOW    = 2
OFF_SPEC_PROP       = 3
OFF_DEEP_SCAN       = 4
OFF_DYNAMIC_KEY     = 5
OFF_ELEM_DEEP       = 6
OFF_PROP_DEEP       = 7

# Guard expression types
GEXPR_MAGIC_GLOBAL      = 0
GEXPR_LOCATOR_MAGIC_PROP= 1
GEXPR_LOCATOR_VALUE     = 2

# Magic props
MPROP_VALUE     = 0
MPROP_TAINTED   = 1
MPROP_ISNULL    = 2
MPROP_TYPE      = 3
MPROP_ISCALLBACK= 4
MPROP_ISPROTOTYPE=5
MPROP_NA        = 255

MAGIC_PROP_MAP = {
    'value': MPROP_VALUE, 'tainted': MPROP_TAINTED,
    'isnull': MPROP_ISNULL, 'type': MPROP_TYPE,
    'isCallback': MPROP_ISCALLBACK, 'isPrototype': MPROP_ISPROTOTYPE,
}

# Compare ops
CMP_EQ  = 0; CMP_NEQ = 1; CMP_GT  = 2; CMP_GTE = 3
CMP_LT  = 4; CMP_LTE = 5; CMP_IN  = 6; CMP_MATCHES = 7

CMP_OP_MAP = {'==': CMP_EQ, '!=': CMP_NEQ, '>': CMP_GT,
              '>=': CMP_GTE, '<': CMP_LT, '<=': CMP_LTE}

# Literal types
LIT_STRING = 0; LIT_INT = 1; LIT_BOOL = 2; LIT_NULL = 3; LIT_STRING_SET = 4

# Dispatch categories
# CPython namespaces (Py_native, Py_hostapi) both map to host_api (3): CPython has
# no V8 builtin IDs, so every rule is dispatched by signature string via the
# host_api hash map (mirrors the CPython adapter's GetBuiltinId() == -1).
CATEGORY_MAP = {'V8_native': 0, 'V8_runtime': 1, 'V8_bytecode': 2, 'Node': 3, 'V8_hostapi': 3,
                'Py_native': 3, 'Py_hostapi': 3}

# ---- CST Helpers ----

def text(node):
    """Get decoded text of a CST node."""
    return node.text.decode('utf-8')

def child_of_type(node, type_name):
    """Get first named child of a specific type."""
    for c in node.named_children:
        if c.type == type_name:
            return c
    return None

def children_of_type(node, type_name):
    """Get all named children of a specific type."""
    return [c for c in node.named_children if c.type == type_name]

def parse_string(node):
    """Extract string content from a string CST node (strips quotes, handles escapes)."""
    s = text(node)
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    result, i = [], 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            c = s[i + 1]
            esc = {'n': '\n', 't': '\t', '\\': '\\', '"': '"', "'": "'"}
            if c in esc:
                result.append(esc[c])
            else:
                result.append('\\')
                result.append(c)
            i += 2
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


# ---- Mystra Compiler ----

class TSLCompiler:
    def __init__(self):
        so_path = Path(__file__).parent / 'tsl_parser.so'
        lib = ctypes.CDLL(str(so_path))
        func = lib.tree_sitter_tsl
        func.restype = ctypes.c_void_p
        lang = Language(func())
        self._parser = Parser(lang)
        # String table
        self._strings = []
        self._str_idx = {}
        # Var declarations
        self._vars = []       # list of (name, value_type, structure, key1_type, key2_type)
        self._var_idx = {}    # name -> index
        # Stats
        self.rule_count = 0
        self.subrule_count = 0
        self.strings = []  # for external access

    def _intern(self, s):
        """Intern a string, return its index."""
        if s not in self._str_idx:
            self._str_idx[s] = len(self._strings)
            self._strings.append(s)
        return self._str_idx[s]

    def compile(self, source):
        """Compile Mystra source to .tbin v4 bytes."""
        tree = self._parser.parse(source.encode('utf-8'))
        root = tree.root_node

        # First pass: walk var_decl nodes
        for child in root.named_children:
            if child.type == 'var_decl':
                self._walk_var_decl(child)

        # Collect all rules: list of (category, sig, params, sub_rules_data)
        raw_rules = []
        for child in root.named_children:
            if child.type == 'annotated_rule':
                rule_info = self._walk_annotated_rule(child)
                if rule_info is not None:
                    raw_rules.append(rule_info)

        # Merge overloaded rules (same func_sig, different argc)
        rules = self._merge_overloaded(raw_rules)

        # Intern all strings (var names, rule strings)
        for name, vtype, structure, k1type, k2type in self._vars:
            self._intern(name)
        for category, sig, params, sub_rules in rules:
            self._intern(sig)
            for sr in sub_rules:
                self._intern_subrule_strings(sr)

        # Emit var table
        var_buf = self._emit_var_table()

        # Emit rules
        rules_buf = b''
        for category, sig, params, sub_rules in rules:
            rules_buf += self._emit_rule(category, sig, sub_rules)

        str_buf = self._emit_string_table()

        HEADER_SIZE = 20
        self.rule_count = len(rules)
        self.subrule_count = sum(len(sr_list) for _, _, _, sr_list in rules)
        self.strings = list(self._strings)

        rules_offset = HEADER_SIZE + len(var_buf)
        str_offset = rules_offset + len(rules_buf)

        # v4 header: Magic(4) + Version(2) + Flags(2) + VarCount(2) + RuleCount(2) + RulesOffset(4) + StringTableOffset(4)
        hdr = b'TBIN' + struct.pack('<HHHH II', 4, 0, len(self._vars), len(rules),
                                    rules_offset, str_offset)
        return hdr + var_buf + rules_buf + str_buf

    # ---- Var declaration walking ----

    def _walk_var_decl(self, node):
        """Walk a var_decl CST node. Registers the variable."""
        idents = children_of_type(node, 'identifier')
        if not idents:
            return
        var_name = text(idents[0])

        # Determine structure from var_key_spec
        key_spec = child_of_type(node, 'var_key_spec')
        structure = VAR_SCALAR
        k1type = 0
        k2type = 0
        if key_spec is not None:
            map2 = child_of_type(key_spec, 'var_key_map2')
            map1 = child_of_type(key_spec, 'var_key_map1')
            if map2 is not None:
                structure = VAR_MAP2
                vtypes = children_of_type(map2, 'var_value_type')
                if len(vtypes) >= 1:
                    k1type = VAR_TYPE_MAP.get(text(vtypes[0]), VAR_NUMBER)
                if len(vtypes) >= 2:
                    k2type = VAR_TYPE_MAP.get(text(vtypes[1]), VAR_NUMBER)
            elif map1 is not None:
                structure = VAR_MAP1
                vtypes = children_of_type(map1, 'var_value_type')
                if len(vtypes) >= 1:
                    k1type = VAR_TYPE_MAP.get(text(vtypes[0]), VAR_NUMBER)

        # Value type: the var_value_type directly under var_decl (after ->)
        val_type_nodes = children_of_type(node, 'var_value_type')
        vtype = VAR_NUMBER
        if val_type_nodes:
            vtype = VAR_TYPE_MAP.get(text(val_type_nodes[-1]), VAR_NUMBER)

        idx = len(self._vars)
        self._vars.append((var_name, vtype, structure, k1type, k2type))
        self._var_idx[var_name] = idx

    # ---- Top-level rule walking ----

    def _walk_annotated_rule(self, node):
        """Walk an annotated_rule node. Returns (category, sig, params, sub_rules) or None."""
        rule_decl = child_of_type(node, 'rule_decl')
        if rule_decl is None:
            return None

        # Extract annotation (optional)
        annotation = child_of_type(node, 'annotation')
        engine_anno = None
        if annotation is not None:
            ident = child_of_type(annotation, 'identifier')
            if ident is not None:
                engine_anno = text(ident)

        return self._walk_rule_decl(rule_decl)

    def _walk_rule_decl(self, node):
        """Walk a rule_decl node. Returns (category, sig, params, sub_rules)."""
        # func_sig
        func_sig_node = child_of_type(node, 'func_sig')
        category, sig = self._extract_func_sig(func_sig_node)
        # Prepend Runtime_ for V8_runtime
        tbin_sig = ('Runtime_' + sig) if category == 'V8_runtime' else sig

        # params
        param_list_node = child_of_type(node, 'param_list')
        params, param_map = self._extract_params(param_list_node)

        # rule_body -> sub_rules
        rule_body = child_of_type(node, 'rule_body')
        sub_rules = []
        if rule_body is not None:
            for sr_node in children_of_type(rule_body, 'sub_rule'):
                srs = self._walk_sub_rule(sr_node, params, param_map)
                sub_rules.extend(srs)

        return (category, tbin_sig, params, sub_rules)

    def _extract_func_sig(self, node):
        """Extract (category, signature) from func_sig node."""
        full = text(node)
        if '::' in full:
            idx = full.index('::')
            return full[:idx], full[idx + 2:]
        return None, full

    def _extract_params(self, node):
        """Extract params list and param_map from param_list node."""
        params = []  # list of (name, is_rest)
        param_map = {}  # name -> index
        if node is None:
            return params, param_map
        for p_node in children_of_type(node, 'param'):
            rest = child_of_type(p_node, 'rest_param')
            if rest is not None:
                ident = child_of_type(rest, 'identifier')
                name = text(ident) if ident else ''
                params.append((name, True))
            else:
                single = child_of_type(p_node, 'single_param')
                if single is not None:
                    ident = child_of_type(single, 'identifier')
                    name = text(ident) if ident else text(single)
                else:
                    name = ''
                params.append((name, False))
            param_map[params[-1][0]] = len(params) - 1
        return params, param_map

    # ---- Sub-rule walking ----

    def _walk_sub_rule(self, sr_node, params, param_map):
        """Walk a sub_rule node. Returns list of sub_rule dicts (may expand OR guards)."""
        # sub_rule has exactly one child that is the actual rule type
        for child in sr_node.named_children:
            t = child.type
            if t == 'propagate_rule':
                return self._walk_flow_rule(child, ACTION_PROPAGATE, params, param_map)
            elif t == 'forward_rule':
                return self._walk_flow_rule(child, ACTION_FORWARD, params, param_map)
            elif t == 'inject_rule':
                return self._walk_inject_rule(child, params, param_map)
            elif t == 'extract_rule':
                return self._walk_extract_rule(child, params, param_map)
            elif t == 'sink_rule':
                return self._walk_sink_rule(child, params, param_map)
            elif t == 'collapse_rule':
                return self._walk_flow_rule(child, ACTION_COLLAPSE, params, param_map)
            elif t == 'taint_source_rule':
                return self._walk_taint_source_rule(child, params, param_map)
            elif t == 'clear_rule':
                return self._walk_simple_rule(child, ACTION_CLEAR, params, param_map)
            elif t == 'preserve_rule':
                return self._walk_simple_rule(child, ACTION_PRESERVE, params, param_map)
            elif t == 'set_rule':
                return self._walk_set_rule(child, params, param_map)
        return []

    def _walk_flow_rule(self, node, action, params, param_map):
        """Walk propagate/forward/collapse rule: ACTION sources -> sinks [guard]."""
        sources = self._walk_source_list(child_of_type(node, 'source_list'), params, param_map)
        sinks = self._walk_sink_list(child_of_type(node, 'sink_list'), params, param_map)
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(action, sources, sinks, guard_dnf, 0)

    def _walk_inject_rule(self, node, params, param_map):
        """Walk INJECT rule: sources -> callback_sink [guard]."""
        sources = self._walk_source_list(child_of_type(node, 'source_list'), params, param_map)
        cb_sink_node = child_of_type(node, 'callback_sink')
        sinks = self._walk_callback_sink(cb_sink_node, params, param_map) if cb_sink_node else []
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(ACTION_INJECT, sources, sinks, guard_dnf, 0)

    def _walk_extract_rule(self, node, params, param_map):
        """Walk EXTRACT rule: callback_source -> sinks [guard]."""
        cb_src_node = child_of_type(node, 'callback_source')
        sources = self._walk_callback_source(cb_src_node, params, param_map) if cb_src_node else []
        sinks = self._walk_sink_list(child_of_type(node, 'sink_list'), params, param_map)
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(ACTION_EXTRACT, sources, sinks, guard_dnf, 0)

    def _walk_sink_rule(self, node, params, param_map):
        """Walk SINK rule: sources @cwe(N) [guard]."""
        sources = self._walk_source_list(child_of_type(node, 'source_list'), params, param_map)
        alert_anno = child_of_type(node, 'alert_anno')
        alert_cwe = 0
        if alert_anno is not None:
            int_node = child_of_type(alert_anno, 'integer')
            if int_node is not None:
                alert_cwe = int(text(int_node))
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(ACTION_SINK, sources, [], guard_dnf, alert_cwe)

    def _walk_taint_source_rule(self, node, params, param_map):
        """Walk TAINT_SOURCE rule: -> sinks [guard]."""
        sinks = self._walk_sink_list(child_of_type(node, 'sink_list'), params, param_map)
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(ACTION_TAINT_SOURCE, [], sinks, guard_dnf, 0)

    def _walk_simple_rule(self, node, action, params, param_map):
        """Walk CLEAR/PRESERVE rule: ACTION [guard]."""
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]
        return self._expand_guard_dnf(action, [], [], guard_dnf, 0)

    def _walk_set_rule(self, node, params, param_map):
        """Walk SET rule: SET target = value [guard]."""
        target_node = child_of_type(node, 'set_target')
        if target_node is None:
            return []

        # Extract var name from set_target's identifier. Belonging analysis:
        # a `set` target is always a declared global store (no `$` sigil).
        ident = child_of_type(target_node, 'identifier')
        var_name = text(ident) if ident else ''
        if var_name not in self._var_idx:
            print(f"Warning: SET references undeclared var '{var_name}'", file=sys.stderr)
            return []
        var_index = self._var_idx[var_name]

        # Extract 0-2 set_key children from set_target
        key_nodes = children_of_type(target_node, 'set_key')
        key_sources = []
        for kn in key_nodes:
            ks = self._walk_value_source(kn, params, param_map)
            key_sources.append(ks)

        # Extract set_value
        value_node = child_of_type(node, 'set_value')
        if value_node is None:
            return []
        value_source = self._walk_value_source(value_node, params, param_map)

        # Type checking: validate key count and types against var declaration
        var_name_str, var_vtype, var_struct, var_k1t, var_k2t = self._vars[var_index]
        expected_keys = {VAR_SCALAR: 0, VAR_MAP1: 1, VAR_MAP2: 2}.get(var_struct, 0)
        if len(key_sources) != expected_keys:
            raise TypeError(
                f"SET {var_name}: expected {expected_keys} key(s) "
                f"(declared as {'scalar' if var_struct == VAR_SCALAR else 'map' + str(expected_keys)}), "
                f"got {len(key_sources)}")
        if expected_keys >= 1:
            self._check_vsrc_type(key_sources[0], var_k1t, var_name, "key1")
        if expected_keys == 2:
            self._check_vsrc_type(key_sources[1], var_k2t, var_name, "key2")
        self._check_vsrc_type(value_source, var_vtype, var_name, "value")

        # Guard
        guard_node = child_of_type(node, 'guard')
        guard_dnf = self._walk_guard(guard_node, params, param_map) if guard_node else [[]]

        # Expand guard DNF
        result = []
        for conjunction in guard_dnf:
            guards = conjunction if conjunction else []
            result.append({
                'action': ACTION_SET,
                'var_index': var_index,
                'key_sources': copy.deepcopy(key_sources),
                'value_source': copy.deepcopy(value_source),
                'guards': copy.deepcopy(guards),
                'sources': [],
                'sinks': [],
                'alert_cwe': 0,
            })
        return result

    def _walk_value_source(self, node, params, param_map):
        """Walk a set_key or set_value node. Returns value source dict."""
        # Check child types
        loc_taint = child_of_type(node, 'set_loc_taint')
        if loc_taint is not None:
            base, index = self._walk_value_source_base(loc_taint, params, param_map)
            return {'vsrc_type': VSRC_LOC_TAINT, 'base': base, 'index': index}

        loc_ref = child_of_type(node, 'set_loc_ref')
        if loc_ref is not None:
            base, index = self._walk_value_source_base(loc_ref, params, param_map)
            return {'vsrc_type': VSRC_LOC_REF, 'base': base, 'index': index}

        loc_value = child_of_type(node, 'set_loc_value')
        if loc_value is not None:
            base, index = self._walk_value_source_base(loc_value, params, param_map)
            return {'vsrc_type': VSRC_LOC_VALUE, 'base': base, 'index': index}

        lit_node = child_of_type(node, 'literal')
        if lit_node is not None:
            lit = self._walk_literal(lit_node)
            return {
                'vsrc_type': VSRC_LITERAL,
                'literal_type': lit.get('literal_type', LIT_NULL),
                'literal_int': lit.get('literal_int', 0),
                'literal_string': lit.get('literal_string', ''),
                'literal_bool': lit.get('literal_bool', False),
            }

        # Fallback
        return {'vsrc_type': VSRC_LITERAL, 'literal_type': LIT_NULL,
                'literal_int': 0, 'literal_string': '', 'literal_bool': False}

    def _walk_value_source_base(self, loc_node, params, param_map):
        """Walk the _base child inside a set_loc_taint/ref/value node. Returns (base, index)."""
        bs = child_of_type(loc_node, 'base_self')
        if bs is not None:
            return (BASE_SELF, 0)

        br = child_of_type(loc_node, 'base_ret')
        if br is not None:
            return (BASE_RETURN, 0)

        ba = child_of_type(loc_node, 'base_args')
        if ba is not None:
            sr = child_of_type(ba, 'slice_single')
            if sr is not None:
                int_node = child_of_type(sr, 'integer')
                idx = int(text(int_node)) if int_node else 0
                return (BASE_ARG, idx)
            so = child_of_type(ba, 'slice_open')
            if so is not None:
                int_node = child_of_type(so, 'integer')
                idx = int(text(int_node)) if int_node else 0
                return (BASE_ARG, idx)
            # Check slice_expr
            se = child_of_type(ba, 'slice_expr')
            if se is not None:
                ss = child_of_type(se, 'slice_single')
                if ss is not None:
                    int_node = child_of_type(ss, 'integer')
                    return (BASE_ARG, int(text(int_node)) if int_node else 0)
            return (BASE_ARG, 0)

        bn = child_of_type(loc_node, 'base_name')
        if bn is not None:
            ident = child_of_type(bn, 'identifier')
            name = text(ident) if ident else ''
            if name in param_map:
                return (BASE_ARG, param_map[name])
            return (BASE_ARG, 0)

        return (BASE_SELF, 0)

    # Value source type → compatible var types
    _VSRC_PRODUCES = {
        VSRC_LOC_TAINT: VAR_TAINT,
        VSRC_LOC_REF:   VAR_REF,
        VSRC_LOC_VALUE: None,  # compatible with string or number (runtime value)
    }
    _LIT_PRODUCES = {
        LIT_STRING: VAR_STRING,
        LIT_INT:    VAR_NUMBER,
        LIT_BOOL:   VAR_BOOL,
    }
    _TYPE_NAMES = {VAR_NUMBER: 'number', VAR_STRING: 'string', VAR_BOOL: 'bool',
                   VAR_TAINT: 'taint', VAR_REF: 'ref'}

    def _check_vsrc_type(self, vs, expected_type, var_name, role):
        """Compile-time type check: verify a value source produces the expected var type."""
        vsrc = vs['vsrc_type']
        if vsrc in (VSRC_LOC_TAINT, VSRC_LOC_REF):
            produced = self._VSRC_PRODUCES[vsrc]
            if produced != expected_type:
                raise TypeError(
                    f"SET {var_name} {role}: .{'taint' if vsrc == VSRC_LOC_TAINT else 'ref'} "
                    f"produces {self._TYPE_NAMES.get(produced, '?')}, "
                    f"but var expects {self._TYPE_NAMES.get(expected_type, '?')}")
        elif vsrc == VSRC_LOC_VALUE:
            if expected_type not in (VAR_STRING, VAR_NUMBER, VAR_REF):
                raise TypeError(
                    f"SET {var_name} {role}: .value produces a runtime value, "
                    f"but var expects {self._TYPE_NAMES.get(expected_type, '?')}")
        elif vsrc == VSRC_LITERAL:
            lit_type = vs.get('literal_type', LIT_NULL)
            produced = self._LIT_PRODUCES.get(lit_type)
            if produced is not None and produced != expected_type:
                raise TypeError(
                    f"SET {var_name} {role}: literal type "
                    f"{self._TYPE_NAMES.get(produced, '?')} doesn't match "
                    f"var type {self._TYPE_NAMES.get(expected_type, '?')}")

    def _expand_guard_dnf(self, action, sources, sinks, guard_dnf, alert_cwe):
        """Expand DNF guard into multiple sub-rules. Each sub-rule is a dict."""
        result = []
        for conjunction in guard_dnf:
            guards = conjunction if conjunction else []
            result.append({
                'action': action,
                'sources': copy.deepcopy(sources),
                'sinks': copy.deepcopy(sinks),
                'guards': copy.deepcopy(guards),
                'alert_cwe': alert_cwe,
            })
        return result

    # ---- Locator walking ----

    def _walk_source_list(self, node, params, param_map):
        """Walk source_list -> list of source dicts. Every item is a locator;
        belonging analysis (in _walk_locator_as_source) decides whether a bare
        name is a declared global-store read or a param/base reference."""
        if node is None:
            return []
        return [self._walk_locator_as_source(loc, params, param_map)
                for loc in children_of_type(node, 'locator')]

    def _walk_sink_list(self, node, params, param_map):
        """Walk sink_list -> list of sink dicts."""
        if node is None:
            return []
        return [self._walk_locator_as_sink(loc, params, param_map)
                for loc in children_of_type(node, 'locator')]

    def _walk_locator_as_source(self, node, params, param_map):
        """Walk a locator node for a source position. Returns source dict.
        Belonging analysis: if the base name was declared with `let`, this is a
        global-store read (BASE_VAR_LOOKUP); otherwise a param/base reference."""
        bn = child_of_type(node, 'base_name')
        if bn is not None:
            ident = child_of_type(bn, 'identifier')
            name = text(ident) if ident else ''
            if name in self._var_idx:
                return self._walk_var_read(node, name, params, param_map)
        base, index, end_index = self._walk_base(node, params, param_map)
        offset, prop_name, key_arg_index = self._walk_path(node, params, param_map)
        return {
            'base': base, 'index': index, 'end_index': end_index,
            'offset': offset, 'prop_name': prop_name, 'key_arg_index': key_arg_index,
        }

    def _walk_var_read(self, node, var_name, params, param_map):
        """Build a BASE_VAR_LOOKUP source dict for a source locator whose base is
        a declared global var. Keys come from the locator's dynamic-key path
        (e.g. io_taint[path.ref])."""
        var_index = self._var_idx[var_name]
        key_sources = self._locator_var_keys(node, params, param_map)
        self._typecheck_var_keys(var_index, key_sources, var_name)
        return {
            'base': BASE_VAR_LOOKUP, 'index': var_index, 'end_index': -1,
            'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
            'var_key_sources': key_sources,
        }

    def _locator_var_keys(self, locator_node, params, param_map):
        """Extract 0-or-1 var key value-sources from a source locator's path.
        A locator carries at most one bracketed key, so global-store reads in
        source position support scalar and map1 vars (map2 uses `set`)."""
        pdk = child_of_type(locator_node, 'path_dyn_key')
        if pdk is None:
            return []
        ks = self._dyn_key_to_vsrc(pdk, params, param_map)
        return [ks] if ks is not None else []

    def _dyn_key_to_vsrc(self, pdk_node, params, param_map):
        """Convert a path_dyn_key inner node into a var-key value-source dict."""
        dkl = child_of_type(pdk_node, 'dyn_key_loc')
        if dkl is not None:
            ident = child_of_type(dkl, 'identifier')
            name = text(ident) if ident else ''
            base = BASE_ARG if name in param_map else BASE_SELF
            index = param_map.get(name, 0)
            t = text(dkl)
            if t.endswith('.taint'):
                vt = VSRC_LOC_TAINT
            elif t.endswith('.ref'):
                vt = VSRC_LOC_REF
            else:
                vt = VSRC_LOC_VALUE
            return {'vsrc_type': vt, 'base': base, 'index': index}
        lit = child_of_type(pdk_node, 'dyn_key_literal')
        if lit is not None:
            snode = child_of_type(lit, 'string')
            return {'vsrc_type': VSRC_LITERAL, 'literal_type': LIT_STRING,
                    'literal_int': 0,
                    'literal_string': parse_string(snode) if snode else '',
                    'literal_bool': False}
        return None

    def _typecheck_var_keys(self, var_index, key_sources, var_name):
        """Validate key count/types of a var read against its declaration."""
        var_name_str, var_vtype, var_struct, var_k1t, var_k2t = self._vars[var_index]
        expected_keys = {VAR_SCALAR: 0, VAR_MAP1: 1, VAR_MAP2: 2}.get(var_struct, 0)
        if len(key_sources) != expected_keys:
            raise TypeError(
                f"{var_name}: expected {expected_keys} key(s) "
                f"(declared as {'scalar' if var_struct == VAR_SCALAR else 'map' + str(expected_keys)}), "
                f"got {len(key_sources)}")
        if expected_keys >= 1:
            self._check_vsrc_type(key_sources[0], var_k1t, var_name, "key1")
        if expected_keys == 2:
            self._check_vsrc_type(key_sources[1], var_k2t, var_name, "key2")

    def _walk_locator_as_sink(self, node, params, param_map):
        """Walk a locator node for a sink position. Returns sink dict."""
        base, index, end_index = self._walk_base(node, params, param_map)
        offset, prop_name, key_arg_index = self._walk_path(node, params, param_map)
        return {
            'base': base, 'index': index,
            'offset': offset, 'prop_name': prop_name, 'key_arg_index': key_arg_index,
        }

    def _walk_base(self, locator_node, params, param_map):
        """Walk the base of a locator. Returns (base, index, end_index)."""
        bs = child_of_type(locator_node, 'base_self')
        if bs is not None:
            return BASE_SELF, 0, -1

        br = child_of_type(locator_node, 'base_ret')
        if br is not None:
            return BASE_RETURN, 0, -1

        ba = child_of_type(locator_node, 'base_args')
        if ba is not None:
            return self._walk_base_args(ba)

        bn = child_of_type(locator_node, 'base_name')
        if bn is not None:
            return self._walk_base_name(bn, params, param_map)

        return BASE_SELF, 0, -1

    def _walk_base_args(self, node):
        """Walk base_args: @args[slice_expr]."""
        # Find the slice expression
        sr = child_of_type(node, 'slice_single')
        if sr is not None:
            int_node = child_of_type(sr, 'integer')
            idx = int(text(int_node)) if int_node else 0
            return BASE_ARG, idx, -1

        so = child_of_type(node, 'slice_open')
        if so is not None:
            int_node = child_of_type(so, 'integer')
            idx = int(text(int_node)) if int_node else 0
            return BASE_ARG_RANGE, idx, -1

        srange = child_of_type(node, 'slice_range')
        if srange is not None:
            ints = children_of_type(srange, 'integer')
            start = int(text(ints[0])) if len(ints) > 0 else 0
            end = int(text(ints[1])) if len(ints) > 1 else -1
            return BASE_ARG_RANGE, start, end

        # Fallback: check named children for slice expressions nested inside
        for child in node.named_children:
            if child.type == 'slice_expr':
                return self._walk_slice_expr(child)

        return BASE_ARG, 0, -1

    def _walk_slice_expr(self, node):
        """Walk a slice_expr node."""
        sr = child_of_type(node, 'slice_single')
        if sr is not None:
            int_node = child_of_type(sr, 'integer')
            return BASE_ARG, int(text(int_node)) if int_node else 0, -1

        so = child_of_type(node, 'slice_open')
        if so is not None:
            int_node = child_of_type(so, 'integer')
            return BASE_ARG_RANGE, int(text(int_node)) if int_node else 0, -1

        srange = child_of_type(node, 'slice_range')
        if srange is not None:
            ints = children_of_type(srange, 'integer')
            start = int(text(ints[0])) if len(ints) > 0 else 0
            end = int(text(ints[1])) if len(ints) > 1 else -1
            return BASE_ARG_RANGE, start, end

        return BASE_ARG, 0, -1

    def _walk_base_name(self, node, params, param_map):
        """Walk base_name: identifier resolved via param_map."""
        ident = child_of_type(node, 'identifier')
        name = text(ident) if ident else ''
        if name in param_map:
            pidx = param_map[name]
            is_rest = params[pidx][1]
            if is_rest:
                return BASE_ARG_RANGE, pidx, -1
            else:
                return BASE_ARG, pidx, -1
        return BASE_ARG, 0, -1

    def _walk_path(self, locator_node, params, param_map):
        """Walk the path component of a locator. Returns (offset, prop_name, key_arg_index)."""
        pes = child_of_type(locator_node, 'path_elem_shallow')
        if pes is not None:
            return OFF_ELEM_SHALLOW, None, -1

        ped = child_of_type(locator_node, 'path_elem_deep')
        if ped is not None:
            return OFF_ELEM_DEEP, None, -1

        pps = child_of_type(locator_node, 'path_prop_shallow')
        if pps is not None:
            return OFF_PROP_SHALLOW, None, -1

        ppd = child_of_type(locator_node, 'path_prop_deep')
        if ppd is not None:
            return OFF_PROP_DEEP, None, -1

        psp = child_of_type(locator_node, 'path_specific_prop')
        if psp is not None:
            ident = child_of_type(psp, 'identifier')
            prop_name = text(ident) if ident else ''
            return OFF_SPEC_PROP, prop_name, -1

        pdk = child_of_type(locator_node, 'path_dyn_key')
        if pdk is not None:
            return self._walk_dyn_key(pdk, params, param_map)

        return OFF_NONE, None, -1

    def _walk_dyn_key(self, node, params, param_map):
        """Walk path_dyn_key node. Returns (OFF_DYNAMIC_KEY, None, key_arg_index)."""
        dka = child_of_type(node, 'dyn_key_args')
        if dka is not None:
            int_node = child_of_type(dka, 'integer')
            idx = int(text(int_node)) if int_node else 0
            return OFF_DYNAMIC_KEY, None, idx

        dkn = child_of_type(node, 'dyn_key_name')
        if dkn is not None:
            ident = child_of_type(dkn, 'identifier')
            name = text(ident) if ident else ''
            if name in param_map:
                return OFF_DYNAMIC_KEY, None, param_map[name]
            return OFF_DYNAMIC_KEY, None, 0

        return OFF_DYNAMIC_KEY, None, 0

    # ---- Callback locator walking ----

    def _walk_callback_sink(self, node, params, param_map):
        """Walk callback_sink -> list of sink dicts."""
        legacy = child_of_type(node, 'callback_sink_legacy')
        if legacy is not None:
            int_node = child_of_type(legacy, 'integer')
            idx = int(text(int_node)) if int_node else 0
            return [{
                'base': BASE_CALLBACK_PARAM, 'index': idx,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': -1, 'spread_start_index': 0,
            }]

        named = child_of_type(node, 'callback_sink_named')
        if named is not None:
            ident = child_of_type(named, 'identifier')
            name = text(ident) if ident else ''
            int_node = child_of_type(named, 'integer')
            idx = int(text(int_node)) if int_node else 0
            owner = -1
            spread_start = 0
            if name in param_map:
                pidx = param_map[name]
                if params[pidx][1]:  # is_rest
                    owner = -2
                    spread_start = pidx
                else:
                    owner = pidx
            return [{
                'base': BASE_CALLBACK_PARAM, 'index': idx,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': owner, 'spread_start_index': spread_start,
            }]

        spread = child_of_type(node, 'callback_sink_spread')
        if spread is not None:
            ident = child_of_type(spread, 'identifier')
            name = text(ident) if ident else ''
            int_node = child_of_type(spread, 'integer')
            idx = int(text(int_node)) if int_node else 0
            spread_start = param_map.get(name, 0)
            return [{
                'base': BASE_CALLBACK_PARAM, 'index': idx,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': -2, 'spread_start_index': spread_start,
            }]

        return []

    def _walk_callback_source(self, node, params, param_map):
        """Walk callback_source -> list of source dicts."""
        legacy = child_of_type(node, 'callback_source_legacy')
        if legacy is not None:
            return [{
                'base': BASE_CALLBACK_RETURN, 'index': 0, 'end_index': -1,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': -1, 'spread_start_index': 0,
            }]

        named = child_of_type(node, 'callback_source_named')
        if named is not None:
            ident = child_of_type(named, 'identifier')
            name = text(ident) if ident else ''
            owner = -1
            spread_start = 0
            if name in param_map:
                pidx = param_map[name]
                if params[pidx][1]:  # is_rest
                    owner = -2
                    spread_start = pidx
                else:
                    owner = pidx
            return [{
                'base': BASE_CALLBACK_RETURN, 'index': 0, 'end_index': -1,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': owner, 'spread_start_index': spread_start,
            }]

        spread = child_of_type(node, 'callback_source_spread')
        if spread is not None:
            ident = child_of_type(spread, 'identifier')
            name = text(ident) if ident else ''
            spread_start = param_map.get(name, 0)
            return [{
                'base': BASE_CALLBACK_RETURN, 'index': 0, 'end_index': -1,
                'offset': OFF_NONE, 'prop_name': None, 'key_arg_index': -1,
                'callback_owner_arg_index': -2, 'spread_start_index': spread_start,
            }]

        return []

    # ---- Guard walking ----

    def _walk_guard(self, node, params, param_map):
        """Walk a guard node. Returns DNF: list of conjunctions (list of guard dicts)."""
        # guard has one child: the predicate expression
        for child in node.named_children:
            return self._walk_pred_expr(child, params, param_map)
        return [[]]

    def _walk_pred_expr(self, node, params, param_map):
        """Walk a predicate expression. Returns DNF."""
        t = node.type
        if t == 'pred_or':
            left = self._walk_pred_expr(node.named_children[0], params, param_map)
            right = self._walk_pred_expr(node.named_children[1], params, param_map)
            return left + right
        elif t == 'pred_and':
            left_dnf = self._walk_pred_expr(node.named_children[0], params, param_map)
            right_dnf = self._walk_pred_expr(node.named_children[1], params, param_map)
            # AND of two DNF: cross-product
            result = []
            for l_conj in left_dnf:
                for r_conj in right_dnf:
                    result.append(l_conj + r_conj)
            return result
        elif t == 'pred_not':
            inner_dnf = self._walk_pred_expr(node.named_children[0], params, param_map)
            # Negate all guards in all conjunctions
            for conj in inner_dnf:
                for g in conj:
                    g['negate'] = not g.get('negate', False)
            return inner_dnf
        elif t == 'pred_paren':
            # Walk inner expression
            for child in node.named_children:
                return self._walk_pred_expr(child, params, param_map)
            return [[]]
        elif t == 'pred_compare':
            return [[self._walk_pred_compare(node, params, param_map)]]
        elif t == 'pred_in':
            return [[self._walk_pred_in(node, params, param_map)]]
        elif t == 'pred_matches':
            return [[self._walk_pred_matches(node, params, param_map)]]
        elif t == 'pred_bool_check':
            return [[self._walk_pred_bool_check(node, params, param_map)]]
        else:
            # Might be a direct guard_expr or other
            return [[]]

    def _walk_guard_expr(self, node, params, param_map):
        """Walk guard_expr -> partial guard dict with expr_type, param_index, etc."""
        for child in node.named_children:
            t = child.type
            if t == 'expr_argc':
                return {
                    'expr_type': GEXPR_MAGIC_GLOBAL, 'magic_global_id': 0,
                    'param_index': 0, 'prop_name': None, 'magic_prop': MPROP_NA,
                }
            elif t == 'expr_is_new':
                return {
                    'expr_type': GEXPR_MAGIC_GLOBAL, 'magic_global_id': 1,
                    'param_index': 0, 'prop_name': None, 'magic_prop': MPROP_NA,
                }
            elif t == 'expr_var_lookup':
                return self._walk_expr_var_lookup(child, params, param_map)
            elif t == 'expr_locator_prop':
                return self._walk_expr_locator_prop(child, params, param_map)
            elif t == 'expr_locator_chain_prop':
                return self._walk_expr_locator_chain_prop(child, params, param_map)
        return {
            'expr_type': GEXPR_MAGIC_GLOBAL, 'magic_global_id': 0,
            'param_index': 0, 'prop_name': None, 'magic_prop': MPROP_NA,
        }

    def _walk_guard_base(self, node, params, param_map):
        """Walk a guard base. Returns (param_index,)."""
        for child in node.named_children:
            t = child.type
            if t == 'guard_base_self':
                return -1
            elif t == 'guard_base_ret':
                return -2
            elif t == 'guard_base_args':
                int_node = child_of_type(child, 'integer')
                return int(text(int_node)) if int_node else 0
            elif t == 'guard_base_name':
                ident = child_of_type(child, 'identifier')
                name = text(ident) if ident else ''
                if name in param_map:
                    return param_map[name]
                return 0
        return 0

    def _walk_expr_locator_prop(self, node, params, param_map):
        """Walk expr_locator_prop: base.prop -> guard dict."""
        # Children: guard_base, identifier (the prop)
        base_node = None
        prop_str = None
        for child in node.named_children:
            if child.type in ('guard_base_self', 'guard_base_ret', 'guard_base_args', 'guard_base_name'):
                base_node = child
            elif child.type == 'identifier':
                prop_str = text(child)

        param_index = self._resolve_guard_base(base_node, params, param_map)
        mp = MAGIC_PROP_MAP.get(prop_str, MPROP_NA)
        expr_type = GEXPR_LOCATOR_VALUE if mp == MPROP_VALUE else GEXPR_LOCATOR_MAGIC_PROP
        return {
            'expr_type': expr_type, 'magic_global_id': 0,
            'param_index': param_index, 'prop_name': None, 'magic_prop': mp,
        }

    def _walk_expr_locator_chain_prop(self, node, params, param_map):
        """Walk expr_locator_chain_prop: base.prop1.prop2 -> guard dict."""
        base_node = None
        idents = []
        for child in node.named_children:
            if child.type in ('guard_base_self', 'guard_base_ret', 'guard_base_args', 'guard_base_name'):
                base_node = child
            elif child.type == 'identifier':
                idents.append(text(child))

        param_index = self._resolve_guard_base(base_node, params, param_map)
        prop_name = idents[0] if idents else None
        mp_str = idents[1] if len(idents) > 1 else None
        mp = MAGIC_PROP_MAP.get(mp_str, MPROP_NA) if mp_str else MPROP_NA
        expr_type = GEXPR_LOCATOR_VALUE if mp == MPROP_VALUE else GEXPR_LOCATOR_MAGIC_PROP
        return {
            'expr_type': expr_type, 'magic_global_id': 0,
            'param_index': param_index, 'prop_name': prop_name, 'magic_prop': mp,
        }

    def _walk_expr_var_lookup(self, node, params, param_map):
        """Walk expr_var_lookup: var_name[key]... .prop -> guard dict.
        No `$` sigil; the leading identifier is the declared global var name."""
        idents = children_of_type(node, 'identifier')
        if not idents:
            return {
                'expr_type': GEXPR_MAGIC_GLOBAL, 'magic_global_id': 0,
                'param_index': 0, 'prop_name': None, 'magic_prop': MPROP_NA,
            }

        var_name = text(idents[0])
        var_index = self._var_idx.get(var_name, 0)

        # 1-2 set_key children
        key_nodes = children_of_type(node, 'set_key')
        var_key_sources = []
        for kn in key_nodes:
            ks = self._walk_value_source(kn, params, param_map)
            var_key_sources.append(ks)

        # Optional trailing identifier after the keys = magic property
        # The grammar is: identifier '[' set_key ']' ('[' set_key ']')? ('.' identifier)?
        # The first identifier is the var name. If there's a trailing one after '.', it's the last.
        magic_prop = MPROP_NA
        if len(idents) > 1:
            mp_str = text(idents[-1])
            magic_prop = MAGIC_PROP_MAP.get(mp_str, MPROP_NA)

        return {
            'expr_type': GEXPR_VAR_LOOKUP,
            'var_index': var_index,
            'var_key_sources': var_key_sources,
            'magic_prop': magic_prop,
            'param_index': 0,
            'prop_name': None,
            'magic_global_id': 0,
        }

    def _resolve_guard_base(self, node, params, param_map):
        """Resolve a guard base node to param_index."""
        if node is None:
            return 0
        t = node.type
        if t == 'guard_base_self':
            return -1
        elif t == 'guard_base_ret':
            return -2
        elif t == 'guard_base_args':
            int_node = child_of_type(node, 'integer')
            return int(text(int_node)) if int_node else 0
        elif t == 'guard_base_name':
            ident = child_of_type(node, 'identifier')
            name = text(ident) if ident else ''
            if name in param_map:
                return param_map[name]
            return 0
        return 0

    def _walk_pred_compare(self, node, params, param_map):
        """Walk pred_compare: expr cmp_op literal -> guard dict."""
        ge = child_of_type(node, 'guard_expr')
        g = self._walk_guard_expr(ge, params, param_map)
        # cmp_op
        cmp_node = child_of_type(node, 'cmp_op')
        cmp_op = CMP_EQ
        if cmp_node is not None:
            cmp_text = text(cmp_node).strip()
            cmp_op = CMP_OP_MAP.get(cmp_text, CMP_EQ)
        # literal
        lit_node = child_of_type(node, 'literal')
        lit = self._walk_literal(lit_node)
        g['compare_op'] = cmp_op
        g['negate'] = False
        g.update(lit)
        return g

    def _walk_pred_in(self, node, params, param_map):
        """Walk pred_in: expr in [literal_list] -> guard dict."""
        ge = child_of_type(node, 'guard_expr')
        g = self._walk_guard_expr(ge, params, param_map)
        ll = child_of_type(node, 'literal_list')
        string_set = []
        if ll is not None:
            for lit_node in children_of_type(ll, 'literal'):
                lit = self._walk_literal(lit_node)
                if lit.get('literal_type') == LIT_STRING:
                    string_set.append(lit.get('literal_string', ''))
                elif lit.get('literal_type') == LIT_INT:
                    string_set.append(str(lit.get('literal_int', 0)))
                else:
                    string_set.append('')
        g['compare_op'] = CMP_IN
        g['negate'] = False
        g['literal_type'] = LIT_STRING_SET
        g['literal_string_set'] = string_set
        g['literal_string'] = None
        g['literal_int'] = 0
        g['literal_bool'] = False
        return g

    def _walk_pred_matches(self, node, params, param_map):
        """Walk pred_matches: expr matches string -> guard dict."""
        ge = child_of_type(node, 'guard_expr')
        g = self._walk_guard_expr(ge, params, param_map)
        str_node = child_of_type(node, 'string')
        pattern = parse_string(str_node) if str_node else ''
        g['compare_op'] = CMP_MATCHES
        g['negate'] = False
        g['literal_type'] = LIT_STRING
        g['literal_string'] = pattern
        g['literal_int'] = 0
        g['literal_bool'] = False
        g['literal_string_set'] = []
        return g

    def _walk_pred_bool_check(self, node, params, param_map):
        """Walk pred_bool_check: guard_expr (treated as == true)."""
        ge = child_of_type(node, 'guard_expr')
        g = self._walk_guard_expr(ge, params, param_map)
        g['compare_op'] = CMP_EQ
        g['negate'] = False
        g['literal_type'] = LIT_BOOL
        g['literal_bool'] = True
        g['literal_string'] = None
        g['literal_int'] = 0
        g['literal_string_set'] = []
        return g

    def _walk_literal(self, node):
        """Walk a literal node. Returns dict with literal_type + value fields."""
        if node is None:
            return {'literal_type': LIT_NULL, 'literal_string': None, 'literal_int': 0,
                    'literal_bool': False, 'literal_string_set': []}
        for child in node.named_children:
            t = child.type
            if t == 'string':
                return {'literal_type': LIT_STRING, 'literal_string': parse_string(child),
                        'literal_int': 0, 'literal_bool': False, 'literal_string_set': []}
            elif t == 'integer':
                return {'literal_type': LIT_INT, 'literal_int': int(text(child)),
                        'literal_string': None, 'literal_bool': False, 'literal_string_set': []}
            elif t == 'lit_true':
                return {'literal_type': LIT_BOOL, 'literal_bool': True,
                        'literal_string': None, 'literal_int': 0, 'literal_string_set': []}
            elif t == 'lit_false':
                return {'literal_type': LIT_BOOL, 'literal_bool': False,
                        'literal_string': None, 'literal_int': 0, 'literal_string_set': []}
            elif t == 'lit_null':
                return {'literal_type': LIT_NULL, 'literal_string': None, 'literal_int': 0,
                        'literal_bool': False, 'literal_string_set': []}
        # Fallback: check if the literal node itself is an integer or string
        # (for cases where the literal wraps a terminal directly)
        return {'literal_type': LIT_NULL, 'literal_string': None, 'literal_int': 0,
                'literal_bool': False, 'literal_string_set': []}

    # ---- Overloaded rule merging ----

    def _merge_overloaded(self, raw_rules):
        """Merge rules with same (category, sig) but different argc."""
        by_key = defaultdict(list)
        result_order = []
        seen_keys = set()
        for rule_info in raw_rules:
            category, sig, params, sub_rules = rule_info
            key = (category, sig)
            by_key[key].append(rule_info)
            if key not in seen_keys:
                result_order.append(key)
                seen_keys.add(key)

        merged = []
        for key in result_order:
            group = by_key[key]
            if len(group) == 1:
                merged.append(group[0])
                continue
            # Multiple rules: merge with @argc guards
            all_sub_rules = []
            longest_params = max(group, key=lambda r: len(r[2]))[2]
            for variant in group:
                category, sig, params, sub_rules = variant
                argc = len(params)
                argc_guard = {
                    'expr_type': GEXPR_MAGIC_GLOBAL,
                    'magic_global_id': 0,  # @argc
                    'param_index': 0, 'prop_name': None,
                    'magic_prop': MPROP_NA,
                    'compare_op': CMP_EQ,
                    'negate': False,
                    'literal_type': LIT_INT,
                    'literal_int': argc,
                    'literal_string': None,
                    'literal_bool': False,
                    'literal_string_set': [],
                }
                for sr in sub_rules:
                    sr_copy = copy.deepcopy(sr)
                    sr_copy['guards'].insert(0, copy.deepcopy(argc_guard))
                    all_sub_rules.append(sr_copy)
            merged.append((group[0][0], group[0][1], longest_params, all_sub_rules))
        return merged

    # ---- String interning for sub-rules ----

    def _intern_subrule_strings(self, sr):
        """Pre-intern all strings referenced in a sub-rule."""
        for loc in sr.get('sources', []) + sr.get('sinks', []):
            if loc.get('prop_name'):
                self._intern(loc['prop_name'])
            # Var source key strings
            for vks in loc.get('var_key_sources', []):
                if vks.get('vsrc_type') == VSRC_LITERAL and vks.get('literal_string'):
                    self._intern(vks['literal_string'])
        for g in sr.get('guards', []):
            if g.get('prop_name'):
                self._intern(g['prop_name'])
            if g.get('literal_string'):
                self._intern(g['literal_string'])
            for s in g.get('literal_string_set', []):
                self._intern(s)
            # Var lookup key sources in guards
            for vks in g.get('var_key_sources', []):
                if vks.get('vsrc_type') == VSRC_LITERAL and vks.get('literal_string'):
                    self._intern(vks['literal_string'])
        # SET-specific strings
        if sr.get('action') == ACTION_SET:
            for ks in sr.get('key_sources', []):
                if ks.get('vsrc_type') == VSRC_LITERAL and ks.get('literal_string'):
                    self._intern(ks['literal_string'])
            vs = sr.get('value_source', {})
            if vs.get('vsrc_type') == VSRC_LITERAL and vs.get('literal_string'):
                self._intern(vs['literal_string'])

    # ---- Binary emission ----

    def _emit_rule(self, category, sig, sub_rules):
        """Emit one rule to binary."""
        cat = CATEGORY_MAP.get(category, 0xFF)
        buf = struct.pack('<HBB', self._intern(sig), cat, len(sub_rules))
        for sr in sub_rules:
            buf += self._emit_subrule(sr)
        return buf

    def _emit_subrule(self, sr):
        """Emit one sub-rule to binary."""
        buf = struct.pack('B', sr['action'])
        buf += struct.pack('<H', sr.get('alert_cwe', 0))
        guards = sr.get('guards', [])
        buf += struct.pack('B', len(guards))
        for g in guards:
            buf += self._emit_guard(g)
        sources = sr.get('sources', [])
        buf += struct.pack('B', len(sources))
        for s in sources:
            buf += self._emit_source(s)
        sinks = sr.get('sinks', [])
        buf += struct.pack('B', len(sinks))
        for s in sinks:
            buf += self._emit_sink(s)
        # SET-specific payload
        if sr['action'] == ACTION_SET:
            buf += struct.pack('<H', sr['var_index'])
            key_sources = sr.get('key_sources', [])
            buf += struct.pack('B', len(key_sources))
            for ks in key_sources:
                buf += self._emit_value_source(ks)
            buf += self._emit_value_source(sr['value_source'])
        return buf

    def _emit_source(self, loc):
        """Emit one source locator to binary."""
        base = loc['base']
        index = loc.get('index', 0)
        end_index = loc.get('end_index', -1)
        offset = loc.get('offset', OFF_NONE)
        buf = struct.pack('BbbB', base, index, end_index, offset)
        if offset == OFF_SPEC_PROP:
            buf += struct.pack('<H', self._intern(loc.get('prop_name', '')))
        elif offset == OFF_DYNAMIC_KEY:
            buf += struct.pack('B', loc.get('key_arg_index', 0) & 0xFF)
        # v3: callback owner for CALLBACK_PARAM/CALLBACK_RETURN
        if base in (BASE_CALLBACK_PARAM, BASE_CALLBACK_RETURN):
            owner = loc.get('callback_owner_arg_index', -1)
            buf += struct.pack('b', owner)
            if owner == -2:
                buf += struct.pack('B', loc.get('spread_start_index', 0))
        # v4: var lookup source — emit key sources after standard header
        if base == BASE_VAR_LOOKUP:
            vks = loc.get('var_key_sources', [])
            buf += struct.pack('B', len(vks))
            for ks in vks:
                buf += self._emit_value_source(ks)
        return buf

    def _emit_sink(self, loc):
        """Emit one sink locator to binary."""
        base = loc['base']
        index = loc.get('index', 0)
        offset = loc.get('offset', OFF_NONE)
        buf = struct.pack('BbB', base, index, offset)
        if offset == OFF_SPEC_PROP:
            buf += struct.pack('<H', self._intern(loc.get('prop_name', '')))
        elif offset == OFF_DYNAMIC_KEY:
            buf += struct.pack('B', loc.get('key_arg_index', 0) & 0xFF)
        # v3: callback owner for CALLBACK_PARAM/CALLBACK_RETURN
        if base in (BASE_CALLBACK_PARAM, BASE_CALLBACK_RETURN):
            owner = loc.get('callback_owner_arg_index', -1)
            buf += struct.pack('b', owner)
            if owner == -2:
                buf += struct.pack('B', loc.get('spread_start_index', 0))
        return buf

    def _emit_value_source(self, vs):
        """Emit one value source to binary."""
        buf = struct.pack('B', vs['vsrc_type'])
        if vs['vsrc_type'] in (VSRC_LOC_TAINT, VSRC_LOC_REF, VSRC_LOC_VALUE):
            buf += struct.pack('Bb', vs['base'], vs['index'])
        elif vs['vsrc_type'] == VSRC_LITERAL:
            lt = vs.get('literal_type', LIT_NULL)
            buf += struct.pack('B', lt)
            if lt == LIT_STRING:
                buf += struct.pack('<H', self._intern(vs.get('literal_string', '')))
            elif lt == LIT_INT:
                buf += struct.pack('<i', vs.get('literal_int', 0))
            elif lt == LIT_BOOL:
                buf += struct.pack('B', 1 if vs.get('literal_bool') else 0)
        return buf

    def _emit_var_table(self):
        """Emit the var table to binary."""
        buf = b''
        for name, vtype, structure, k1type, k2type in self._vars:
            buf += struct.pack('<HBB', self._intern(name), vtype, structure)
            if structure >= VAR_MAP1:
                buf += struct.pack('B', k1type)
            if structure == VAR_MAP2:
                buf += struct.pack('B', k2type)
        return buf

    def _emit_guard(self, g):
        """Emit one guard to binary."""
        expr_type = g.get('expr_type', GEXPR_MAGIC_GLOBAL)
        buf = struct.pack('B', expr_type)
        if expr_type == GEXPR_MAGIC_GLOBAL:
            buf += struct.pack('B', g.get('magic_global_id', 0))
        elif expr_type == GEXPR_VAR_LOOKUP:
            buf += struct.pack('<H', g.get('var_index', 0))
            vks = g.get('var_key_sources', [])
            buf += struct.pack('B', len(vks))
            for ks in vks:
                buf += self._emit_value_source(ks)
        else:
            buf += struct.pack('B', g.get('param_index', 0) & 0xFF)
            prop_name = g.get('prop_name')
            buf += struct.pack('<H', self._intern(prop_name) if prop_name else 0)
        buf += struct.pack('BBB',
                           g.get('magic_prop', MPROP_NA),
                           g.get('compare_op', CMP_EQ),
                           1 if g.get('negate', False) else 0)
        lt = g.get('literal_type', LIT_NULL)
        buf += struct.pack('B', lt)
        if lt == LIT_STRING:
            ls = g.get('literal_string')
            buf += struct.pack('<H', self._intern(ls) if ls else 0)
        elif lt == LIT_INT:
            buf += struct.pack('<i', g.get('literal_int', 0))
        elif lt == LIT_BOOL:
            buf += struct.pack('B', 1 if g.get('literal_bool', False) else 0)
        elif lt == LIT_NULL:
            pass
        elif lt == LIT_STRING_SET:
            ss = g.get('literal_string_set', [])
            buf += struct.pack('B', len(ss))
            for s in ss:
                buf += struct.pack('<H', self._intern(s))
        return buf

    def _emit_string_table(self):
        """Emit the string table to binary."""
        buf = struct.pack('<H', len(self._strings))
        for s in self._strings:
            enc = s.encode('utf-8')
            buf += struct.pack('<H', len(enc)) + enc
        return buf


# ---- Binary Dumper ----

def _dump_read_value_source(data, pos, strings):
    """Read one value source from binary data. Returns (description_str, new_pos)."""
    vsrc_names = ['LocTaint', 'LocRef', 'LocValue', 'Literal']
    bn = ['Self', 'Arg', 'ArgRange', 'Return', 'Global', 'CbParam', 'CbRet', 'VarLookup']
    vt = data[pos]; pos += 1
    vt_str = vsrc_names[vt] if vt < len(vsrc_names) else f'?{vt}'
    if vt in (0, 1, 2):  # VSRC_LOC_TAINT, VSRC_LOC_REF, VSRC_LOC_VALUE
        base = data[pos]; pos += 1
        index = struct.unpack_from('b', data, pos)[0]; pos += 1
        base_str = bn[base] if base < len(bn) else f'?{base}'
        return f'{vt_str}({base_str}[{index}])', pos
    elif vt == 3:  # VSRC_LITERAL
        lt = data[pos]; pos += 1
        if lt == 0:  # LIT_STRING
            si = struct.unpack_from('<H', data, pos)[0]; pos += 2
            return f'Literal("{strings[si]}")', pos
        elif lt == 1:  # LIT_INT
            val = struct.unpack_from('<i', data, pos)[0]; pos += 4
            return f'Literal({val})', pos
        elif lt == 2:  # LIT_BOOL
            val = data[pos]; pos += 1
            return f'Literal({"true" if val else "false"})', pos
        else:
            return f'Literal(null)', pos
    return f'?vsrc{vt}', pos


def dump_tbin(data):
    if data[:4] != b'TBIN':
        print(f"Error: invalid magic {data[:4]!r}")
        return
    ver = struct.unpack_from('<H', data, 4)[0]
    vc = 0  # var count
    if ver == 4:
        _flags, vc, rc = struct.unpack_from('<HHH', data, 6)
        rules_off = struct.unpack_from('<I', data, 12)[0]
        sto = struct.unpack_from('<I', data, 16)[0]
        pos = 20  # after header, start of var table
    elif ver in (2, 3):
        _flags, rc = struct.unpack_from('<HH', data, 6)
        sto = struct.unpack_from('<I', data, 10)[0]
        pos = 14
        rules_off = 14
    else:
        rc, sto = struct.unpack_from('<HI', data, 6)
        pos = 12
        rules_off = 12
    print(f"TBIN v{ver}, {rc} rules, {vc} vars, string table at 0x{sto:x}")
    strings, spos = [], sto
    ec = struct.unpack_from('<H', data, spos)[0]; spos += 2
    for _ in range(ec):
        sl = struct.unpack_from('<H', data, spos)[0]; spos += 2
        strings.append(data[spos:spos+sl].decode('utf-8')); spos += sl
    print(f"String table: {len(strings)} entries")

    # Dump var table (v4 only)
    vtn = ['number', 'string', 'bool', 'taint', 'ref']
    vsn = ['scalar', 'map1', 'map2']
    if ver == 4 and vc > 0:
        print(f"\n--- Var declarations ({vc}) ---")
        for vi in range(vc):
            name_idx = struct.unpack_from('<H', data, pos)[0]; pos += 2
            vtype = data[pos]; pos += 1
            structure = data[pos]; pos += 1
            k1_str, k2_str = '', ''
            if structure >= 1:  # VAR_MAP1 or VAR_MAP2
                k1 = data[pos]; pos += 1
                k1_str = f'[{vtn[k1] if k1 < len(vtn) else f"?{k1}"}]'
            if structure == 2:  # VAR_MAP2
                k2 = data[pos]; pos += 1
                k2_str = f'[{vtn[k2] if k2 < len(vtn) else f"?{k2}"}]'
            vtype_str = vtn[vtype] if vtype < len(vtn) else f'?{vtype}'
            struct_str = vsn[structure] if structure < len(vsn) else f'?{structure}'
            print(f"  var[{vi}] {strings[name_idx]}{k1_str}{k2_str} -> {vtype_str}  ({struct_str})")

    # Position at rules start
    pos = rules_off

    bn = ['Self', 'Arg', 'ArgRange', 'Return', 'Global', 'CbParam', 'CbRet', 'VarLookup']
    on = ['None', 'ElemShallow', 'PropShallow', 'SpecProp', 'DeepScan', 'DynKey', 'ElemDeep', 'PropDeep']
    an = ['Propagate', 'Forward', 'Clear', 'Sink', 'Preserve', 'Collapse', 'TaintSource', 'Inject', 'Extract', 'Set']
    cn = ['V8_native', 'V8_runtime', 'V8_bytecode', 'Node']
    for _ in range(rc):
        si = struct.unpack_from('<H', data, pos)[0]; pos += 2
        cat_str = ''
        if ver >= 2:
            cat = data[pos]; pos += 1
            cat_str = f' [{cn[cat] if cat < len(cn) else "Legacy"}]'
        sc = data[pos]; pos += 1
        print(f"\nrule {strings[si]}:{cat_str}  ({sc} sub-rules)")
        for si2 in range(sc):
            act = data[pos]; pos += 1
            cwe = struct.unpack_from('<H', data, pos)[0]; pos += 2
            gc = data[pos]; pos += 1
            cstr = f' @cwe({cwe})' if cwe else ''
            print(f"  [{si2}] {an[act] if act < len(an) else f'?{act}'}{cstr} guards={gc}")
            for _ in range(gc):
                et = data[pos]; pos += 1
                if et == 0:  # GEXPR_MAGIC_GLOBAL
                    pos += 1
                elif et == GEXPR_VAR_LOOKUP:  # var lookup
                    var_idx = struct.unpack_from('<H', data, pos)[0]; pos += 2
                    vkc = data[pos]; pos += 1
                    vk_strs = []
                    for _ in range(vkc):
                        vs_str, pos = _dump_read_value_source(data, pos, strings)
                        vk_strs.append(vs_str)
                    print(f"      guard: VarLookup var[{var_idx}] keys=[{', '.join(vk_strs)}]", end='')
                else:
                    pos += 3  # param_index(1) + prop_name(2)
                # magic_prop, compare_op, negate
                mp = data[pos]; pos += 1
                cmp_op = data[pos]; pos += 1
                neg = data[pos]; pos += 1
                if et == GEXPR_VAR_LOOKUP:
                    print(f" mp={mp} cmp={cmp_op} neg={neg}", end='')
                lt = data[pos]; pos += 1
                if lt == 0: pos += 2
                elif lt == 1: pos += 4
                elif lt == 2: pos += 1
                elif lt == 4: cnt = data[pos]; pos += 1; pos += cnt * 2
                if et == GEXPR_VAR_LOOKUP:
                    print()  # end line
            src_c = data[pos]; pos += 1
            for _ in range(src_c):
                b, idx, eidx = data[pos], struct.unpack_from('b', data, pos+1)[0], struct.unpack_from('b', data, pos+2)[0]
                off = data[pos+3]; pos += 4; extra = ''
                if off == 3: pi = struct.unpack_from('<H', data, pos)[0]; pos += 2; extra = f' .{strings[pi]}'
                elif off == 5: extra = f' [dyn:{data[pos]}]'; pos += 1
                if ver >= 3 and b in (5, 6):
                    owner = struct.unpack_from('b', data, pos)[0]; pos += 1
                    extra += f' owner={owner}'
                    if owner == -2:
                        spread_start = data[pos]; pos += 1
                        extra += f' spread_start={spread_start}'
                if ver >= 4 and b == 7:  # kVarLookup
                    vkc = data[pos]; pos += 1
                    vk_strs = []
                    for _ in range(vkc):
                        vs_str, pos = _dump_read_value_source(data, pos, strings)
                        vk_strs.append(vs_str)
                    extra += f' keys=[{", ".join(vk_strs)}]'
                print(f"    src: {bn[b] if b < len(bn) else f'?{b}'}[{idx}:{eidx}] {on[off] if off < len(on) else f'?{off}'}{extra}")
            snk_c = data[pos]; pos += 1
            for _ in range(snk_c):
                b, idx = data[pos], struct.unpack_from('b', data, pos+1)[0]
                off = data[pos+2]; pos += 3; extra = ''
                if off == 3: pi = struct.unpack_from('<H', data, pos)[0]; pos += 2; extra = f' .{strings[pi]}'
                elif off == 5: extra = f' [dyn:{data[pos]}]'; pos += 1
                if ver >= 3 and b in (5, 6):
                    owner = struct.unpack_from('b', data, pos)[0]; pos += 1
                    extra += f' owner={owner}'
                    if owner == -2:
                        spread_start = data[pos]; pos += 1
                        extra += f' spread_start={spread_start}'
                print(f"    sink: {bn[b] if b < len(bn) else f'?{b}'}[{idx}] {on[off] if off < len(on) else f'?{off}'}{extra}")
            # SET-specific payload
            if act == ACTION_SET:
                var_idx = struct.unpack_from('<H', data, pos)[0]; pos += 2
                ksc = data[pos]; pos += 1
                ks_strs = []
                for _ in range(ksc):
                    vs_str, pos = _dump_read_value_source(data, pos, strings)
                    ks_strs.append(vs_str)
                val_str, pos = _dump_read_value_source(data, pos, strings)
                print(f"    SET var[{var_idx}][{', '.join(ks_strs)}] = {val_str}")


# ---- CLI ----

def main():
    ap = argparse.ArgumentParser(description='Mystra Compiler (tree-sitter) -- .tsl to .tbin')
    ap.add_argument('input', help='Input .tsl or .tbin (with --dump)')
    ap.add_argument('-o', '--output', help='Output .tbin file')
    ap.add_argument('--dump', action='store_true', help='Pretty-print .tbin')
    ap.add_argument('--verbose', action='store_true', help='Print stats')
    args = ap.parse_args()
    if args.dump:
        dump_tbin(Path(args.input).read_bytes())
        return
    source = Path(args.input).read_text()
    compiler = TSLCompiler()
    data = compiler.compile(source)
    out = args.output or args.input.rsplit('.', 1)[0] + '.tbin'
    Path(out).write_bytes(data)
    if args.verbose:
        print(f"Compiled {compiler.rule_count} rules, {compiler.subrule_count} sub-rules -> {out} ({len(data)} bytes)", file=sys.stderr)
        print(f"String table: {len(compiler.strings)} entries", file=sys.stderr)
    else:
        print(f"Compiled {compiler.rule_count} rules -> {out} ({len(data)} bytes)")


if __name__ == '__main__':
    main()
