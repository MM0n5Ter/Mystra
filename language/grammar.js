// grammar.js — Tree-sitter grammar for Mystra v3.3
//
// Mystra is a declarative rule language for specifying taint propagation
// in dynamic taint analysis engines. Rules map API functions to taint
// flow actions (propagate, inject, extract, sink, etc.).
//
// Surface syntax (paper-faithful):
//   - Action keywords are lowercase: propagate, source, sink, inject,
//     extract, set, clear, forward, collapse, preserve.
//   - Rules have NO terminator. A rule body is a sequence of sub-rules,
//     delimited purely by keyword disjointness: a sub-rule always begins
//     with an action keyword, and a body ends at the next `rule` / `@engine`
//     / `let` / EOF. Newlines are insignificant (whitespace); sub-rules may
//     appear one-per-line or on the same line.
//   - Global-store variables are referenced WITHOUT a `$` sigil. A bare
//     name is a var read iff it was declared with `let` (belonging analysis
//     performed by the compiler); otherwise it is an object locator. The two
//     share the same surface form on purpose (cf. Algorithm 1: x in Globals).
//   - `let` declarations keep a trailing `;` (paper: `let x[..] -> t ;`).
//   - Comments start with `#`.

module.exports = grammar({
  name: 'tsl',

  // Newlines are insignificant: rule/body boundaries come from keyword
  // disjointness, not line structure.
  extras: $ => [/[ \t\r\n]/, $.comment],

  word: $ => $.identifier,

  rules: {
    source_file: $ => repeat(choice($.annotated_rule, $.var_decl)),

    annotated_rule: $ => seq(
      repeat($.annotation),
      $.rule_decl
    ),

    annotation: $ => seq('@engine', '(', $.identifier, ')'),

    // Variable declarations — persistent global state for the Shadow VM.
    // Keyword is `let`; node name kept as var_decl for compiler stability.
    var_decl: $ => seq('let', $.identifier, optional($.var_key_spec), '->', $.var_value_type, ';'),
    var_key_spec: $ => choice(
      $.var_key_map2,
      $.var_key_map1,
    ),
    var_key_map2: $ => seq('[', $.var_value_type, ']', '[', $.var_value_type, ']'),
    var_key_map1: $ => seq('[', $.var_value_type, ']'),
    var_value_type: $ => choice('number', 'string', 'bool', 'taint', 'ref'),

    // A rule has no terminator; the body is delimited by keyword disjointness.
    rule_decl: $ => seq(
      'rule',
      $.func_sig,
      optional($.param_list),
      ':',
      $.rule_body
    ),

    // Body greedily consumes sub-rules. It ends when the next token cannot
    // start a sub-rule (i.e. `rule` / `@engine` / `let` / EOF).
    rule_body: $ => repeat1($.sub_rule),

    sub_rule: $ => choice(
      $.propagate_rule,
      $.forward_rule,
      $.inject_rule,
      $.extract_rule,
      $.sink_rule,
      $.collapse_rule,
      $.taint_source_rule,
      $.clear_rule,
      $.preserve_rule,
      $.set_rule,
    ),

    propagate_rule: $ => seq('propagate', $.source_list, '->', $.sink_list, optional($.guard)),
    forward_rule:   $ => seq('forward', $.source_list, '->', $.sink_list, optional($.guard)),
    inject_rule:    $ => seq('inject', $.source_list, '->', $.callback_sink, optional($.guard)),
    extract_rule:   $ => seq('extract', $.callback_source, '->', $.sink_list, optional($.guard)),
    sink_rule:      $ => seq('sink', $.source_list, $.alert_anno, optional($.guard)),
    collapse_rule:  $ => seq('collapse', $.source_list, '->', $.sink_list, optional($.guard)),
    taint_source_rule: $ => seq('source', '->', $.sink_list, optional($.guard)),
    clear_rule:     $ => seq('clear', optional($.guard)),
    preserve_rule:  $ => seq('preserve', optional($.guard)),
    set_rule:       $ => seq('set', $.set_target, '=', $.set_value, optional($.guard)),

    // SET target: var_name or var_name[key] or var_name[key1][key2].
    // No `$` sigil — belonging analysis resolves whether the base is a
    // declared global (var write) or an object locator.
    set_target: $ => seq($.identifier, optional(seq('[', $.set_key, ']',
                        optional(seq('[', $.set_key, ']'))))),
    set_key: $ => choice($.set_loc_ref, $.set_loc_value, $.literal),
    set_value: $ => choice($.set_loc_taint, $.set_loc_ref, $.set_loc_value, $.literal),
    set_loc_taint: $ => seq($._base, '.taint'),
    set_loc_ref:   $ => seq($._base, '.ref'),
    set_loc_value: $ => seq($._base, '.value'),

    // Function signature: V8_native::Foo or Node::fs.readFile
    func_sig: $ => seq(
      $.identifier,
      repeat(seq(choice('::', '.'), $.identifier))
    ),

    param_list: $ => seq('(', $._param_items, ')'),
    _param_items: $ => seq($.param, repeat(seq(',', $.param))),
    param: $ => choice(
      $.rest_param,
      $.single_param,
    ),
    rest_param: $ => seq('...', $.identifier),
    single_param: $ => $.identifier,

    // Locator lists. A source item is a plain locator; a bare name that was
    // declared with `let` is resolved to a var read by the compiler.
    source_list: $ => seq($.locator, repeat(seq(',', $.locator))),
    sink_list:   $ => seq($.locator, repeat(seq(',', $.locator))),

    // Locator: base + optional path
    locator: $ => seq($._base, optional($._path)),

    _base: $ => choice(
      $.base_self,
      $.base_ret,
      $.base_args,
      $.base_name,
    ),

    base_self: $ => '@self',
    base_ret:  $ => '@ret',
    base_args: $ => seq('@args', '[', $.slice_expr, ']'),
    base_name: $ => $.identifier,

    slice_expr: $ => choice(
      $.slice_range,
      $.slice_open,
      $.slice_single,
    ),
    slice_range:  $ => seq($.integer, ':', $.integer),
    slice_open:   $ => seq($.integer, ':'),
    slice_single: $ => $.integer,

    _path: $ => choice(
      $.path_elem_shallow,
      $.path_elem_deep,
      $.path_prop_shallow,
      $.path_prop_deep,
      $.path_specific_prop,
      $.path_dyn_key,
    ),

    path_elem_shallow: $ => seq('[', '*', ']'),
    path_elem_deep:    $ => seq('[', '**', ']'),
    path_prop_shallow: $ => seq('.', '*'),
    path_prop_deep:    $ => seq('.', '**'),
    path_specific_prop: $ => seq('.', $.identifier),
    path_dyn_key:      $ => seq('[', $._dyn_key_inner, ']'),

    // A dynamic key may be an arg ref, a plain name, a string, or a
    // var-store accessor (`name.value` / `name.ref` / `name.taint`) used for
    // keying global stores, e.g. `filelist[path.value]`.
    _dyn_key_inner: $ => choice(
      $.dyn_key_args,
      $.dyn_key_loc,
      $.dyn_key_name,
      $.dyn_key_literal,
    ),
    dyn_key_args: $ => seq('@args', '[', $.integer, ']'),
    dyn_key_loc:  $ => seq($.identifier, choice('.value', '.ref', '.taint')),
    dyn_key_name: $ => $.identifier,
    dyn_key_literal: $ => $.string,

    // Callback references (named + legacy + spread)
    callback_sink: $ => choice(
      $.callback_sink_legacy,
      $.callback_sink_named,
      $.callback_sink_spread,
    ),
    callback_sink_legacy: $ => seq('@callback.param', '[', $.integer, ']'),
    callback_sink_named:  $ => seq($.identifier, '.param', '[', $.integer, ']'),
    callback_sink_spread: $ => seq($.identifier, '[', '*', ']', '.param', '[', $.integer, ']'),

    callback_source: $ => choice(
      $.callback_source_legacy,
      $.callback_source_named,
      $.callback_source_spread,
    ),
    callback_source_legacy: $ => '@callback.ret',
    callback_source_named:  $ => seq($.identifier, '.ret'),
    callback_source_spread: $ => seq($.identifier, '[', '*', ']', '.ret'),

    // Alert annotation
    alert_anno: $ => seq('@cwe', '(', $.integer, ')'),

    // Guard clause
    guard: $ => seq('where', $._or_expr),

    _or_expr:  $ => choice($.pred_or, $._and_expr),
    pred_or:   $ => prec.left(1, seq($._or_expr, 'or', $._and_expr)),

    _and_expr: $ => choice($.pred_and, $._not_expr),
    pred_and:  $ => prec.left(2, seq($._and_expr, 'and', $._not_expr)),

    _not_expr: $ => choice($.pred_not, $._atom_pred, $.pred_paren),
    pred_not:  $ => seq('not', $._not_expr),
    pred_paren: $ => seq('(', $._or_expr, ')'),

    _atom_pred: $ => choice(
      $.pred_compare,
      $.pred_in,
      $.pred_matches,
      $.pred_bool_check,
    ),
    pred_compare:   $ => seq($.guard_expr, $.cmp_op, $.literal),
    pred_in:        $ => seq($.guard_expr, 'in', '[', $.literal_list, ']'),
    pred_matches:   $ => seq($.guard_expr, 'matches', $.string),
    pred_bool_check: $ => $.guard_expr,

    guard_expr: $ => choice(
      $.expr_argc,
      $.expr_is_new,
      $.expr_var_lookup,
      $.expr_locator_chain_prop,
      $.expr_locator_prop,
    ),
    // Var-store lookup in a guard: name[key]... .prop (no `$` sigil).
    expr_var_lookup: $ => prec(3, seq($.identifier, '[', $.set_key, ']',
                              optional(seq('[', $.set_key, ']')),
                              optional(seq('.', $.identifier)))),
    expr_argc:  $ => '@argc',
    expr_is_new: $ => '@is_new',
    expr_locator_chain_prop: $ => seq($._guard_base, '.', $.identifier, '.', $.identifier),
    expr_locator_prop: $ => seq($._guard_base, '.', $.identifier),

    _guard_base: $ => choice(
      $.guard_base_self,
      $.guard_base_ret,
      $.guard_base_args,
      $.guard_base_name,
    ),
    guard_base_self: $ => '@self',
    guard_base_ret:  $ => '@ret',
    guard_base_args: $ => seq('@args', '[', $.integer, ']'),
    guard_base_name: $ => $.identifier,

    // Comparison operators
    cmp_op: $ => choice('==', '!=', '>=', '<=', '>', '<'),

    // Literals
    literal: $ => choice($.string, $.integer, $.lit_true, $.lit_false, $.lit_null),
    lit_true:  $ => 'true',
    lit_false: $ => 'false',
    lit_null:  $ => 'null',

    literal_list: $ => seq($.literal, repeat(seq(',', $.literal))),

    // Terminals
    comment: $ => token(seq('#', /[^\n]*/)),
    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,
    integer: $ => /-?[0-9]+/,
    string: $ => seq('"', repeat(choice(/[^"\\]/, seq('\\', /./))), '"'),
  }
});
