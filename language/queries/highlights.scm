; highlights.scm — Tree-sitter highlight queries for Mystra

; Structural keywords
["rule" "let"] @keyword

; Action keywords (lowercase, paper-faithful)
["propagate" "forward" "inject" "extract" "sink"
 "collapse" "source" "clear" "preserve" "set"] @keyword.operator

; Guard keywords
["where" "and" "or" "not" "in" "matches"] @keyword

; Value / declaration types
(var_value_type) @type

; Constants
(lit_true) @constant.builtin
(lit_false) @constant.builtin
(lit_null) @constant.builtin

; Magic names (anonymous tokens)
["@self" "@ret" "@args" "@cwe" "@callback.param" "@engine"] @variable.builtin

; Magic names that are single-literal rules (only the named node is queryable)
[(expr_argc) (expr_is_new) (callback_source_legacy)] @variable.builtin

; Function signature
(func_sig) @function

; Parameters
(single_param (identifier) @variable.parameter)
(rest_param (identifier) @variable.parameter)

; Operators
["->" ":" ";" "==" "!=" ">=" "<=" ">" "<" "="] @operator
["[" "]" "(" ")" "," "..."] @punctuation.bracket
["*" "**"] @operator

; Callback references
(callback_sink_named (identifier) @variable.parameter)
(callback_source_named (identifier) @variable.parameter)

; Guard properties
(expr_locator_prop (identifier) @property)
(expr_locator_chain_prop (identifier) @property)

; Literals
(integer) @number
(string) @string
(comment) @comment

; Annotation
(annotation (identifier) @string)
