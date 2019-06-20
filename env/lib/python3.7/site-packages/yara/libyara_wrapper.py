"""
A ctypes wrapper to libyara.dll or libyara.so version 1.6

Note: read the ctypes wrapper README to see details on how to extend
      yara-1.6 to free matched results after each scan...

[mjdorma@gmail.com]
"""
import sys
import os

import ctypes
from ctypes import *


#define yara.h

MAX_PATH                               = 1024

MAX_INCLUDE_DEPTH                      = 16
LEX_BUF_SIZE                           = 1024

STRING_FLAGS_FOUND                     = 0x01
STRING_FLAGS_REFERENCED                = 0x02
STRING_FLAGS_HEXADECIMAL               = 0x04
STRING_FLAGS_NO_CASE                   = 0x08
STRING_FLAGS_ASCII                     = 0x10
STRING_FLAGS_WIDE                      = 0x20
STRING_FLAGS_REGEXP                    = 0x40
STRING_FLAGS_FULL_WORD                 = 0x80
STRING_FLAGS_ANONYMOUS                 = 0x100
STRING_FLAGS_FAST_MATCH                = 0x200

def IS_HEX(flags):
    return flags & STRING_FLAGS_HEXADECIMAL
def IS_NO_CASE(flags):
    return flags & STRING_FLAGS_NO_CASE
def IS_ASCII(flags):
    return flags & STRING_FLAGS_ASCII
def IS_WIDE(flags):
    return flags & STRING_FLAGS_WIDE
def IS_REGEXP(flags):
    return flags & STRING_FLAGS_REGEXP
def IS_FULL_WORD(flags):
    return flags & STRING_FLAGS_FULL_WORD
def IS_ANONYMOUS(flags):
    return flags & STRING_FLAGS_ANONYMOUS

RULE_FLAGS_MATCH                       = 0x01
RULE_FLAGS_PRIVATE                     = 0x02
RULE_FLAGS_GLOBAL                      = 0x04
RULE_FLAGS_REQUIRE_EXECUTABLE          = 0x08
RULE_FLAGS_REQUIRE_FILE                = 0x10

ERROR_SUCCESS                          = 0

ERROR_INSUFICIENT_MEMORY               = 1
ERROR_DUPLICATE_RULE_IDENTIFIER        = 2
ERROR_INVALID_CHAR_IN_HEX_STRING       = 3
ERROR_MISMATCHED_BRACKET               = 4
ERROR_SKIP_AT_END                      = 5
ERROR_INVALID_SKIP_VALUE               = 6
ERROR_UNPAIRED_NIBBLE                  = 7
ERROR_CONSECUTIVE_SKIPS                = 8
ERROR_MISPLACED_WILDCARD_OR_SKIP       = 9
ERROR_UNDEFINED_STRING                 = 10
ERROR_UNDEFINED_IDENTIFIER             = 11
ERROR_COULD_NOT_OPEN_FILE              = 12
ERROR_INVALID_REGULAR_EXPRESSION       = 13
ERROR_SYNTAX_ERROR                     = 14
ERROR_DUPLICATE_TAG_IDENTIFIER         = 15
ERROR_UNREFERENCED_STRING              = 16
ERROR_DUPLICATE_STRING_IDENTIFIER      = 17
ERROR_CALLBACK_ERROR                   = 18
ERROR_MISPLACED_OR_OPERATOR            = 19
ERROR_INVALID_OR_OPERATION_SYNTAX      = 20
ERROR_SKIP_INSIDE_OR_OPERATION         = 21
ERROR_NESTED_OR_OPERATION              = 22
ERROR_MISPLACED_ANONYMOUS_STRING       = 23
ERROR_COULD_NOT_MAP_FILE               = 24
ERROR_ZERO_LENGTH_FILE                 = 25
ERROR_INVALID_ARGUMENT                 = 26
ERROR_DUPLICATE_META_IDENTIFIER        = 27
ERROR_INCLUDES_CIRCULAR_REFERENCE      = 28
ERROR_INCORRECT_VARIABLE_TYPE          = 29
ERROR_COULD_NOT_ATTACH_TO_PROCESS      = 30
ERROR_VECTOR_TOO_LONG                  = 31
ERROR_INCLUDE_DEPTH_EXCEEDED           = 32

META_TYPE_INTEGER                      = 1
META_TYPE_STRING                       = 2
META_TYPE_BOOLEAN                      = 3

VARIABLE_TYPE_INTEGER                  = 1
VARIABLE_TYPE_STRING                   = 2
VARIABLE_TYPE_BOOLEAN                  = 3

CALLBACK_CONTINUE                      = 0
CALLBACK_ABORT                         = 1
CALLBACK_ERROR                         = 2


class MATCH(Structure):
    pass
MATCH._fields_ = [
            ('offset', c_size_t),
            ('data', c_char_p),
            ('length', c_int),
            ('next', POINTER(MATCH)),
            ]


class REGEXP(Structure):
    pass
REGEXP._fields_ = [
            ('regexp', c_void_p),
            ('extra', c_void_p),
            ]


class MASK_REGEXP(Union):
    _fields_ = [
            ('mask', c_char_p),
            ('re', REGEXP),
            ]


class STRING(Structure):
    pass
STRING._fields_ = [
            ('flags', c_int),
            ('identifier', c_char_p),
            ('length', c_uint),
            ('string', c_char_p),
            ('mask_re', MASK_REGEXP),
            ('matches_head', POINTER(MATCH)),
            ('matches_tail', POINTER(MATCH)),
            ('next', POINTER(STRING)),
            ]


class SIB(Union):
    _fields_ = [
            ('string', c_char_p),
            ('integer', c_size_t),
            ('boolean', c_int),
            ]


class VARIABLE(Structure):
    pass
VARIABLE._fields_ = [
            ('identifier', c_char_p),
            ('value', SIB),
            ('next', POINTER(VARIABLE)),
            ]


class TAG(Structure):
    pass
TAG._fields_ = [
            ('identifier', c_char_p),
            ('next', POINTER(TAG)),
            ]


class TERM(Structure):
    pass
TERM._fields_ = [
            ('type', c_int),
            ]


class NAMESPACE(Structure):
    pass
NAMESPACE._fields_ = [
            ('name', c_char_p),
            ('global_rules_satisfied', c_int),
            ('next', POINTER(NAMESPACE)),
            ]


class META(Structure):
    pass
META._fields_ = [
            ('type', c_int),
            ('identifier', c_char_p),
            ('value', SIB),
            ('next', POINTER(META)),
            ]


class RULE(Structure):
    pass
RULE._fields_ = [
            ('identifier', c_char_p),
            ('flags', c_int),
            ('ns', POINTER(NAMESPACE)),
            ('string_list_head', POINTER(STRING)),
            ('tag_list_head', POINTER(TAG)),
            ('meta_list_head', POINTER(META)),
            ('condition', POINTER(TERM)),
            ('next', POINTER(RULE)),
            ]


class STRING_LIST_ENTRY(Structure):
    pass
STRING_LIST_ENTRY._fields_ = [
            ('string', POINTER(STRING)),
            ('next', POINTER(STRING_LIST_ENTRY)),
            ]


class RULE_LIST_ENTRY(Structure):
    pass
RULE_LIST_ENTRY._fields_ = [
            ('rule', POINTER(RULE)),
            ('next', POINTER(RULE_LIST_ENTRY)),
            ]


RULE_LIST_HASH_TABLE_SIZE = 10007
class RULE_LIST(Structure):
    pass
RULE_LIST._fields_ = [
            ('head', POINTER(RULE)),
            ('tail', POINTER(RULE)),
            ('hash_table', (RULE_LIST_ENTRY * RULE_LIST_HASH_TABLE_SIZE)),
            ]


class HASH_TABLE(Structure):
    pass
HASH_TABLE._fields_ = [
            ('hashed_strings_2b', ((POINTER(STRING_LIST_ENTRY) * 256) * 256)),
            ('hashed_strings_1b', (POINTER(STRING_LIST_ENTRY) * 256)),
            ('non_hashed_strings', POINTER(STRING_LIST_ENTRY)),
            ('populated', c_int),
            ]


class MEMORY_BLOCK(Structure):
    pass
MEMORY_BLOCK._fields_ = [
            ('data', c_char_p),
            ('size', c_size_t),
            ('base', c_size_t),
            ('next', POINTER(MEMORY_BLOCK)),
            ]


#YARACALLBACK = CFUNCTYPE(c_int, POINTER(RULE), py_object)
YARACALLBACK = CFUNCTYPE(c_int, POINTER(RULE), c_void_p)
YARAREPORT = CFUNCTYPE(None, c_char_p, c_int, c_char_p)
def error_report_function(filename, line_number, error_message):
    if not filename:
        filename = "??"
    print("%s:%s: %s" % (filename, line_number, error_message))
error_report_function = YARAREPORT(error_report_function)


class YARA_CONTEXT(Structure):
    pass
YARA_CONTEXT._fields_ = [
            ('last_result', c_int),
            ('error_report_function', YARAREPORT),
            ('errors', c_int),
            ('last_error', c_int),
            ('last_error_line', c_int),

            ('rule_list', RULE_LIST),
            ('hash_table', HASH_TABLE),

            ('namespaces', POINTER(NAMESPACE)),
            ('current_namespace', POINTER(NAMESPACE)),

            ('variables', POINTER(VARIABLE)),

            ('current_rule_strings', POINTER(STRING)),
            ('current_rule_flags', c_int),
            ('inside_for', c_int),

            ('file_name_stack', (c_char_p * MAX_INCLUDE_DEPTH)),
            ('file_name_stack_ptr', c_int),

            ('file_stack', (c_void_p * MAX_INCLUDE_DEPTH)),
            ('file_stack_prt', c_int),

            ('last_error_extra_info', (c_char * 256)),

            ('lex_buf', (c_char * LEX_BUF_SIZE)),
            ('lex_buf_ptr', c_char_p),
            ('lex_buf_len', c_ushort),

            ('fast_match', c_int),
            ('allow_includes', c_int),
            ('scanning_process_memory', c_int),

            ('include_base_dir', (c_char * MAX_PATH)),
            ]


#Import libyara
if sys.platform == 'win32':
    dllpath = os.path.join(sys.prefix, 'DLLs')
    library = os.path.join(dllpath, 'libyara.dll')
else:
    dllpath = os.path.join(sys.prefix, 'lib')
    library = os.path.join(dllpath, 'libyara.so')

tmp = os.environ['PATH']
os.environ['PATH'] += ";%s" % dllpath
try:
    libyaradll = cdll.LoadLibrary(library)
except Exception as err:
    print("Failed to import '%s'" % library)
    print("PATH = %s" % os.environ['PATH'])
    raise
os.environ['PATH'] = tmp


#error handling sweetness
class YaraSyntaxError(Exception):
    pass

class YaraCallbackError(Exception):
    pass

class YaraMatchError(Exception):
    pass


#convert unicode to ascii if we're in 3x
if sys.version_info[0] < 3: #major
    def tobyte(s):
        return s
else:
    def tobyte(s):
        if type(s) is bytes:
            return s
        else:
            return s.encode('utf-8', errors='ignore')


if sys.version_info[0] < 3: #major
    def frombyte(s):
        return s
else:
    def frombyte(s):
        if type(s) is bytes:
            return str(s.decode(encoding='utf-8', errors='ignore'))
        else:
            return s


#Define libyara's function prototypes

#RULE*             lookup_rule(RULE_LIST* rules,
#                              const char* identifier,
#                              NAMESPACE* ns);
libyaradll.lookup_rule.restype = POINTER(RULE)
libyaradll.lookup_rule.argtypes = [POINTER(RULE_LIST),
                                c_char_p,
                                POINTER(NAMESPACE)]
def lookup_rule(rules, name, namespace):
    return libyaradll.lookup_rule(rules, tobyte(name), namespace)


#STRING*           lookup_string(STRING* string_list_head,
#                               const char* identifier);
libyaradll.lookup_string.restype = POINTER(STRING)
libyaradll.lookup_string.argtypes = [POINTER(STRING),
                                  c_char_p]
def lookup_string(head, name):
    return libyaradll.lookup_string(head, tobyte(name))


#TAG*              lookup_tag(TAG* tag_list_head, const char* identifier);
libyaradll.lookup_tag.restype = POINTER(TAG)
libyaradll.lookup_tag.argtypes = [POINTER(TAG), c_char_p]
def lookup_tag(head, name):
    return libyaradll.lookup_tag(head, tobyte(name))


#META*             lookup_meta(META* meta_list_head, const char* identifier);
libyaradll.lookup_meta.restype = POINTER(META)
libyaradll.lookup_meta.argtypes = [POINTER(META), c_char_p]
def lookup_meta(head, name):
    return libyaradll.lookup_meta(head, tobyte(name))


#VARIABLE*         lookup_variable(VARIABLE* _list_head,
#                                  const char* identifier);
libyaradll.lookup_variable.restype = POINTER(VARIABLE)
libyaradll.lookup_variable.argtypes = [POINTER(VARIABLE), c_char_p]
def lookup_variable(head, name):
    return libyaradll.lookup_variable(head, tobyte(name))


#YARA_CONTEXT*     yr_create_context();
libyaradll.yr_create_context.restype = POINTER(YARA_CONTEXT)
libyaradll.yr_create_context.argtypes = []
yr_create_context = libyaradll.yr_create_context


#void              yr_destroy_context(YARA_CONTEXT* context);
libyaradll.yr_destroy_context.restype = None
libyaradll.yr_destroy_context.argtypes = [POINTER(YARA_CONTEXT)]
yr_destroy_context = libyaradll.yr_destroy_context


#int               yr_calculate_rules_weight(YARA_CONTEXT* context);
libyaradll.yr_calculate_rules_weight.restype = c_int
libyaradll.yr_calculate_rules_weight.argtypes = [POINTER(YARA_CONTEXT)]
yr_calculate_rules_weight = libyaradll.yr_calculate_rules_weight


#NAMESPACE*        yr_create_namespace(YARA_CONTEXT* context,
#                                      const char* name);
libyaradll.yr_create_namespace.restype = POINTER(NAMESPACE)
libyaradll.yr_create_namespace.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_create_namespace(context, name):
    return libyaradll.yr_create_namespace(context, tobyte(name))


#int               yr_define_integer_variable(YARA_CONTEXT* context,
#                                             const char* identifier,
#                                             size_t value);
libyaradll.yr_define_integer_variable.restype = c_int
libyaradll.yr_define_integer_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_size_t]
def yr_define_integer_variable(context, name, value):
    return libyaradll.yr_define_integer_variable(context, tobyte(name), value)


#int               yr_define_boolean_variable(YARA_CONTEXT* context,
#                                             const char* identifier,
#                                             int value);
libyaradll.yr_define_boolean_variable.restype = c_int
libyaradll.yr_define_boolean_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_size_t]
def yr_define_boolean_variable(context, name, value):
    return libyaradll.yr_define_boolean_variable(context, tobyte(name), value)


#int               yr_define_string_variable(YARA_CONTEXT* context,
#                                            const char* identifier,
#                                            const char* value);
libyaradll.yr_define_string_variable.restype = c_int
libyaradll.yr_define_string_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_char_p]
def yr_define_string_variable(context, name, value):
    return libyaradll.yr_define_string_variable(context, tobyte(name),
            tobyte(value))


#int               yr_undefine_variable(YARA_CONTEXT* context,
#                                       const char* identifier);
libyaradll.yr_undefine_variable.restype = c_int
libyaradll.yr_undefine_variable.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_undefine_variable(context, name):
    return libyaradll.yr_undefine_variable(context, tobyte(name))


#char*             yr_get_current_file_name(YARA_CONTEXT* context);
libyaradll.yr_get_current_file_name.restype = c_char_p
libyaradll.yr_get_current_file_name.argtypes = [POINTER(YARA_CONTEXT)]
def yr_get_current_file_name(context):
    return frombyte(libyaradll.yr_get_current_file_name(context))


#int               yr_push_file_name(YARA_CONTEXT* context,
#                                    const char* file_name);
libyaradll.yr_push_file_name.restype = c_int
libyaradll.yr_push_file_name.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_push_file_name(context, name):
    return libyaradll.yr_push_file_name(context, tobyte(name))


#void              yr_pop_file_name(YARA_CONTEXT* context);
libyaradll.yr_pop_file_name.restype = None
libyaradll.yr_pop_file_name.argtypes = [POINTER(YARA_CONTEXT)]
yr_pop_file_name = libyaradll.yr_pop_file_name

#int               yr_push_file(YARA_CONTEXT* context, FILE* fh);

#FILE*             yr_pop_file(YARA_CONTEXT* context);

#int               yr_compile_string(const char* rules_string,
#                                   YARA_CONTEXT* context);
libyaradll.yr_compile_string.restype = c_int
libyaradll.yr_compile_string.argtypes = [c_char_p, POINTER(YARA_CONTEXT)]
def yr_compile_string(rules_string, context):
    errors = libyaradll.yr_compile_string(tobyte(rules_string), context)
# TODO:  Couldn't easily identify the yara filename for this error
#        -->> now handled in rules.py with the self._error_reports check
    if errors:
        error_line = context.contents.last_error_line
        error_message = (c_char * 256)()
        yr_get_error_message(context, error_message, 256)
        filename = yr_get_current_file_name(context)
        return (filename, error_line, error_message.value)
#       #filename = context.contents.file_name_stack[context.contents.file_name_stack_ptr - 1 ]
#       msg = "Error %s:%s %s" % (filename, error_line, error_message.value)
#       raise YaraSyntaxError(msg)


#int               yr_compile_file(FILE* rules_file, YARA_CONTEXT* context);
def yr_compile_file(rules_file, context):
    with open(rules_file, 'rb') as f:
        rules_string = f.read()
    return yr_compile_string(rules_string, context)


#int               yr_scan_mem(unsigned char* buffer,
#                             size_t buffer_size,
#                             YARA_CONTEXT* context,
#                             YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_mem.restype = c_int
libyaradll.yr_scan_mem.argtypes = [c_char_p, c_size_t,
                                POINTER(YARA_CONTEXT),
                                c_void_p, c_void_p]
def yr_scan_mem(data, *args):
    ret = libyaradll.yr_scan_mem(*([tobyte(data)] + list(args)))
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        raise Exception("Unknown error occurred")


#int               yr_scan_file(const char* file_path,
#                               YARA_CONTEXT* context,
#                               YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_file.restype = c_int
libyaradll.yr_scan_file.argtypes = [c_char_p,
                                POINTER(YARA_CONTEXT),
                                c_void_p, c_void_p]
def yr_scan_file(path, *args):
    ret = libyaradll.yr_scan_file(*([tobyte(path)] + list(args)))
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        if ret == ERROR_COULD_NOT_OPEN_FILE:
            raise YaraMatchError("Could not open file '%s'" % path)
        elif ret == ERROR_COULD_NOT_MAP_FILE:
            raise YaraMatchError("Could not map file '%s'" % path)
        elif ret == ERROR_ZERO_LENGTH_FILE:
            raise YaraMatchError("Zero length file '%s'" % path)
        else:
            raise YaraMatchError("Unknown error occurred")


#int               yr_scan_proc(int pid, YARA_CONTEXT* context,
#                               YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_proc.restype = c_int
libyaradll.yr_scan_proc.argtypes = [c_int, POINTER(YARA_CONTEXT),
                                 c_void_p, c_void_p]
def yr_scan_proc(*args):
    ret = libyaradll.yr_scan_proc(*args)
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        if ret == ERROR_COULD_NOT_ATTACH_TO_PROCESS:
            raise YaraMatchError("Access denied")
        elif ret == ERROR_INSUFICIENT_MEMORY:
            raise YaraMatchError("Not enough memory")
        else:
            raise YaraMatchError("Unknown error occurred")


#char*             yr_get_error_message(YARA_CONTEXT* context,
#                                       char* buffer, int buffer_size);
libyaradll.yr_get_error_message.restype = c_char_p
libyaradll.yr_get_error_message.argtypes = [POINTER(YARA_CONTEXT),
                                    c_char_p, c_int]
yr_get_error_message = libyaradll.yr_get_error_message


#void              yr_init();
libyaradll.yr_init.argtypes = []
libyaradll.yr_init()


#### EXTRA Goodness!

if hasattr(libyaradll, 'yr_free_matches'):
    libyaradll.yr_free_matches.restype = None
    libyaradll.yr_free_matches.argtypes = [POINTER(YARA_CONTEXT)]
    yr_free_matches = libyaradll.yr_free_matches
else:
    raise NotImplementedError("Add yr_free_matches to libyara >>README""")


#See if we have yr_malloc_count and yr_free_count for testing?
#  yr_malloc_count and yr_free_count track how many free's and malloc's have
#  been called in the libyara.dll/so
#
try:
    yr_malloc_count()
    yr_free_count()
except:
    #:( nope... stub them out!
    yr_malloc_count = lambda: 0
    yr_free_count = lambda: 0
