"""yar file preprocessor.

Enable preprocessor directives in yara files.


Note: This is a derivative of the *preprocess* Python project by Trent Mick.
      https://pypi.python.org/pypi/preprocess
"""

import os
import sys
import getopt
import types
import re
import pprint
import copy


class PreprocessError(Exception):
    def __init__(self, msg, defines):
        msg = "%s:%s:%s" % (defines['__FILE__'], defines['__LINE__'], msg)
        super(PreprocessError, self).__init__(msg)


def _evaluate(expr, defines):
    """Evaluate the given expression string with the given context.
    WARNING: This runs eval() on a user string. This is unsafe.
    """
    try:
        rv = eval(expr, {'defined':lambda v: v in defines}, defines)
    except Exception as exc:
        msg = str(exc)
        if msg.startswith("name '") and msg.endswith("' is not defined"):
            varName = msg[len("name '"):-len("' is not defined")]
            if expr.find("defined(%s)" % varName) != -1:
                msg += """(perhaps you want "defined('%s')" instead of """ \
                       ' "defined(%s)")' % (varName, varName)
        elif msg.startswith("invalid syntax"):
            msg = "invalid syntax: '%s'" % expr
        raise PreprocessError(msg, defines)
    return rv


SKIP, EMIT = (0, 1)
class State(object):
    __slots__ = ('state', 'emitted', 'seen')
    def __init__(self, state, emitted, seen):
        self.state = state
        self.emitted = emitted
        self.seen = seen


_statements = ['#\s*(?P<op>if|elif|ifdef|ifndef)\s+(?P<expr>.*?)',
               '#\s*(?P<op>else|endif)',
               '#\s*(?P<op>error)\s+(?P<error>.*?)',
               '#\s*(?P<op>define)\s+(?P<var>[^\s]*?)(\s+(?P<val>.+?))?',
               '#\s*(?P<op>undef)\s+(?P<var>[^\s]*?)',
               '(?P<op>include)\s+"(?P<fname>.*?)"',
               "(?P<op>include)\s+'(?P<fname>.*?)'",
               '(?P<op>include)\s+(?P<var>[^\s]+?)',
             ]
_statements = [re.compile("^\s*"+p+"\s$") for p in _statements]


def preprocess(infile, defines={}, include_paths=[]):
    "return a string of the processed infile"
    output = []
    paths = []
    _process(infile, output, copy.copy(defines), include_paths, paths)
    return "".join(output)


def _process(infile, output, defines, include_paths, paths):
    path = os.path.normpath(os.path.abspath(infile))
    paths.append(path)

    # Process the input file.
    with open(infile, 'r') as f:
        lines = f.readlines()

    defines['__FILE__'] = infile
    states = [State(EMIT, 0, 0)]
    
    for line_number, line in enumerate(lines):
        defines['__LINE__'] = line_number

        for _statement in _statements:
            match = _statement.match(line)
            if match:
                break
        else:
            match = None
        
        if match:
            op = match.group("op")
            if op == "define":
                if not (states and states[-1].state == SKIP):
                    var, val = match.group("var", "val")
                    if val is None:
                        val = None
                    else:
                        try:
                            val = eval(val, {}, {})
                        except:
                            pass
                    defines[var] = val
            elif op == "undef":
                if not (states and states[-1].state == SKIP):
                    var = match.group("var")
                    try:
                        del defines[var]
                    except KeyError:
                        pass
            elif op == "include":
                if not (states and states[-1].state == SKIP):
                    if "var" in match.groupdict():
                        # This is the second include form: #include VAR
                        var = match.group("var")
                        f = defines[var]
                    else:
                        # This is the first include form: #include "path"
                        # or the include form: #include 'path'
                        f = match.group("fname")
                    ext = os.path.splitext(f)[-1]
                    if ext != '.yar':
                        msg = "Invalid file extension '%s'."\
                              "Can only include .yar" % ext
                        raise PreprocessError(msg, defines)
                    for d in [os.path.dirname(infile)] + include_paths:
                        p = os.path.normpath(os.path.join(d, f))
                        if os.path.exists(p):
                            break
                    else:
                        msg = "Could not find #include file "\
                              '"%s" on include path: %r' % (f, p)
                        raise PreprocessError(msg, defines)

                    # This check makes us more lazy when writing rules...
                    # It means we no longer have to do ifndef define 
                    # for each rule file to build one preprocessed rule.
                    # If it turns out that there are other directives that
                    # are broken because of this, we can turn it back on and 
                    # go back to the rule files to add the ifndef directives.
                    if p not in paths:
                        _process(p, output, defines, include_paths, paths)

            elif op in ("if", "ifdef", "ifndef"):
                if op == "if":
                    expr = match.group("expr")
                elif op == "ifdef":
                    expr = "defined('%s')" % match.group("expr")
                elif op == "ifndef":
                    expr = "not defined('%s')" % match.group("expr")
                try:
                    if states and states[-1].state == SKIP:
                        states.append(State(SKIP, 0, 0))
                    elif _evaluate(expr, defines):
                        states.append(State(EMIT, 1, 0))
                    else:
                        states.append(State(SKIP, 0, 0))
                except KeyError:
                    msg = "Use of undefined variable in #%s stmt" % op
                    raise PreprocessError(msg, defines)
            elif op == "elif":
                expr = match.group("expr")
                try:
                    if states[-1].seen: 
                        msg = "Illegal #elif after #else in same #if block"
                        raise PreprocessError(msg, defines)
                    elif states[-1].emitted:
                        states[-1] = State(SKIP, 1, 0)
                    elif states[:-1] and states[-2].state == SKIP:
                        states[-1] = State(SKIP, 0, 0)
                    elif _evaluate(expr, defines):
                        states[-1] = State(EMIT, 1, 0)
                    else:
                        states[-1] = State(SKIP, 0, 0)
                except IndexError:
                    msg = "#elif statement without leading #if statement"
                    raise PreprocessError(msg, defines)
            elif op == "else":
                try:
                    if states[-1].seen:
                        msg = "Illegal #else after #else in same #if block"
                        raise PreprocessError(msg, defines)
                    elif states[-1].emitted:
                        states[-1] = State(SKIP, 1, 1)
                    elif states[:-1] and states[-2].state == SKIP:
                        states[-1] = State(SKIP, 0, 1)
                    else:
                        states[-1] = State(EMIT, 1, 1)
                except IndexError:
                    msg = "#else statement without leading #if statement"
                    raise PreprocessError(msg, defines)
            elif op == "endif":
                try:
                    states.pop()
                except IndexError:
                    msg = "#endif statement without leading #if statement"
                    raise PreprocessError(msg, defines)
            elif op == "error":
                if not (states and states[-1].state == SKIP):
                    error = match.group("error")
                    raise PreprocessError("#error: "+error, defines)
        else:
            try:
                if states[-1].state == EMIT:
                    # Substitute all defines into line.
                    sline = line
                    for name in reversed(sorted(defines, key=len)):
                        value = defines[name]
                        sline = sline.replace(name, str(value))
                    output.append(sline)
                else:
                    # skip line
                    pass
            except IndexError:
                raise PreprocessError("Superfluous #endif before this line",
                                          defines)
    if len(states) > 1:
        raise PreprocessError("Unterminated #if block", defines)
    elif len(states) < 1:
        raise PreprocessError("Superfluous #endif on or before this line",
                              defines)

