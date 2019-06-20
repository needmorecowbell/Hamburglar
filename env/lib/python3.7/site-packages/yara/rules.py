"""Compiles a YARA rules files into a thread safe Rules object ready for
matching.

[mjdorma@gmail.com]
"""

import sys
import os
import pprint
import types
import copy
import traceback
import threading
from io import BytesIO 

from yara.preprocessor import preprocess
from yara.libyara_wrapper import *


CALLBACK_CONTINUE = 0
CALLBACK_ABORT = 1


if sys.version_info[0] < 3: 
    INT_TYPES = [long, int]
else:
    INT_TYPES = [int]


class RuleContext():
    """Wraps a libyara context and provides additional state to gain finer
    control over libyara's matching execution.  This class is responsible
    for the conversion of libyara results to python results.
    """
    def __init__(self, strings, externals, fast_match):
        """See doc for Rules()"""
        self._callback_error = None
        self._callback = YARACALLBACK(self._callback)

        self._context = yr_create_context()

        self._error_report_function = YARAREPORT(self._error_report_function)
        self._error_reports = []
        self._context.contents.error_report_function = \
                                    self._error_report_function

        self._process_externals(externals)
        self._context.contents.allow_includes = True 
        self._context.contents.fast_match = fast_match

        for namespace, filename, string in strings:
            yr_push_file_name(self._context, filename)
            ns = yr_create_namespace(self._context, namespace)
            self._context.contents.current_namespace = ns
            yr_compile_string(string, self._context)

        if self._error_reports:
            msg = ["%s:%s: %s" % (f, l, e) for f, l, e in self._error_reports]
            exc = YaraSyntaxError("\n".join(msg))
            exc.errors = self._error_reports
            raise exc

    def __del__(self):
        self.free()

    def free(self):
        """Call yr_destroy_context to free up this context in libyara"""
        if self._context:
            yr_destroy_context(self._context)
            self._context = None

    def _error_report_function(self, filename, line_number, error_message):
        if not filename:
            filename = "<undefined yarfile>"
        self._error_reports.append((frombyte(filename), line_number,
                                    frombyte(error_message)))

    def _callback(self, rule, null):
        try:
            if (rule.contents.flags & RULE_FLAGS_MATCH) or\
                    self._match_callback is not None:
                match = self._process_rule(rule)
            else:
                return CALLBACK_CONTINUE

            if self._match_callback is not None:
                try:
                    res = self._match_callback(match)
                    if res is None:
                        return CALLBACK_CONTINUE
                    elif res not in [CALLBACK_CONTINUE, CALLBACK_ABORT]:
                        raise TypeError("Expected 0 or 1, got %s" % res)
                    return res
                except StopIteration:
                    return CALLBACK_ABORT

            elif (rule.contents.flags & RULE_FLAGS_MATCH):
                name = match.pop('namespace')
                namespace = self._matches.get(name, [])
                namespace.append(match)
                self._matches[name] = namespace
                return CALLBACK_CONTINUE

        except Exception as exc:
            self._callback_error = traceback.format_exc()
            return CALLBACK_ERROR

    def _process_rule(self, rule):
        tag = rule.contents.tag_list_head
        tag_list = []
        while tag:
            tag_list.append(frombyte(tag.contents.identifier))
            tag = tag.contents.next

        meta = rule.contents.meta_list_head
        meta_dict = {}
        while meta:
            if meta.contents.type == META_TYPE_INTEGER:
                value = meta.contents.value.integer
            elif meta.contents.type == META_TYPE_BOOLEAN:
                value = bool(meta.contents.value.boolean)
            else:
                value = frombyte(meta.contents.value.string)
            meta_dict[frombyte(meta.contents.identifier)] = value
            meta = meta.contents.next

        string = rule.contents.string_list_head
        string_list = []
        while string:
            if string.contents.flags & STRING_FLAGS_FOUND:
                match = string.contents.matches_head
                while match:
                    data = frombyte(string_at(match.contents.data,
                                        match.contents.length))
                    string_list.append(dict(data=data,
                        offset=match.contents.offset,
                        identifier=frombyte(string.contents.identifier),
                        flags=string.contents.flags))
                    match = match.contents.next
            string = string.contents.next

        return dict(tags=tag_list,
                    meta=meta_dict,
                    strings=string_list,
                    rule=frombyte(rule.contents.identifier),
                    namespace=frombyte(rule.contents.ns.contents.name),
                    matches=bool(rule.contents.flags & RULE_FLAGS_MATCH))

    def _process_externals(self, externals):
        for key, value in externals.items():
            if type(value) in INT_TYPES:
                yr_define_integer_variable(self._context, key, value)
            elif type(value) is bool:
                yr_define_boolean_variable(self._context, key, value)
            elif type(value) is str:
                yr_define_string_variable(self._context, key, value)
            else:
                raise TypeError(\
                    "External values must be of type int, long, bool or str")

    def weight(self):
        """Calculate the rules weight for this context"""
        return yr_calculate_rules_weight(self._context)

    def match(self, fnc, *args, **kwargs):
        """Call one of the three match fnc's with appropriate args.
        See Rules.match_? function doc
        """
        self._process_externals(kwargs.get('externals', {}))
        callback = kwargs.get('callback', None)
        if callback is not None:
            if not hasattr(callback, '__call__'):
                raise TypeError("callback object not a callable")
        self._matches = {}
        self._callback_error = None
        self._match_callback = callback
        args = list(args) + [self._context, self._callback, None]
        try:
            fnc(*args)
        except YaraCallbackError:
            if self._callback_error is None:
                raise YaraCallbackError("Unkown error occurred")
            else:
                msg = "Error in callback handler:\n%s" % \
                        self._callback_error
                raise YaraCallbackError(msg)
        finally:
            yr_free_matches(self._context)
        return self._matches


class Rules():
    """ Rules manages the seamless construction of a new context per thread and
    exposes libyara's match capability.
    """
    def __init__(self, paths={},
                 defines={},
                 include_path=[],
                 strings=[],
                 externals={},
                 fast_match=False):
        """Defines a new yara context with specified yara sigs

        Options:
            paths          - {namespace:rules_path,...}
            include_path  - a list of paths to search for given #include
                             directives. 
            defines        - key:value defines for the preprocessor.  Sub in 
                             strings or macros defined in your rules files.
            strings        - [(namespace, filename, rules_string),...]
            externals      - define boolean, integer, or string variables
                             {var:val,...}
            fast_match     - enable fast matching in the YARA context

        Note:
            namespace - defines which namespace we're building our rules under
            rules_path - path to the .yar file
            filename  - filename which the rules_string came from
            rules_string - the text read from a .yar file
        """
        self._strings = copy.copy(strings)
        self.namespaces = set()
        self._contexts = {}
        for namespace, path in paths.items():
            self.namespaces.add(namespace)
            string = preprocess(path, defines, include_path)
            self._strings.append((namespace, path, string))
        self._context_args = [self._strings,
                                  externals,
                                  fast_match]

    def __str__(self):
        return "Rules + %s" % "\n      + ".join([a[0] for a in self._strings])

    @property
    def context(self):
        ident = threading.current_thread().ident
        c = self._contexts.get(ident, None)
        if c is None:
                c = RuleContext(*self._context_args)
                self._contexts[ident] = c
        return c

    def free(self):
        ident = threading.current_thread().ident
        c = self._contexts.pop(ident, None)
        if c is not None:
            c.free()

    def weight(self):
        return self.context.weight()

    def match_path(self, filepath, externals={}, callback=None):
        """Match a filepath against the compiled rules
        Required argument:
           filepath - filepath to match against

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        return self.context.match(yr_scan_file, filepath,
                                  externals=externals,
                                  callback=callback)

    def match_data(self, data, externals={}, callback=None):
        """Match data against the compiled rules
        Required argument:
           data - filepath to match against

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        return self.context.match(yr_scan_mem, data, len(data),
                            externals=externals,
                            callback=callback)

    def match_proc(self, pid, externals={}, callback=None):
        """Match a process memory against the compiled rules
        Required argument:
           pid - process id

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        return self.context.match(yr_scan_proc, pid,
                            externals=externals,
                            callback=callback)

    def match(self, filepath=None, pid=None, data=None, **match_kwargs):
        """Match on one of the following: pid= filepath= or data=
        Require one of the following:
           filepath - filepath to match against
           pid - process id
           data - filepath to match against

        Options:
            externals - define boolean, integer, or string variables
            callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Functionally equivalent to (yara-python.c).match
        """
        if filepath is not None:
            return self.match_path(filepath, **match_kwargs)
        elif pid is not None:
            return self.match_proc(pid, **match_kwargs)
        elif data is not None:
            return self.match_data(data, **match_kwargs)
        else:
            raise Exception("matche() missing a required argument")


YARA_RULES_ROOT = os.environ.get('YARA_RULES',
                    os.path.join(os.path.dirname(__file__), 'rules'))
INCLUDE_PATH = os.environ.get('PATH','.').split(':')


def load_rules(rules_rootpath=YARA_RULES_ROOT,
               blacklist=[],
               whitelist=[],
               include_path=INCLUDE_PATH,
               **rules_kwargs):
    """A simple way to build a complex yara Rules object with strings equal to
    [(namespace:filepath:source),...]

    YARA rules files found under the rules_rootpath are loaded based on the
    exclude namespace blacklist or include namespace whitelist. 

    i.e.
    Where rules_rootpath = './rules' which contained:
        ./rules/hbgary/libs.yar
        ./rules/hbgary/compression.yar
        ./rules/hbgary/fingerprint.yar

    The resultant Rules object would contain the following namespaces:
        hbgary.libs
        hbgary.compression
        hbgary.fingerprint

    Optional YARA rule loading parameters:
       rules_rootpath - root dir to search for YARA rules files
       blacklist - namespaces "starting with" to exclude
       whitelist - namespaces "starting with" to include

    Rule options:
        externals - define boolean, integer, or string variables {var:val,...}
        fast_match - enable fast matching in the YARA context
    """
    whitelist = set(whitelist)
    blacklist = set(blacklist)

    rules_rootpath = os.path.abspath(rules_rootpath)
    if not rules_rootpath.endswith(os.path.sep):
        rules_rootpath = rules_rootpath + os.path.sep

    paths = {}
    for path, children, names in os.walk(rules_rootpath):
        relative_path = path[len(rules_rootpath):]
        namespace_base = ".".join(relative_path.split(os.path.sep))

        for filename in names:
            name, ext = os.path.splitext(filename)
            if ext != '.yar':
                continue
            if namespace_base:
                namespace = "%s.%s" % (namespace_base, name)
            else:
                namespace = name
            if [a for a in filter(namespace.startswith, blacklist)]:
                continue
            if (whitelist and \
                    not [a for a in filter(namespace.startswith, whitelist)]):
                continue

            paths[namespace] = os.path.join(path, filename)

    include_path = copy.copy(include_path)
    include_path.append(rules_rootpath)
    rules = Rules(paths=paths, include_path=include_path, **rules_kwargs)
    c = rules.context
    rules.free()
    return rules


def compile(filepath=None, source=None, fileobj=None, filepaths=None,
        sources=None, **rules_kwargs):
    """Compiles a YARA rules file and returns an instance of class Rules

    Require one of the following:
        filepath - str object containing a YARA rules filepath
        source - str object containing YARA source
        fileobj - a file object containing a set of YARA rules
        filepaths - {namespace:filepath,...}
        sources - {namespace:source_str,...}

    Rule options:
        externals - define boolean, integer, or string variables {var:val,...}
        fast_match - enable fast matching in the YARA context

    Functionally equivalent to (yara-python.c).compile
    """
    kwargs = rules_kwargs.copy()
    if filepath is not None:
        kwargs['paths'] = dict(main=filepath)
    elif fileobj is not None:
        kwargs['strings'] = [('main', '<undef>', fileobj.read())]
    elif source is not None:
        kwargs['strings'] = [('main', '<undef>', source)]
    elif sources is not None:
        kwargs['strings'] = [(a, '<undef>', b) for a, b in sources.items()]
    elif filepaths is not None:
        kwargs['paths'] = filepaths
    else:
        raise ValueError("compile() missing a required argument")

    rules = Rules(**kwargs)
    c = rules.context
    rules.free()
    return rules


if __name__ == "__main__":
    rules = load_rules()
    matches = rules.match_path(sys.argv[1])
    pprint.pprint(matches)
