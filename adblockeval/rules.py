import pickle
import re
from collections import namedtuple
from urllib.parse import urlparse
from pathlib import Path

from adblockeval.ahocorasick import AhoCorasickIndex

# Matches a hostname according to RFC 1123
_HOSTNAME_REGEX = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*'
                             r'[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9]'
                             r'[A-Za-z0-9\-]*[A-Za-z0-9])$')
_DOMAIN_RULE_SPLIT_REGEXP = re.compile('[/^]')

MatchResult = namedtuple('MatchResult', ['is_match', 'matches'])
RuleKeywords = namedtuple('RuleKeywords', ['url_keywords', 'domain_keywords',])
RuleOrigin = namedtuple('RuleOrigin', ['source_file', 'line_no'])


class AdblockRules:
    def __init__(self, rule_list=None, rule_files=None, cache_file=None,
                 skip_parsing_errors=False):
        if rule_list and cache_file:
            raise ValueError('Cannot use rule_list if cache_file is provided. '
                             'Put your rules into a file and use rule_files instead.')
        self.skip_parsing_errors = skip_parsing_errors
        self.rules = []

        if rule_list is not None and cache_file is None:
            self.rules += self._parse_rules(rule_list)

        load_from_cache = False
        if rule_files is not None:
            rule_files = [Path(rule_file) for rule_file in rule_files]
            if cache_file:
                cache_file = Path(cache_file)
                try:
                    cache_mtime = cache_file.stat().st_mtime
                except FileNotFoundError:
                    load_from_cache = False
                else:
                    newest_mtime = max(rule_file.stat().st_mtime for rule_file in rule_files)
                    load_from_cache = newest_mtime <= cache_mtime
            if load_from_cache:
                with cache_file.open('rb') as f:
                    self.rules, self._index = pickle.load(f)
            else:
                for rule_file in rule_files:
                    with rule_file.open() as f:
                        self.rules += self._parse_rules(f.readlines(), str(rule_file))

        if not load_from_cache:
            self._index = RulesIndex(self.rules)

        if cache_file and not load_from_cache:
            with cache_file.open('wb') as f:
                pickle.dump((self.rules, self._index), f, pickle.HIGHEST_PROTOCOL)

    def _parse_rules(self, rule_list, source_file=None):
        for line_no, rule_str in enumerate(rule_list, start=1):
            # Comments
            if rule_str.startswith('!'):
                continue

            rule_str = rule_str.strip()
            if not rule_str:
                continue

            # We skip cosmetic rules because they cannot be
            # matched against URLs
            if '##' in rule_str or '#@#' in rule_str:
                continue

            try:
                rule = self._parse_rule(rule_str)
                rule.origin = RuleOrigin(source_file, line_no)
                yield rule
            except RuleParsingError as e:
                if not self.skip_parsing_errors:
                    raise

    def match_slow(self, url, domain=None, origin=None):
        matching_rules = []
        parsed_url = urlparse(url)
        for rule in self.rules:
            if rule.match(url, parsed_url.netloc, domain, origin):
                if rule.is_exception:
                    return MatchResult(False, [rule])
                matching_rules.append(rule)
        return MatchResult(bool(matching_rules), matching_rules)

    def match(self, url, domain=None, origin=None):
        matching_rules = []
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        for rule in self._index.get_possible_rules(url, netloc, domain):
            if rule.match(url, parsed_url.netloc, domain, origin):
                if rule.is_exception:
                    return MatchResult(False, [rule])
                matching_rules.append(rule)
        return MatchResult(bool(matching_rules), matching_rules)

    def _parse_rule(self, rule_str):
        is_exception = False

        parts = rule_str.rsplit('$', 1)
        expression = parts[0]
        options = RuleOptions.from_string(parts[1]) if len(parts) == 2 else None

        # Exception rules
        if expression.startswith('@@'):
            is_exception = True
            expression = expression[2:]

        # Domain rules. According to uBlock manual, any rule that looks
        # like a hostname does not match as substring but as domain.
        if expression.startswith('||') or _HOSTNAME_REGEX.match(expression):
            rule = DomainRule.from_expression(expression, options)
        # Regexp rules
        elif expression.startswith('/') and expression.endswith('/'):
            rule = RegexpRule.from_expression(expression, options)
        # Substring rules
        else:
            rule = SubstringRule.from_expression(expression, options)

        rule.is_exception = is_exception

        return rule


class RulesIndex:
    def __init__(self, rules):
        self.rules = rules
        self._build_index()

    def _build_index(self):
        always_check_rules = []
        url_keywords = []
        url_outputs = []
        domain_keywords = []
        domain_outputs = []
        domain_opt_keywords = []
        domain_opt_outputs = []

        for rule_index, rule in enumerate(self.rules):
            if rule.options:
                self._add_keywords(rule_index, domain_opt_keywords, domain_opt_outputs,
                                   rule.options.include_domains)
            rule_keywords = rule.get_keywords()
            if not rule_keywords.url_keywords and not rule_keywords.domain_keywords:
                always_check_rules.append(rule_index)
                continue
            self._add_keywords(rule_index, url_keywords, url_outputs,
                               rule_keywords.url_keywords)
            self._add_keywords(rule_index, domain_keywords, domain_outputs,
                               rule_keywords.domain_keywords)

        self._url_index = AhoCorasickIndex.from_keywords(url_keywords, url_outputs)
        self._domain_index = AhoCorasickIndex.from_keywords(domain_keywords,domain_outputs)
        self._domain_opt_index = AhoCorasickIndex.from_keywords(domain_opt_keywords,
                                                                domain_opt_outputs)
        self._always_check_rules = always_check_rules

    def _add_keywords(self, rule_index, keyword_list, output_list, keywords):
        if keywords is None:
            return
        for keyword in keywords:
            keyword_list.append(keyword)
            output_list.append(rule_index)

    def get_possible_rules(self, url, netloc, domain):
        rule_indexes = set(self._always_check_rules)
        rule_indexes.update(self._url_index.get_matching_keywords(url))
        rule_indexes.update(self._domain_index.get_matching_keywords(netloc))
        if domain:
            domain_opt_rules = set(self._domain_opt_index.get_matching_keywords(domain))
        else:
            domain_opt_rules = None

        for rule_index in rule_indexes:
            rule = self.rules[rule_index]
            if domain_opt_rules is not None and rule.options and rule.options.include_domains:
                if rule_index not in domain_opt_rules:
                    continue
            yield rule


class RuleParsingError(Exception):
    pass


class Rule:
    __slots__ = ('origin', 'expression', 'options', 'is_exception')

    def __init__(self, expression, options):
        self.expression = expression
        self.options = options
        self.origin = None
        self.is_exception = False

    def match(self, url, netloc, domain, origin=None):
        if self.options and not self.options.can_apply_rule(domain, origin):
            return False
        return True

    def __str__(self):
        if self.options:
            expression_str = '{}${}'.format(self.expression, self.options)
        else:
            expression_str = self.expression
        return '@@' + expression_str if self.is_exception else expression_str

    def __repr__(self):
        return '{}<{!r}>'.format(self.__class__.__name__, str(self))


class RegexpRule(Rule):
    __slots__ = ('_regexp_obj', )

    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if not super().match(url, netloc, domain, origin):
            return False
        return self._regexp_obj.search(url) is not None

    def get_keywords(self):
        return RuleKeywords(
            url_keywords=_get_regexp_keywords(self._regexp_obj.pattern),
            domain_keywords=None)

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with / and ends with /$
        if not (expression.startswith('/') and expression.endswith('/')):
            raise RuleParsingError('Not a regular expression rule: {}'.format(expression))
        pattern = expression[1:-1]
        match_case = options.has_included('match-case') if options else False
        try:
            regexp_obj = re.compile(pattern,
                                    re.IGNORECASE if not match_case else 0)
        except re.error:
            raise RuleParsingError('Invalid regular expression {}'.format(pattern))
        return cls(expression, options, regexp_obj)


class DomainRule(Rule):
    __slots__ = ('_domain', '_domain_regexp_obj', '_path_regexp_obj')

    def __init__(self, expression, options, domain, domain_regexp_obj, path_regexp_obj):
        super().__init__(expression, options)
        self._domain = domain
        self._domain_regexp_obj = domain_regexp_obj
        self._path_regexp_obj = path_regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if not super().match(url, netloc, domain, origin):
            return False

        if isinstance(self._domain_regexp_obj, tuple):
            self._domain_regexp_obj = re.compile(*self._domain_regexp_obj)
        match_obj = self._domain_regexp_obj.search(netloc)
        if match_obj is None:
            return False
        domain_matches = match_obj.start() == 0 or netloc[match_obj.start() - 1] == '.'
        if not domain_matches:
            return False
        # We have no path to check, so if we did not refuse the domain
        # yet, the domain matches and so will the rule itself.
        if self._path_regexp_obj is None:
            return True

        # Splitting at netloc is a little bit hacky, but is the fastest
        # way to get the actual path without re-parsing the whole URL
        url_parts = url.split(netloc, maxsplit=1)
        path = url_parts[1] if len(url_parts) == 2 else '/'
        if isinstance(self._path_regexp_obj, tuple):
            self._path_regexp_obj = re.compile(*self._path_regexp_obj)
        return self._path_regexp_obj.search(path) is not None

    def get_keywords(self):
        return RuleKeywords(
            url_keywords=None,
            domain_keywords=_get_longest_keyword(self._domain.strip('|')))

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with || and often ends with ^ which
        # however makes no sense, since these characters cannot
        # be part of a domain
        ruleparts = _DOMAIN_RULE_SPLIT_REGEXP.split(expression[2:], maxsplit=1)
        domain = ruleparts[0]
        if len(ruleparts) == 2:
            path = ruleparts[1]
            separator = expression[2+len(domain)]
            if separator == '/':
                path = '/' + path
        else:
            path = None

        domain_regexp_obj = _compile_wildcards(domain, prefix=r'', suffix='$', lazy=True)
        if path:
            prefix = '^' if path.startswith('/') else ''
            path_regexp_obj = _compile_wildcards(path, prefix=prefix, suffix='', lazy=True)
        else:
            path_regexp_obj = None
        return cls(expression, options, domain, domain_regexp_obj, path_regexp_obj)


class SubstringRule(Rule):
    __slots__ = ('_regexp_obj', )

    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if not super().match(url, netloc, domain, origin):
            return False
        if isinstance(self._regexp_obj, tuple):
            self._regexp_obj = re.compile(*self._regexp_obj)
        return self._regexp_obj.search(url) is not None

    def get_keywords(self):
        return RuleKeywords(
            url_keywords=_get_longest_keyword(self.expression.strip('|')),
            domain_keywords=None)

    @classmethod
    def from_expression(cls, expression, options):
        origin_expression = expression
        fix_start = False
        fix_end = False

        # Must match the beginning of a URL
        if expression.startswith('|'):
            fix_start = True
            expression = expression[1:]

        # Must match the end of a URL
        if expression.endswith('|'):
            fix_end = True
            expression = expression[:-1]

        # Wildcard stars at the end and beginning do not
        # have any influence here.
        expression = expression.strip('*')

        match_case = options.has_included('match-case') if options else False
        regexp_obj = _compile_wildcards(expression,
                                        '^' if fix_start else None,
                                        '$' if fix_end else None,
                                        match_case,
                                        lazy=True)

        return cls(origin_expression, options, regexp_obj)


class RuleOptions:
    __slots__ = ('include_domains', 'exclude_domains', 'options_mask',
                 'options_mask_negative')

    AVAILABLE_OPTIONS = {
        'script': 1 << 1,
        'image': 1 << 2,
        'stylesheet': 1 << 3,
        'object': 1 << 4,
        'xmlhttprequest': 1 << 5,
        'object-subrequest': 1 << 6,
        'subdocument': 1 << 7,
        'ping': 1 << 8,
        'websocket': 1 << 9,
        'webrtc': 1 << 10,
        'document': 1 << 11,
        'elemhide': 1 << 12,
        'generichide': 1 << 13,
        'genericblock': 1 << 14,
        'popup': 1 << 15,
        'other': 1 << 16,
        'third-party': 1 << 17,
        'match-case': 1 << 18,
        'collapse': 1 << 19,
        'donottrack': 1 << 20

    }

    def __init__(self, include_domains, exclude_domains, options_mask=0,
                 options_mask_negative=0):
        self.include_domains = include_domains
        self.exclude_domains = exclude_domains
        self.options_mask = options_mask
        self.options_mask_negative = options_mask_negative

    def can_apply_rule(self, domain, origin):
        if self.exclude_domains and _contains_subdomain(domain, self.exclude_domains):
            return False
        if self.include_domains and not _contains_subdomain(domain, self.include_domains):
            return False
        return True

    def has_included(self, keyword):
        return self._has(self.options_mask, keyword)

    def has_excluded(self, keyword):
        return self._has(self.options_mask_negative, keyword)

    def _has(self, mask, keyword):
        try:
            return bool(mask & self.AVAILABLE_OPTIONS[keyword])
        except KeyError:
            raise ValueError('Unsupported option keyword: {}'.format(keyword))

    def __str__(self):
        option_str_list = []
        for option, bitmask in sorted(self.AVAILABLE_OPTIONS.items()):
            if self.options_mask & bitmask:
                option_str_list.append(option)
            if self.options_mask_negative & bitmask:
                option_str_list.append('~' + option)
        if self.exclude_domains or self.include_domains:
            domain_list = []
            if self.include_domains:
                domain_list += sorted(self.include_domains)
            if self.exclude_domains:
                domain_list += sorted('~' + domain for domain in self.exclude_domains)
            option_str_list.append('domain=' + '|'.join(domain_list))
        return ','.join(option_str_list)

    @classmethod
    def from_string(cls, option_str):
        option_parts = option_str.split(',')
        include_domains = []
        exclude_domains = []
        options_mask = 0
        options_mask_negative = 0
        for option_part in option_parts:
            if not option_part:
                continue
            if option_part in cls.AVAILABLE_OPTIONS:
                options_mask |= cls.AVAILABLE_OPTIONS[option_part]
            elif option_part[0] == '~' and option_part[1:] in cls.AVAILABLE_OPTIONS:
                options_mask_negative |= cls.AVAILABLE_OPTIONS[option_part[1:]]
            elif option_part.startswith('domain='):
                domains = option_part[len('domain='):].split('|')
                for domain in domains:
                    # domain=* will have the same effect as
                    # not having domain option set
                    if not domain or domain == '*':
                        continue
                    domain_list = include_domains if domain[0] != '~' else exclude_domains
                    domain_list.append(domain if domain[0] != '~' else domain[1:])
        return cls(include_domains=include_domains if include_domains else None,
                   exclude_domains=exclude_domains if exclude_domains else None,
                   options_mask=options_mask,
                   options_mask_negative=options_mask_negative)


def _compile_wildcards(expression, prefix='', suffix='', match_case=False, lazy=False):
    """Translate the expression into a regular expression.
    A star matches anything, while ^ is a placeholder for a single separator
    character. According to the docs, "Separator character is anything but a
    letter, digit, or one of the following: _ - . %"
    """
    wildcards = [(match.start(), match.group(0))
                 for match in re.finditer('[*^]', expression)]
    regex_parts = []
    if prefix:
        regex_parts.append(prefix)
    start = 0
    for pos, wildard_type in wildcards:
        regex_parts.append(re.escape(expression[start:pos]))
        regex_parts.append('.*' if wildard_type == '*' else '[^a-zA-Z0-9._%-]')
        start = pos + 1
    if start < len(expression):
        regex_parts.append(re.escape(expression[start:]))
    if suffix:
        regex_parts.append(suffix)
    pattern = ''.join(regex_parts)
    options = re.IGNORECASE if not match_case else 0
    return (pattern, options) if lazy else re.compile(pattern, options)


def _get_longest_keyword(wildcard_str):
    keyword = max(re.split('[*^]', wildcard_str), key=len)
    return [keyword] if keyword else []


def _get_regexp_keywords(pattern):
    """Extracts keywords from a regular expression that must appear in an URL.

    The algorithm does a very bad parsing of regular expression and is very
    conservative about the extracted keywords. We favor correctness over
    a probably more complete result. Namely, if the rule matches, at least
    one of the extracted keywords is in the URL. To ensure correctness, it
    only take constant keywords in parsing depth == 1 and very simple
    constant pipe options like (foo|bar|qux) in a group in depth == 1.
    However, this should extract some keywords for the regular expressions
    in the easylist.
    """
    token_specification = [
        ('ESCAPE',           r'\\.'),
        ('CHAR_GROUP_OPEN',  r'\['),
        ('CHAR_GROUP_CLOSE', r'\]'),
        ('PIPE_GROUP',       r'\([\w\d\-_|]+\)'),
        ('GROUP_OPEN',       r'\('),
        ('GROUP_CLOSE',      r'\)'),
        ('LENGTH_OPEN',      r'\{'),
        ('LENGTH_CLOSE',     r'\}'),
        ('OPTIONAL',         r'\?'),
        ('KEYWORD',          r'\w+'),
        ('OTHER',            r'.')
    ]
    tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
    keywords = []
    stack = ['start']
    state_was_keyword = False
    num_pipe_keywords = 0
    for mo in re.finditer(tok_regex, pattern):
        state = stack[-1]
        kind = mo.lastgroup
        value = mo.group(kind)

        if kind == 'PIPE_GROUP' and len(stack) == 1:
            pipe_keywords = value.split('|')
            pipe_keywords[0] = pipe_keywords[0][1:] # remove (
            pipe_keywords[-1] = pipe_keywords[-1][:-1] # remove )
            num_pipe_keywords = len(pipe_keywords)
            keywords += pipe_keywords
            continue
        elif kind == 'GROUP_OPEN':
            stack.append('group')
        elif kind == 'GROUP_CLOSE' and state == 'group':
            stack.pop()
        elif kind == 'CHAR_GROUP_OPEN':
            stack.append('char_group')
        elif kind == 'CHAR_GROUP_CLOSE' and state == 'char_group':
            stack.pop()
        elif kind == 'LENGTH_OPEN':
            stack.append('length')
        elif kind == 'LENGTH_CLOSE' and state == 'length':
            stack.pop()
        elif kind == 'KEYWORD' and len(stack) == 1:
            keywords.append(value)
            state_was_keyword = True
            continue
        elif kind == 'OPTIONAL':
            if state_was_keyword:
                # Strip of last character, because something
                # like foob? only garantuees foo to be present.
                keyword = keywords.pop()[:-1]
                if keyword:
                    keywords.append(keyword)
                # If a whole construct like (foo|bar|qux)? is
                # optional, we have to remove all keywords again.
            elif num_pipe_keywords:
                for i in range(num_pipe_keywords):
                    keywords.pop()
        state_was_keyword = False
        num_pipe_keywords = 0

    return set(keywords)


def _is_subdomain(subdomain, domain):
    return (subdomain == domain or
                (subdomain.endswith(domain) and
                 len(subdomain) > len(domain) and
                 subdomain[-len(domain)-1] == '.'))


def _contains_subdomain(subdomain, domain_list):
    return any(_is_subdomain(subdomain, domain) for domain in domain_list)
