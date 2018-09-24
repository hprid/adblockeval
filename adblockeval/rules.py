import re
from collections import namedtuple
from urllib.parse import urlparse

# Matches a hostname according to RFC 1123
_HOSTNAME_REGEX = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*'
                             r'[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9]'
                             r'[A-Za-z0-9\-]*[A-Za-z0-9])$')

MatchResult = namedtuple('MatchResult', ['is_match', 'matches'])


class AdblockRules:
    def __init__(self, rule_list=None, skip_parsing_errors=False):
        self.skip_parsing_errors = skip_parsing_errors
        self.rules = []
        self._current_line_no = 1
        if rule_list is not None:
            self.add_rules(rule_list)

    def add_rules(self, rule_list):
        self.rules += self._parse_rules(rule_list)

    def _parse_rules(self, rule_list):
        # In case rule_list is empty, rule_no must be defined.
        rule_no = self._current_line_no
        for rule_no, rule_str in enumerate(rule_list, start=self._current_line_no):
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
                yield rule_no, rule
            except RuleParsingError as e:
                if not self.skip_parsing_errors:
                    raise
        self._current_line_no = rule_no

    def match(self, url, domain=None, origin=None):
        matching_rules = []
        parsed_url = urlparse(url)
        for rule_no, rule in self.rules:
            if rule.match(url, parsed_url.netloc, domain, origin):
                if rule.is_exception:
                    return MatchResult(False, [(rule_no, rule)])
                matching_rules.append((rule_no, rule))
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


class RuleParsingError(Exception):
    pass


class Rule:
    __slots__ = ('expression', 'options', 'is_exception')

    def __init__(self, expression, options):
        self.expression = expression
        self.options = options
        self.is_exception = False

    def match(self, url, netloc, domain, origin=None):
        raise NotImplemented

    def __str__(self):
        if self.options:
            expression_str = '{}${}'.format(self.expression, self.options)
        else:
            expression_str = self.expression
        return '@@' + expression_str if self.is_exception else expression_str

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, str(self))


class RegexpRule(Rule):
    __slots__ = ('_regexp_obj', )

    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if self.options and not self.options.can_apply_rule(domain, origin):
            return False
        return (self.options.can_apply_rule(domain, origin) and
                self._regexp_obj.search(url) is not None)

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with / and ends with /$
        if not expression.startswith('/') and expression.endswith('/'):
            raise RuleParsingError('Not a regular expression rule: {}'.format(expression))
        pattern = expression[1:-1]
        match_case = options.has_set('match-case') if options else False
        try:
            regexp_obj = re.compile(pattern,
                                    re.IGNORECASE if not match_case else 0)
        except re.error:
            raise RuleParsingError('Invalid regular expression {}'.format(pattern))
        return cls(expression, options, regexp_obj)


class DomainRule(Rule):
    __slots__ = ('_domain', '_regexp_obj')

    def __init__(self, expression, options, domain, regexp_obj):
        super().__init__(expression, options)
        self._domain = domain
        self._regexp_obj = regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if self.options and not self.options.can_apply_rule(netloc, origin):
            return False
        match_obj = self._regexp_obj.search(netloc)
        if match_obj is None:
            return False
        return match_obj.start() == 0 or netloc[match_obj.start() - 1] == '.'

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with || and often ends with ^ which
        # however makes no sense, since these characters cannot
        # be part of a doamin
        domain = expression[2:].rstrip('^')
        regexp_obj = _compile_wildcards(domain, prefix=r'', suffix='$')
        return cls(expression, options, domain, regexp_obj)


class SubstringRule(Rule):
    __slots__ = ('_regexp_obj', )

    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, netloc, domain, origin=None):
        if self.options and not self.options.can_apply_rule(domain, origin):
            return False
        return self._regexp_obj.search(url) is not None

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

        match_case = options.has_set('match-case') if options else False
        regexp_obj = _compile_wildcards(expression,
                                        '^' if fix_start else None,
                                        '$' if fix_end else None,
                                        match_case)

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
        if self.exclude_domains and domain in self.exclude_domains:
            return False
        if self.include_domains and domain not in self.include_domains:
            return False
        return True

    def has_set(self, keyword):
        try:
            return bool(self.options_mask & self.AVAILABLE_OPTIONS[keyword])
        except KeyError:
            raise ValueError('Unsupported option keyword: {}'.format(keyword))

    def __str__(self):
        option_str_list = []
        if self.exclude_domains or self.include_domains:
            domain_list = []
            if self.include_domains:
                domain_list += self.include_domains
            if self.exclude_domains:
                domain_list += ('~' + domain for domain in self.exclude_domains)
            option_str_list.append('domain=' + '|'.join(domain_list))
        for option, bitmask in self.AVAILABLE_OPTIONS.items():
            if self.options_mask & bitmask:
                option_str_list.append(option)
            if self.options_mask_negative & bitmask:
                option_str_list.append('~' + option)
        return ','.join(option_str_list)

    @classmethod
    def from_string(cls, option_str):
        option_parts = option_str.split(',')
        include_domains = []
        exclude_domains = []
        options_mask = 0
        for option_part in option_parts:
            if option_part in cls.AVAILABLE_OPTIONS:
                options_mask |= cls.AVAILABLE_OPTIONS[option_part]
            elif option_part.startswith('domain='):
                domains = option_part[len('domain='):].split('|')
                for domain in domains:
                    # domain=* will have the same effect as
                    # not having domain option set
                    if not domain or domain == '*':
                        continue
                    domain_list = include_domains if domain[0] != '~' else exclude_domains
                    domain_list.append(domain)
        return cls(include_domains=include_domains if include_domains else None,
                   exclude_domains=exclude_domains if exclude_domains else None,
                   options_mask=options_mask)


def _compile_wildcards(expression, prefix='', suffix='', match_case=False):
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
    return re.compile(''.join(regex_parts),
                      re.IGNORECASE if not match_case else 0)
