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
        if rule_list is not None:
            self.add_rules(rule_list)

    def add_rules(self, rule_list):
        self.rules += self._parse_rules(rule_list)

    def _parse_rules(self, rule_list):
        for rule_str in rule_list:
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
                yield self._parse_rule(rule_str)
            except RuleParsingError as e:
                if not self.skip_parsing_errors:
                    raise

    def match(self, url, domain=None, origin=None):
        if domain is None:
            domain = urlparse(url).netloc
        matching_rules = []
        for rule in self.rules:
            if rule.match(url, domain, origin):
                if rule.is_exception:
                    return MatchResult(False, [rule])
                matching_rules.append(rule)
        return MatchResult(bool(matching_rules), matching_rules)

    def _parse_rule(self, rule_str):
        is_exception = False

        parts = rule_str.rsplit('$', 1)
        expression = parts[0]
        options = self._parse_options(parts[1]) if len(parts) == 2 else None

        # Exception rules
        if expression.startswith('@@'):
            is_exception = True
            expression = expression[2:]

        # Regexp rules
        if '/$/' in expression:
            rule = RegexpRule.from_expression(expression, options)
        # Domain rules. According to uBlock manual, any rule that looks
        # like a hostname does not match as substring but as domain.
        elif expression.startswith('||') or _HOSTNAME_REGEX.match(expression):
            rule = DomainRule.from_expression(expression, options)
        # Substring rules
        else:
            rule = SubstringRule.from_expression(expression, options)

        rule.is_exception = is_exception

        return rule

    def _parse_options(self, option_str):
        # FIXME: Implement this
        return None


class RuleParsingError(Exception):
    pass


class Rule:
    def __init__(self, expression, options):
        self.expression = expression
        self.options = options
        self.is_exception = False

    def match(self, url, domain, origin=None):
        raise NotImplemented

    def __str__(self):
        return '@@' + self.expression if self.is_exception else self.expression


class RegexpRule(Rule):
    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, domain, origin=None):
        return self._regexp_obj.search(url) is not None

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with / and ends with /$
        if not expression.startswith('/') and expression.endswith('/$'):
            raise RuleParsingError('Not a regular expression rule: {}'.format(expression))
        pattern = expression[1:-2]
        try:
            regexp_obj = re.compile(pattern)
        except re.error:
            raise RuleParsingError('Invalid regular expression {}'.format(pattern))
        return cls(expression, options, regexp_obj)


class DomainRule(Rule):
    def __init__(self, expression, options, domain, regexp_obj):
        super().__init__(expression, options)
        self._domain = domain
        self._regexp_obj = regexp_obj

    def match(self, url, domain, origin=None):
        return self._regexp_obj.search(domain) is not None

    @classmethod
    def from_expression(cls, expression, options):
        # Expression starts with || and often ends with ^ which
        # however makes no sense, since these characters cannot
        # be part of a doamin
        domain = expression[2:].rstrip('^')
        regexp_obj = _compile_wildcards(domain, fix_start=True, fix_end=True)
        return cls(expression, options, domain, regexp_obj)


class SubstringRule(Rule):
    def __init__(self, expression, options, regexp_obj):
        super().__init__(expression, options)
        self._regexp_obj = regexp_obj

    def match(self, url, domain, origin=None):
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

        regexp_obj = _compile_wildcards(expression, fix_start, fix_end)

        return cls(origin_expression, options, regexp_obj)


def _compile_wildcards(expression, fix_start, fix_end):
    """Translate the expression into a regular expression.
    A star matches anything, while ^ is a placeholder for a single separator
    character. According to the docs, "Separator character is anything but a
    letter, digit, or one of the following: _ - . %"
    """
    wildcards = [(match.start(), match.group(0))
                 for match in re.finditer('[*^]', expression)]
    regex_parts = ['^'] if fix_start else []
    start = 0
    for pos, wildard_type in wildcards:
        regex_parts.append(re.escape(expression[start:pos]))
        regex_parts.append('.*' if wildard_type == '*' else '[^a-zA-Z0-9._%-]')
        start = pos + 1
    if start < len(expression):
        regex_parts.append(re.escape(expression[start:]))
    if fix_end:
        regex_parts.append('$')
    return re.compile(''.join(regex_parts))
