import unittest
from pathlib import Path

from adblockeval.rules import AdblockRules, SubstringRule, RuleParsingError, _get_regexp_keywords, _is_subdomain

EASYLIST_PATH = Path(__file__).parent / '../examples/easylist.txt'


class ParsingTest(unittest.TestCase):
    def test_standard_rule(self):
        rule_list = ['/ads/*.jpg']
        rules = AdblockRules(rule_list)

    def test_comment_rule(self):
        rule_list = [
            '! Some Comment',
            '',
            '/some/rule',
        ]
        rules = AdblockRules(rule_list)
        self.assertEqual(len(rules.rules), 1)

    def test_ignore_cosmetic(self):
        rule_list = [
            '###ad-lead',
            'cnet.com#@##adboard',
        ]
        rules = AdblockRules(rule_list)
        self.assertEqual(len(rules.rules), 0)

    def test_exception_rule(self):
        url = 'static/some/exception.jpg'
        rules = AdblockRules(['/some/*.jpg', '@@/some/exception.jpg'])
        self.assertFalse(rules.match(url).is_match)

    def test_regexp_rule(self):
        rule_list = ['/\\.science\\/[0-9]{2,9}\\/$/$script,third-party,']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('https://marchfor.science/1337/',
                                    origin='script').is_match)

    def test_domain_rule(self):
        rule_list = ['||adzbazar.com^$third-party']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('http://adzbazar.com/').is_match)

    def test_rule_fix_end(self):
        rule_list = ['/ad.php|']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('foo/ad.php').is_match)
        self.assertFalse(rules.match('foo/ad.phps').is_match)

    def test_rule_fix_start(self):
        rule_list = ['|javascript:*window.location$popup']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('javascript:foo;window.location=bar').is_match)
        self.assertFalse(rules.match('script=javascript:foo;window.location=bar').is_match)

    def test_substring_rule(self):
        expr = SubstringRule.from_expression('foo/*/bar^', None)
        self.assertTrue(expr.match('foo/qux/bar/', 'example.com', None))

    @unittest.skipIf(not EASYLIST_PATH.is_file(),
                     reason='Requires easylist.txt in examples')
    def test_load_easylist(self):
        with EASYLIST_PATH.open() as f:
            rules = AdblockRules(f.readlines())
        urls = [
            'https://imagesrv.adition.com/banners/268/00/86/70/52/images/konfetti.png',
            'https://match.adsrvr.org/track/cmf/generic?ttd_pid=theadex&ttd_puid=1001718401132270252&ttd_tpi=1',
            'https://s.hs-data.com/comon/prj/isdc/v3/default/static/js/lib/hammer.min.js',
            'https://ih.adscale.de/map?ssl=1&format=video',
        ]
        is_matches = [rules.match(url, 'www.example.com').is_match for url in urls]
        is_matches_expected = [True, True, False, True]
        self.assertEqual(is_matches, is_matches_expected)

    def test_match_case(self):
        rule_list = ['/FooBar$match-case']
        rules = AdblockRules(rule_list)
        match_not = rules.match('http://example.com/foobarqux', 'example.org')
        match = rules.match('http://example.com/FooBarqux', 'example.org')
        self.assertFalse(match_not.is_match)
        self.assertTrue(match.is_match)

    def test_match_case_regexp(self):
        rule_list = ['/com.*FooBar/$match-case']
        rules = AdblockRules(rule_list)
        match_not = rules.match('http://example.com/foobarqux', 'example.org')
        match = rules.match('http://example.com/FooBarqux', 'example.org')
        self.assertFalse(match_not.is_match)
        self.assertTrue(match.is_match)

    def test_invalid_regexp(self):
        with self.assertRaises(RuleParsingError):
            AdblockRules(['/[/'])
        AdblockRules(['/[/'], skip_parsing_errors=True)

    def test_match_slow_match_fast(self):
        urls = [
            'https://imagesrv.adition.com/banners/268/00/86/70/52/images/konfetti.png',
            'https://match.adsrvr.org/track/cmf/generic?ttd_pid=theadex&ttd_puid=1001718401132270252&ttd_tpi=1',
            'https://s.hs-data.com/comon/prj/isdc/v3/default/static/js/lib/hammer.min.js',
            'https://ih.adscale.de/map?ssl=1&format=video',
        ]
        rules = AdblockRules([
            '/banners/*',
            '/ttd_puid=\d+/',
            '||adscale.de^',
            'hammer*',
            '@@https://$domain=hs-data.com'
        ])
        for url in urls:
            self.assertEqual(rules.match(url, 'www.example.com'),
                             rules.match_slow(url, 'www.example.com'))

    def test_rule_no_index(self):
        rules = AdblockRules(['/[Aa](d[bB]lock|ds)/'])
        self.assertTrue(rules.match('http://example.com/adBlock/1.png',
                                    'example.com').is_match)

    def test_get_regexp_keywords(self):
        keywords = _get_regexp_keywords('foo?(bar|qux)(daz|doo)?\.([a-z]{3}|[0-9]{2}')
        self.assertEqual(keywords, {'fo', 'bar', 'qux'})

    def test_domain_option_parsing(self):
        rules = AdblockRules(['ads$domain=example.com|~example.org|example.net'])
        options = rules.rules[0].options
        self.assertEqual(['example.com', 'example.net'], options.include_domains)
        self.assertEqual(['example.org'], options.exclude_domains)

    def test_domain_applicability(self):
        rules = AdblockRules([
            '/foo*$domain=example.com|example.org',
            '||^adscale.de$$domain=example.com|example.org',
            '/[a-f]{3,7}/$domain=example.com|example.org',
            '/foo*$domain=~example.net',
            '||^adscale.de$$domain=~example.org',
            '/[a-f]{3,7}/$domain=~example.net'
        ])
        self.assertTrue(rules.match('http://example.net/foobar', 'example.com').is_match)
        self.assertTrue(rules.match('http://example.net/foobar', 'example.org').is_match)
        self.assertFalse(rules.match('http://example.net/foobar', 'example.net').is_match)
        self.assertTrue(rules.match('http://foo.adscale.de/', 'example.com').is_match)
        self.assertTrue(rules.match('http://foo.adscale.de/', 'example.org').is_match)
        self.assertFalse(rules.match('http://foo.adscale.de/', 'example.net').is_match)
        self.assertTrue(rules.match('http://example.net/afbd', 'example.com').is_match)
        self.assertTrue(rules.match('http://example.net/afbd', 'example.org').is_match)
        self.assertFalse(rules.match('http://example.net/afbd', 'example.net').is_match)

    def test_rule_formatting(self):
        rule_list = [
            '||adzbazar.com^$script,third-party,domain=example.com|example.org',
            '/adblock/$script,third-party,domain=example.com|~example.org',
            '/|ads/',
            'adbanner.png|'
        ]
        rules = AdblockRules(rule_list)
        for rule in rules.rules:
            self.assertEqual(rule_list[rule.line_no - 1], str(rule))

    def test_rule_options(self):
        rules = AdblockRules([
            'foo$script,~stylesheet,domain=*'
        ])
        rule = rules.rules[0]
        self.assertTrue(rule.options.has_included('script'))
        self.assertTrue(rule.options.has_excluded('stylesheet'))
        self.assertIsNone(rule.options.include_domains)
        with self.assertRaises(ValueError):
            rule.options.has_included('nonexistingoption')
        with self.assertRaises(ValueError):
            rule.options.has_excluded('nonexistingoption')

    def test_is_subdomain(self):
        self.assertTrue(_is_subdomain('foo.example.org', 'example.org'))
        self.assertTrue(_is_subdomain('bar.foo.example.org', 'example.org'))
        self.assertTrue(_is_subdomain('example.org', 'example.org'))
        self.assertFalse(_is_subdomain('noexample.org', 'example.org'))
