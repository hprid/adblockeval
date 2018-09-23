import unittest

from adblockeval.rules import AdblockRules, SubstringRule


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
        rules = AdblockRules(['/some/*.jpg'])
        self.assertTrue(rules.match(url)[0])
        rules.add_rules(['@@/some/exception.jpg'])
        self.assertFalse(rules.match(url).is_match)

    def test_regexp_rule(self):
        rule_list = ['/\\.science\\/[0-9]{2,9}\\/$/$script,third-party,']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('https://marchfor.science/1337/',
                                    origin='script').is_match)

    def test_domain_rule(self):
        rule_list = ['||adzbazar.com^$third-party']
        rules = AdblockRules(rule_list)
        self.assertTrue(rules.match('http:/adzbazar.com/').is_match)

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
