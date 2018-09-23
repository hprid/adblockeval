import unittest

from adblockeval.ahocorasick import AhoCorasickIndex


class AhoCoraSickTest(unittest.TestCase):
    def test_build_index(self):
        # This example is taken from:
        # Aho, Corasick. Efficient String Matching: An Aid to Bibliographic
        # search. Communications of the ACM, 18(6), 333-340. 1975.
        # PDF: https://cr.yp.to/bib/1975/aho.pdf
        keywords = ['he', 'she', 'his', 'hers']
        index = AhoCorasickIndex.from_keywords(keywords)
        self.assertEqual(index._goto_fn, {
            (0, 'h'): 1,
            (0, 's'): 3,
            (1, 'e'): 2,
            (1, 'i'): 6,
            (2, 'r'): 8,
            (3, 'h'): 4,
            (4, 'e'): 5,
            (6, 's'): 7,
            (8, 's'): 9
        })
        self.assertEqual(index._fail_fn,
                         [0, 0, 0, 0, 1, 2, 0, 3, 0, 3])
        he = keywords.index('he')
        she = keywords.index('she')
        his = keywords.index('his')
        hers = keywords.index('hers')
        self.assertEqual(index._output_fn, {
            2: {he},
            5: {she, he},
            7: {his},
            9: {hers}
        })

    def test_keywords_match_single(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_foo = index.get_matching_keywords('XXfooXXX')
        self.assertSequenceEqual([0], sorted(result_foo))

    def test_keywords_match_both(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_both = index.get_matching_keywords('XXfooXXbarXX')
        self.assertSequenceEqual([0, 1], sorted(result_both))

    def test_no_match(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_both = index.get_matching_keywords('anfobaxdummy')
        self.assertSequenceEqual([], sorted(result_both))

    def test_keywords_match_both_consecutive(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_both = index.get_matching_keywords('XXfoobarXX')
        self.assertSequenceEqual([0, 1, 2], sorted(result_both))

    def test_keywords_match_beginning(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_foo = index.get_matching_keywords('fooXX')
        self.assertSequenceEqual([0], sorted(result_foo))

    def test_keywords_match_end(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_foo = index.get_matching_keywords('XXfoo')
        self.assertSequenceEqual([0], sorted(result_foo))

    def test_keywords_match_full(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result_foo = index.get_matching_keywords('foo')
        self.assertSequenceEqual([0], sorted(result_foo))

    def test_empty_keywords(self):
        index = AhoCorasickIndex.from_keywords([])
        result_foo = index.get_matching_keywords('foo')
        self.assertSequenceEqual([], sorted(result_foo))

    def test_empty_string_keyword(self):
        keywords = ['foo', '', 'bar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result = index.get_matching_keywords('quxbax')
        self.assertSequenceEqual([1], sorted(result))

    def test_empty_string_haystack(self):
        keywords = ['foo', 'bar', 'foobar']
        index = AhoCorasickIndex.from_keywords(keywords)
        result = index.get_matching_keywords('')
        self.assertSequenceEqual([], sorted(result))

    def test_failfn_step2b(self):
        keywords = ['ad', 'bac']
        index = AhoCorasickIndex.from_keywords(keywords)
        result = index.get_matching_keywords('labac')
        self.assertSequenceEqual([1], sorted(result))
