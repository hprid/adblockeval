from collections import defaultdict


class AhoCorasickIndex:
    def __init__(self, goto_fn, fail_fn, output_fn):
        self._goto_fn = goto_fn
        self._fail_fn = fail_fn
        self._output_fn = output_fn

    def get_matching_keywords(self, haystack):
        state = 0
        seen = set()
        for symbol in haystack:
            while True:
                index = (state, symbol)
                if index in self._goto_fn:
                    state = self._goto_fn[index]
                    break
                else:
                    # An non-existing index with state != 0 encodes a
                    # fail in the goto function. Note that goto(0, sigma)
                    # is defined to be 0, therefore, a non-existing index
                    # is not fail when state == 0.
                    if state == 0:
                        break
                    state = self._fail_fn[state]
            if state in self._output_fn:
                for keyword in self._output_fn[state]:
                    if keyword not in seen:
                        seen.add(keyword)
                        yield keyword

    @classmethod
    def from_keywords(cls, keywords, outputs=None):
        return cls(*_build_index(keywords, outputs))


def _build_index(keywords, outputs):
    if not keywords:
        return {}, {}, {}
    if outputs is None:
        outputs = range(len(keywords))
    # The goto function is basically a trie where there is some
    # special handling of the first state for non-"walkable"
    # symbols (see comment below)
    # goto_fn: (state, symbol) -> state | fail
    goto_fn = {}
    # The output function maps end states of keywords to the
    # keyword, so we know what matches.
    #  output_fn: state -> {keyword, ...}
    output_fn = defaultdict(set)
    state_counter = 0
    state_symbols = defaultdict(list)
    depths_states = defaultdict(list)
    depths_states[0] = [0]
    for keyword_output, keyword in zip(outputs, keywords):
        state = 0
        for depth, symbol in enumerate(keyword, start=1):
            try:
                new_state = goto_fn[state, symbol]
                goto_fn[state, symbol] = new_state
                state = new_state
            except KeyError:
                state_counter += 1
                depths_states[depth].append(state_counter)
                state_symbols[state].append(symbol)
                goto_fn[state, symbol] = state_counter
                state = state_counter
        output_fn[state].add(keyword_output)
    # Normally state == 0 and symbol not in {w_0 | w in keywords}
    # loops back to 0 in the goto function. However, we do not
    # model this explicitly but implicitly when accessing the
    # goto function.

    # Calculate the fail function
    # fail_fn: state -> state
    max_depth = max(len(keyword) for keyword in keywords)
    fail_fn = [0] * (state_counter + 1)
    for state in depths_states[1]:
        fail_fn[state] = 0
    for depth in range(2, max_depth + 1):
        for prev_state in depths_states[depth - 1]:
            for symbol in state_symbols[prev_state]:
                next_state = goto_fn[prev_state, symbol]
                state = fail_fn[prev_state]
                while True:
                    # This implicitly encodes g(0, sigma) != fail
                    if (state, symbol) in goto_fn or state == 0:
                        break
                    state = fail_fn[state]
                # This implicitly encodes g(0, sigma) != fail
                fail_value = goto_fn.get((state, symbol), 0)
                fail_fn[next_state] = fail_value
                if fail_value in output_fn:
                    output_fn[next_state].update(output_fn[fail_value])
    output_fn = dict(output_fn)
    return goto_fn, fail_fn, output_fn
