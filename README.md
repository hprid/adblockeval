# adblockeval

[![Build Status](https://travis-ci.org/hprid/adblockeval.svg?branch=master)](https://travis-ci.org/hprid/adblockeval)
[![codecov](https://codecov.io/gh/hprid/adblockeval/branch/master/graph/badge.svg)](https://codecov.io/gh/hprid/adblockeval)

Evaluates URLs against AdBlock rules efficiently to check which rules would 
block them, if any. It applies Aho-Corasick string matching to reduce the 
number of AdBlock rules that have to be evaluated.

## Status
This project is currently under development. It is already usable, but not
yet well tested against the real world data.
