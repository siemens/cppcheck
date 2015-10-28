#/usr/bin/python
#
# cppcheck addon for Y2038 safeness detection
#
# Example usage:
# $ cppcheck --dump path-to-src/
# $ python addons/y2038.py path-to-src/*.dump
#

import cppcheckdata
import sys
import re

def reportDirError(directive, severity, msg):
    sys.stderr.write('(' + severity + ') [' + directive.cfg + '] '
		     + directive.file + ':'
		     + str(directive.linenr) + ' '
		     + directive.str + ' : ' + msg + '\n')

def reportTokError(token, severity, msg):
    sys.stderr.write('(' + severity + ') '
		     + token.file + ':'
		     + str(token.linenr) + ' '
		     + token.str + ' : ' + msg + '\n')

# Match _TIME_BITS definitions

re_y2038_correct_64_bit_support = re.compile('^\s*#\s*define\s+_TIME_BITS\s+64\s*$')
re_y2038_incorrect_bit_support = re.compile('^\s*#\s*define\s+_TIME_BITS\s+.*$')
re_y2038_undef_bit_support = re.compile('^\s*#\s*undef\s+_TIME_BITS\s*$')

# List of Y2038-sensitive identifiers

id_Y2038 = ['clock_gettime']

for arg in sys.argv[1:]:
    if not arg[-5:] == '.dump':
        continue
    print('Checking ' + arg + '...')
    y2038safe = False
    data = cppcheckdata.parsedump(arg)
    directive = data.directivelist[0]
    token = data.tokenlist[0]
    cfg = None
    while directive or token:
	if directive and directive.cfg != cfg:
		cfg = directive.cfg
		token = data.tokenlist[0]
	linenr = 1000000
	if directive and int(directive.linenr) < linenr:
		linenr = int(directive.linenr)
	if token and int(token.linenr) < linenr:
		linenr = int(token.linenr)
	if directive and linenr == int(directive.linenr):
		if re_y2038_correct_64_bit_support.match(directive.str):
			y2038safe = True
		elif re_y2038_incorrect_bit_support.match(directive.str):
			y2038safe = False
		elif re_y2038_undef_bit_support.match(directive.str):
			y2038safe = False
		directive = directive.next
	if token and linenr == int(token.linenr):
		if token.str in id_Y2038 and not y2038safe:
			reportTokError(token, 'Y2038', token.str
			                 + ' may not be Y2038-proof'
					 + ' (cfg: ' + cfg + ')')
		token = token.next
