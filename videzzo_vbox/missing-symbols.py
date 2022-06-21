#!/usr/bin/python3

# With Clang, VBox always misses some symbols
# List these symbols and use this script to update include/iprt/mangling.h

symbols = []
with open('missing-symbols.txt') as f:
    for line in f:
        symbols.append(line.strip())


with open('generated-symbols.txt', 'w') as f:
    for symbol in symbols:
        f.write('# define {0}{1}RT_MANGLER({0})\n'.format(symbol, ' ' * (80 - len(symbol))))
