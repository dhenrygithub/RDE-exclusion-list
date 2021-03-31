#!/usr/bin/env python
#

if __name__ == '__main__':

    with open('database.csv') as check_file:
        check_set = set([row.split(',')[1].strip().upper() for row in check_file])

    with open('candidates.csv', 'r') as in_file, open('file3.csv', 'w') as out_file:
        for line in in_file:
            if line.split(',')[0].strip().upper() in check_set:
                out_file.write(line)
