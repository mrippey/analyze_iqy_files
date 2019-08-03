#!/usr/bin/env python3
#
# analyze_iqy.py
# Author: Mike
#
# Twitter: @nahamike01

"""
Purpose: Intrusion detection, endpoint and network analysis all intrigue me in addition to Python.
Still learning the language, I use these small projects to grasp certain concepts and gain confidence.
"""
import pandas as pd
import argparse
import os.path
import sys
import time
import yara
import pprint

# Ensure script is only reading an .iqy file, if not exit. Use Pandas to pull information from file and print it.
def discover_contents(f_path):
    if f_path.endswith('iqy'):
        read_in_iqy = pd.read_csv(f_path)
        df = pd.DataFrame(read_in_iqy)
    else:
        print("Wrong File Type Encountered. Exiting...")
        sys.exit(1)

    print('Information Extracted From File: \n%s' % df)

    print("\n")

    print("Possible Date File Last Modified: %s" % time.ctime(os.path.getmtime(f_path)))

    print("-"*100)

'''
Yara rule for the .iqy file courtesy of @ItsReallyNick 
https://www.fireeye.com/blog/products-and-services/2018/12/detect-and-block-email-threats-with-custom-yara-rules.html

'''
def test_against_yar():
    print("Yara Reults: \n")
    rules = yara.compile('/path/where_your/rules_are/iqy.yar')
    matches = rules.match('/path_to/suspect_file/.iqy')
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(matches)
    print("-"*100)


def main():
    parser = argparse.ArgumentParser(
        description="Investigate Suspicious .iqy Files.")
    parser.add_argument('file', nargs=1, help='Provide the path of the .iqy file to be checked.')

    args = parser.parse_args()

    for f in args.file:
        discover_contents(f)
        test_against_yar()


if __name__ == '__main__':
    main()








'''
Another option utilizing regex. Still needs tweaking, don't care for how it looks.

import re
    with open(path) as file:
        for item in file:
            try:
                urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+/+[^/\\&\?]+', item)
            except re.error:
                pass
            print(urls[:])
'''