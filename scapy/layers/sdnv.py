#!/usr/bin/python


# Copyright 2012, The MITRE Corporation
#
#                             NOTICE
#    This software/technical data was produced for the U.S. Government
#    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
#      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
#        and Article GP-51, Rights in Data  General, respectively.
#    
#      This software is publicly released under MITRE case #12-3054


from sys import *
from random import * # For testing

def displayHex(bytes):
    i = 0
    for b in bytes:
        if i%16==0:
            rint('\n%02x: ' % i)
        print('%02x' % b)
        i += 1
    print('\n')

class SDNVValueError(Exception):
    def __init__(self, maxValue):
        self.maxValue = maxValue
            
class SDNV:
    def __init__(self, maxValue=2**32-1):
        self.maxValue = maxValue
        return
    
    def setMax(self, max):
        self.maxValue = maxValue
    
    def getMax(self):
        return self.maxValue
    
    def encode(self, number):
        if number>self.maxValue:
            raise SDNVValueError(self.maxValue)
        
        foo = bytearray()
        foo.append(number & 0x7F)
        number = number >> 7
        
        while ( number > 0 ):
            thisByte = number & 0x7F
            thisByte |= 0x80
            number = number >> 7
            temp = bytearray()
            temp.append(thisByte)
            foo = temp+foo
            
        return(foo)
        
    def decode(self, bytes, offset):
        number = 0
        numBytes = 1
        
        b = ba[offset]
        number = (b & 0x7F)
        while (b & 0x80 == 0x80):
            number = number << 7
            if ( number > self.maxValue ):
                raise SDNVValueError(self.maxValue)
            b = ba[offset+numBytes]
            number += (b & 0x7F)
            numBytes += 1
        if ( number > self.maxValue ):
            raise SDNVValueError(self.maxValue)
        return(number, numBytes)
        
def toSDNV(number):
    foo = bytearray()
    foo.append(number & 0x7F)
    number = number >> 7
    
    while ( number > 0 ):
        thisByte = number & 0x7F
        thisByte |= 0x80
        number = number >> 7
        temp = bytearray()
        temp.append(thisByte)
        foo = temp+foo
        
    return(foo)

def lenOfEncodedSDNV(number):
    foo = toSDNV(number)
    return len(foo)

def extractSDNVFromByteArray(ba, offset):
    number = 0
    numBytes = 1
    
    b = ba[offset]
    number = (b & 0x7F)
    while (b & 0x80 == 0x80):
        number = number << 7
        b = ba[offset+numBytes]
        number += (b & 0x7F)
        numBytes += 1
    return(number, numBytes)

def doTestVector(vec):        
    # Test numbers individually
    for n in vec:
        ba = toSDNV(n)
        (num, sdnvLen) = extractSDNVFromByteArray(ba, 0)
        if num != n:
            print("Error encoding/decoding", n)
            return False
     
    # Encode them all in a bunch
    ba = bytearray()
    for n in vec:
        temp = toSDNV(n)
        ba = ba+temp
    
    offset = 0
    outNums = []
    for n in vec:
        (num, sdnvLen) = extractSDNVFromByteArray(ba, offset)
        outNums.append(num)
        offset += sdnvLen
        
    if outNums!=vec:
        print("Failed on multi-number encode/decode")
        return False
    
    return True

def doRandomTestVector(howMany):
    vec = []
    for i in range(0, howMany):
        vec.append(randint(0, maxint))
    result = doTestVector(vec)
    return result

def doTests():
    strings = ["yip", "yow", "nibble"]
    for s in strings:
        ba = bytearray(s)
        print("ba is", ba, "of length", len(ba))
        displayHex(ba)
    
    # Several small integers
    ba = bytearray()
    theNums = [0,1,2,5,126,127,128,129,130,150,190,220,254,255,256]
    print("Doing test vector:", theNums)
    result = doTestVector(theNums)
    if result!= True:
        print("doTestVector failed on:", theNums)
    else:
        print("Success")
        
    theNums = [0,1,0,1,0,128,32765, maxint-10, 4, 32766, 32767, 32768, 32769]
    print("Doing test vector:", theNums)
    result = doTestVector(theNums)
    if result!= True:
        print("doTestVector failed on:", theNums)
    else:
        print("Success")

    numToDo = 100
    print("Doing random vector", numToDo)
    result = doRandomTestVector(numToDo)
    if result!= True:
        print("doTestVector failed on:", theNums)
    else:
        print("Success")
    
    # Tests using the SDNV class
    s = SDNV(30)
    b = s.encode(17)
    theNums = [0,4,20,29,30,31,33]
    for n in theNums:
        try:
            b = s.encode(n)
        except SDNVValueError as e:
            print("Could not encode", n, "-- maximum value is:", e.maxValue)
    
if __name__ == "__main__":
    doTests()
