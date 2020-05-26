"""
File Secure can be used to encrypt and decrypt your files using
AES 128, 192 and 256. This application has been tested on text, images and
video formats
Author: Aseem Mehta
email: am1435@rit.edu
"""

try:
    from Tkinter import *
    from Tkinter import filedialog
except:
    from tkinter import *
    from tkinter import filedialog
    
import copy, math, random
import concurrent.futures

"""
Class contains functions which are common to all other classes
"""
class All:
    
    #Performs Matrix multiplication MixColumn layer
    def multiply (a, b) :
        # making b as the smaller number
        if a < b :
            a, b = b, a
        sum = 0
        while b > 0:
            if b & 1:
                # if b is odd
                sum ^= a
            a <<= 1
            b >>= 1
            # if a overflows
            if (a & 0x100 ) :
                a ^= 0x11B
        return sum % 0x11B
    
    #Performs Matrix multiplication MixColumn layer
    def column_operation ( col , matrix ) :
        result = []
        for i in range (4) :
            res = 0
            for j in range (4) :
                res^= All.multiply ( matrix [ i ][ j ] , col [ j ])
            result.append("%0.2X"%(res))
        return result
    
    
    #prodives s-box values
    def sboxx(a):
        val1 = int(a[0],16)
        val2 = int(a[1],16)
        Sbox = [
                [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
                [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
                [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
                [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
                [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
                [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
                [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
                [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
                [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
                [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
                [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
                [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
                [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
                [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
                [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
                [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]

        return "%0.2X"%(Sbox[(val1)][(val2)])    
    
    
    #performs xor between s box value and round coefficient for w0+4i of key
    def roundCoefficient(s0,subKeyRound):
        if subKeyRound < 9:
            rcValue = 2**(subKeyRound-1)
        elif subKeyRound == 9:
            rcValue = 27
        elif subKeyRound == 10:
            rcValue = 54
        return int(s0,16)^rcValue

    # Provides the gFunction values
    def gFunction(w,subKeyRound):
        v0 = w[2:4]
        v1 = w[4:6]
        v2 = w[6:8]
        v3 = w[8:]
        # shuffle and s-box value
        s0 = hex(All.roundCoefficient(All.sboxx(v1),subKeyRound))
        s1 = All.sboxx(v2)
        s2 = All.sboxx(v3)
        s3 = All.sboxx(v0)
        return int(s0+s1+s2+s3,16)


"""
Class is used to generate AES 128 Key and all the round Keys
"""
class AESkey:
    
    #Generates 128 bit Key
    def keygenerator(folderPath):
        key = random.getrandbits(128)
        f = open(folderPath+"Key.txt","w+")
        key = "0x%0.32X"%(key)
        f.write(key)
        f.close()
        return key

    # Helps generate every round key using preious keys
    def subKeyGenerator(previousKey,subKeyRound):
        prevW0,prevW1,prevW2,prevW3 = int(previousKey[0][2:],16),\
                        int(previousKey[1][2:],16),int(previousKey[2][2:],16),int(previousKey[3][2:],16)    
        nextW0 = prevW0^All.gFunction(previousKey[3],subKeyRound)

        nextW1 = nextW0^prevW1
        nextW2 = nextW1^prevW2
        nextW3 = nextW2^prevW3
        nextKey = ["0x%0.8X"%nextW0,"0x%0.8X"%nextW1,"0x%0.8X"%nextW2,"0x%0.8X"%nextW3]

        return nextKey
    # generates all subkeys
    def keyTransform(key):
        subkey = 11
        w0 = key[0:10]
        w1 = "0x"+key[10:18] 
        w2 = "0x"+key[18:26]
        w3 = "0x"+key[26:] 
        key0 = [w0,w1,w2,w3]    
        key = [key0]
        for subKeyRound in range(1,subkey):
            key.append(AESkey.subKeyGenerator(key[subKeyRound-1],subKeyRound))
        return key

"""
Class is used to generate 192 128 Key and all the round Keys
"""
class AES192:
    
    #Generates 192 bit Key
    def keygenerator(folderPath):
        key = random.getrandbits(192)
        f = open(folderPath+"Key.txt","w+")
        key = "0x%0.48X"%(key)
        f.write(key)
        f.close()
        return key

    # Helps generate every round key using preious keys
    def subKeyGenerator(previousKey,subKeyRound):
        prevW0,prevW1,prevW2,prevW3,prevW4,prevW5 = int(previousKey[0][2:],16),int(previousKey[1][2:],16),\
                                                int(previousKey[2][2:],16),int(previousKey[3][2:],16),\
                                                int(previousKey[4][2:],16),int(previousKey[5][2:],16) 
        
        nextW0 = prevW0^All.gFunction(previousKey[5],subKeyRound)        
        nextW1 = nextW0^prevW1
        nextW2 = nextW1^prevW2
        nextW3 = nextW2^prevW3
        # Last round only has 4 bytes
        if subKeyRound != 8:
            nextW4 = nextW3^prevW4
            nextW5 = nextW4^prevW5                
            nextKey = ["0x%0.8X"%nextW0,"0x%0.8X"%nextW1,"0x%0.8X"%nextW2,"0x%0.8X"%nextW3,"0x%0.8X"%nextW4,"0x%0.8X"%nextW5]
        else:
            nextKey = ["0x%0.8X"%nextW0,"0x%0.8X"%nextW1,"0x%0.8X"%nextW2,"0x%0.8X"%nextW3]
        return nextKey
    
    # generates all subkeys
    def keyTransform(key):
        numberRound = 9
        w0 = key[0:10]
        w1 = "0x"+key[10:18] 
        w2 = "0x"+key[18:26]
        w3 = "0x"+key[26:34] 
        w4 = "0x"+key[34:42]
        w5 = "0x"+key[42:]
        subKey = [w0,w1,w2,w3,w4,w5]
        tempKey = copy.deepcopy(subKey)

        for subKeyRound in range(1,numberRound):
            subKey = AES192.subKeyGenerator(subKey,subKeyRound)
            tempKey = tempKey+subKey
        
        key = []
        for i in range(0,len(tempKey),4):
            key.append(tempKey[i:i+4])
        return key    

"""
Class is used to generate AES 256 Key and all the round Keys
"""
class AES256:
    # Performs h-function
    def hFunction(w):
        v0 = w[2:4]
        v1 = w[4:6]
        v2 = w[6:8]
        v3 = w[8:]
        # shuffle and s-box value
        s0 = All.sboxx(v0)
        s1 = All.sboxx(v1)
        s2 = All.sboxx(v2)
        s3 = All.sboxx(v3)
        return int(s0+s1+s2+s3,16)
    
    #Generates 256 bit Key
    def keygenerator(folderPath):
        key = random.getrandbits(256)
        f = open(folderPath+"Key.txt","w+")
        key = "0x%0.64X"%(key)
        f.write(key)
        f.close()

        return key

    # Helps generate every round key using preious keys
    def subKeyGenerator(previousKey,subKeyRound):
        prevW0,prevW1,prevW2,prevW3,prevW4,prevW5,prevW6,prevW7 = int(previousKey[0][2:],16),\
                                                int(previousKey[1][2:],16),int(previousKey[2][2:],16),\
                                                int(previousKey[3][2:],16),int(previousKey[4][2:],16),\
                                                int(previousKey[5][2:],16),int(previousKey[6][2:],16),\
                                                int(previousKey[7][2:],16)
        
        nextW0 = prevW0^All.gFunction(previousKey[7],subKeyRound)        
        nextW1 = nextW0^prevW1
        nextW2 = nextW1^prevW2
        nextW3 = nextW2^prevW3
        
        if subKeyRound != 8:
            nextW4 = AES256.hFunction("0x%0.8X"%nextW3)^prevW4
            nextW5 = nextW4^prevW5
            nextW6 = nextW5^prevW6
            nextW7 = nextW6^prevW7
            nextKey = ["0x%0.8X"%nextW0,"0x%0.8X"%nextW1,"0x%0.8X"%nextW2,"0x%0.8X"%nextW3,\
                       "0x%0.8X"%nextW4,"0x%0.8X"%nextW5,"0x%0.8X"%nextW6,"0x%0.8X"%nextW7]
        else:
            nextKey = ["0x%0.8X"%nextW0,"0x%0.8X"%nextW1,"0x%0.8X"%nextW2,"0x%0.8X"%nextW3]
        return nextKey
    
    # generates all subkeys
    def keyTransform(key):
        numberRound = 8
        w0 = key[0:10]
        w1 = "0x"+key[10:18] 
        w2 = "0x"+key[18:26]
        w3 = "0x"+key[26:34] 
        w4 = "0x"+key[34:42]
        w5 = "0x"+key[42:50]
        w6 = "0x"+key[50:58]
        w7 = "0x"+key[58:]
        subKey = [w0,w1,w2,w3,w4,w5,w6,w7]
        tempKey = copy.deepcopy(subKey)
        
        for subKeyRound in range(1,numberRound):
            subKey = AES256.subKeyGenerator(subKey,subKeyRound)
            tempKey = tempKey+subKey
        key = []
        for i in range(0,len(tempKey),4):
            key.append(tempKey[i:i+4])
        return key

"""
Class Uses AES key to encrypt data
"""
class Encryption:
    
    # performs mixcolumn opreration
    def mixColumn(shiftedRows):
        mix = [
        [0x02,0x03,0x01,0x01],
        [0x01,0x02,0x03,0x01],
        [0x01,0x01,0x02,0x03],
        [0x03,0x01,0x01,0x02]
        ]
        mixColumn = []
        for row in shiftedRows: 
            row_int = list ( map ( lambda x :  int(x,16) , row ) )
            mixColumn.append(All.column_operation (row_int,mix))
        return mixColumn

    #performs first key addition before any round statrs
    def firstkeyaddition(subText,subKey):
        return [("%0.2X"%(subText[0]^int(subKey[2:4],16))),("%0.2X"%(subText[1]^int(subKey[4:6],16)))\
                   ,("%0.2X"%(subText[2]^int(subKey[6:8],16))),("%0.2X"%(subText[3]^int(subKey[8:],16)))]

    # performs byte substitituion
    def byteSubstitution(text):
        byteSubstitution = []
        for smallBlock in text:
            byteSubstitution.append([All.sboxx(smallBlock[0]),All.sboxx(smallBlock[1]),\
                                     All.sboxx(smallBlock[2]),All.sboxx(smallBlock[3])])    
        return byteSubstitution

    # performs block shifts
    def shiftRows(byteSubstitution):
        shiftedRows = copy.deepcopy(byteSubstitution)
        shiftedRows[0][1],shiftedRows[0][2],shiftedRows[0][3] = byteSubstitution[1][1],\
                                                    byteSubstitution[2][2],byteSubstitution[3][3]
        shiftedRows[1][1],shiftedRows[1][2],shiftedRows[1][3] = byteSubstitution[2][1],\
                                                    byteSubstitution[3][2],byteSubstitution[0][3]
        shiftedRows[2][1],shiftedRows[2][2],shiftedRows[2][3] = byteSubstitution[3][1],\
                                                    byteSubstitution[0][2],byteSubstitution[1][3]
        shiftedRows[3][1],shiftedRows[3][2],shiftedRows[3][3] = byteSubstitution[0][1],\
                                                    byteSubstitution[1][2],byteSubstitution[2][3]
        return shiftedRows
    
    # performs key addition at the end of a round
    def roundEndKeyAddition(mixValue,subKey):
        roundEndAddition = []
        for i in range(4):
            roundEndAddition.append([("%0.2X"%(int(mixValue[i][0],16)^int(subKey[i][2:4],16))),("%0.2X"%(int(mixValue[i][1],16)^int(subKey[i][4:6],16)))\
                                     ,("%0.2X"%(int(mixValue[i][2],16)^int(subKey[i][6:8],16))),("%0.2X"%(int(mixValue[i][3],16)^int(subKey[i][8:],16)))])
        return roundEndAddition

    # calls all the functions consisting of one round of operations
    def encryptText(text,key):
        byteSubstitute = Encryption.byteSubstitution(text)
        shiftedRows = Encryption.shiftRows(byteSubstitute)
        mixValue = Encryption.mixColumn(shiftedRows)
        roundComplete = Encryption.roundEndKeyAddition(mixValue,key)
        return roundComplete

    # calls all the functions consisting of last round of operations
    def lastRoundEncryptText(text,key):
        byteSubstitute = Encryption.byteSubstitution(text)
        shiftedRows = Encryption.shiftRows(byteSubstitute)
        roundComplete = Encryption.roundEndKeyAddition(shiftedRows,key)
        return roundComplete

    # writes the encrypted data to file
    def writeFile(fileName,data):
        dataString = ""
        for dataList1 in data:
            for dataList2 in dataList1:
                for dataList3 in dataList2:
                    dataString += dataList3
        f = open(fileName,"w+")
        f.write(dataString)
        f.close()

    # reads file which needs to be encrypted
    def readfile(fileName):
        #with open("Text.txt", mode='rb') as file: # b is important -> binary
        f=open(fileName,"rb")
        num=list(f.read())
        f.close()
        length = len(num)
        iteration = math.ceil(length/16)
        blocks = []
        for i in range(iteration):
            tempblock = num[(0+(16*i)):(16+(16*i))]
            blocks.append(tempblock)
        return blocks

    def runHelp(textBlock,key):
        if len(textBlock) <16:
            textBlock = textBlock + [0]*(16-len(textBlock)-1)+[16-len(textBlock)-1]
        firstKeyAddition = []
        for i in range(0,16,4):
            firstKeyAddition.append(Encryption.firstkeyaddition(textBlock[i+0:i+4],key[0][int(i/4)]))   
        for j in range(1,len(key)-1):
            firstKeyAddition = Encryption.encryptText(firstKeyAddition,key[j])           
        return Encryption.lastRoundEncryptText(firstKeyAddition,key[-1])
        #return firstKeyAddition

    # runs the Encryption
    def run(fileName,AESchoice,folderPath):
        if AESchoice == '128':
            key1 = AESkey.keygenerator(folderPath)
            key = AESkey.keyTransform(key1)
        elif AESchoice == '192':
            key1 = AES192.keygenerator(folderPath)
            key = AES192.keyTransform(key1)
        elif AESchoice == '256':
            key1 = AES256.keygenerator(folderPath)
            key = AES256.keyTransform(key1)
        text = Encryption.readfile(fileName)
        key = [key]*len(text)
        encryptedText = []
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(Encryption.runHelp,text,key)
            for result in results:
                encryptedText.append(result)

        Encryption.writeFile(folderPath+"encryptedFile.txt",encryptedText)
        return "File Encrypted","encryptedFile.txt",key1


"""
Class performs Decryption of encrypted data
"""
class Decryption:
    # performs mixColumn operation
    def invMixColumn(text):
        mix_inv = [
        [0x0E , 0x0B , 0x0D, 0x09],
        [0x09 , 0x0E , 0x0B, 0x0D],
        [0x0D , 0x09 , 0x0E, 0x0B],
        [0x0B , 0x0D ,0x09, 0x0E]]

        invMixColumn = []
        for row in text: 
            row_int = list ( map ( lambda x :  int(x,16) , row ) )
            invMixColumn.append(All.column_operation (row_int,mix_inv))
        return invMixColumn
    
    # reads the encrypted file
    def readfile(fileName):
        AllBytes=[]
        with open(fileName, "rb") as f:
            byte = f.read(2)
            i = 0
            while byte != b"":
                i+=1
                # Do stuff with byte.
                AllBytes.append(byte)
                byte = f.read(2)
        EncryptedData = []
        for i in range(math.ceil(len(AllBytes)/16)):
            EncryptedData.append(AllBytes[(0+(16*i)):(16+(16*i))])
        return EncryptedData

    # provides the inv s-box values
    def invSbox(b):
        val1 = int(b[0],16)
        val2 = int(b[1],16)

        inv_Sbox = [[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
                [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
                [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
                [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
                [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
                [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
                [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
                [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
                [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
                [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
                [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
                [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
                [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
                [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
                [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
                [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]

        return "%0.2X"%(inv_Sbox[(val1)][(val2)])    

    # Performs first key addition for decryption (last key of generated key)
    def firstKeyDecrypter(subText,subKey):
        return [("%0.2X"%(int(subText[0],16)^int(subKey[2:4],16))),("%0.2X"%(int(subText[1],16)^int(subKey[4:6],16)))\
                   ,("%0.2X"%(int(subText[2],16)^int(subKey[6:8],16))),("%0.2X"%(int(subText[3],16)^int(subKey[8:],16)))]

    # Inverts the shift row operation performed in encryption
    def invShiftRows(text):
        shiftedRows = copy.deepcopy(text)

        shiftedRows[0][1],shiftedRows[0][2],shiftedRows[0][3] = text[3][1],text[2][2],text[1][3]
        shiftedRows[1][1],shiftedRows[1][2],shiftedRows[1][3] = text[0][1],text[3][2],text[2][3]
        shiftedRows[2][1],shiftedRows[2][2],shiftedRows[2][3] = text[1][1],text[0][2],text[3][3]
        shiftedRows[3][1],shiftedRows[3][2],shiftedRows[3][3] = text[2][1],text[1][2],text[0][3]
        return shiftedRows

    # Inverts byte substitution operation performed in encryption
    def invByteSubstitution(invShiftedRows):
        invByteSubstitute = []
        for smallBlock in invShiftedRows:
            invByteSubstitute.append([Decryption.invSbox(smallBlock[0]),Decryption.invSbox(smallBlock[1]),\
                                      Decryption.invSbox(smallBlock[2]),Decryption.invSbox(smallBlock[3])])
        return invByteSubstitute

    # Calls all functions for first round of decryption
    def decryptFirstText(textBlock,key):
        decryption = []
        for i in range(0,16,4):
            decryption.append(Decryption.firstKeyDecrypter(textBlock[i+0:i+4],key[-1][int(i/4)]))    
        invShiftRowsList = Decryption.invShiftRows(decryption) 
        invByteSubstitute = Decryption.invByteSubstitution(invShiftRowsList)
        return invByteSubstitute 

    # Operation: key addition
    def keyAddition(text,key):
        decryption = []
        for i in range(0,16,4):
            decryption.append(Decryption.firstKeyDecrypter(text[int(i/4)],key[int(i/4)]))
        return decryption

    # Calls all functions for all round of decryption exceept first
    def decryptText(text,key):
        decryption = Decryption.keyAddition(text,key)
        invMixColumnList = Decryption.invMixColumn(decryption)
        invShiftRowsList = Decryption.invShiftRows(invMixColumnList)
        invByteSubstitute = Decryption.invByteSubstitution(invShiftRowsList)
        return invByteSubstitute

    # performs last key addition
    def lastKeyAddition(decryption,subKey):
        text = []
        for i in range(0,16,4):
            text.append(Decryption.firstKeyDecrypter(decryption[int(i/4)],subKey[int(i/4)]))
        return text

    # writes decrypted data to specific file
    def writeDecryptedFile(folderPath,fileName,decryptedData):
        dataString = []
        data = decryptedData[:-1]
        endLine = decryptedData[-1]

        for dataList1 in data:
            for dataList2 in dataList1:
                for dataList3 in dataList2:
                    dataString.append(int(dataList3,16))
        
        # Used to remove padding
        BytesRemaining = 16 - int(decryptedData[-1][-1][-1],16)-1
        endLine = endLine[0] + endLine[1] + endLine[2] + endLine[3] 
        allZero = True
        for i in range(15-BytesRemaining):
            if int(endLine[BytesRemaining+i],16)!=0:
                allZero = False
                break
        
        if allZero == False:
            endValue = 16
        else:
            endValue = BytesRemaining

            
        for i in range(endValue):
            dataString.append(int(endLine[i],16))
        binary_format = bytes(dataString)
        f = open(folderPath+fileName,'w+b')
        f.write(binary_format)
        f.close()
        
        
    def runHelp(textBlock,key):
        decryption = Decryption.decryptFirstText(textBlock,key)
        for j in range(2,len(key)):
            decryption = Decryption.decryptText(decryption,key[len(key)-j])
        return Decryption.lastKeyAddition(decryption,key[0])

    # runs decryption program
    def run(decryptFileName,fileName,folderPath,key,AESchoice):
        #fileName = "encryptedText.txt"
        if AESchoice == '128':
            key = AESkey.keyTransform(key)
        elif AESchoice == '192':
            key = AES192.keyTransform(key)    
        elif AESchoice == '256':
            key = AES256.keyTransform(key)
        EncryptedData = Decryption.readfile(fileName)
        key = [key]*len(EncryptedData)
        decryptedText = []
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(Decryption.runHelp,EncryptedData,key)
        
            for result in results:
                decryptedText.append(result)
       
        Decryption.writeDecryptedFile(folderPath,decryptFileName,decryptedText)
        return "File Decrypted"   

# provides the file path
def chooseFile():
    window.sourceFile = filedialog.askopenfilename(parent=window, initialdir= "/", title='Please select a directory')

# provides the directory path
def chooseDir():
    window.sourceFolder =  filedialog.askdirectory(parent=window, initialdir= "/", title='Please select a directory')

# Runs Encryption
def encryption(AESchoice,fileName, folderPath):
    if AESchoice == None or fileName == "" or folderPath == "":
        selection = "Enter All Values"
        encryptOp.config(text = selection)
    else:
        if "/" in folderPath:
            folderPath = folderPath+"/"
        else:
            folderPath = folderPath+"\\"
        progress,name,key = Encryption.run(fileName,AESchoice,folderPath)
        selection = "Progress: "+progress+"\nFileName: "+name
        encryptOp.config(text = selection)
        keyText = Text(encryptOpFrame,height=1, borderwidth=0)
        keyText.insert(2.0,"Key: "+key)
        keyText.place(relx = 0, rely = 0.6,relwidth = 1,relheight = 0.4)

#Runs Decryption
def decryption(AESchoice,fileName,folderPath,formatValue,key):
    if AESchoice == None or fileName == "" or key == "" or folderPath =="":
        selection = "Enter All Values"
        encryptOp.config(text = selection)
    else:       
        if (AESchoice == '128' and len(key) == 34) or (AESchoice == '192' and len(key) == 50) or (AESchoice == '256' and len(key) == 66):
            decryptFileName = "DecryptedFile"+formatValue
            if "/" in folderPath:
                folderPath = folderPath+"/"
            else:
                folderPath = folderPath+"\\"            
            progress = Decryption.run(decryptFileName,fileName,folderPath,key,AESchoice)
            selection = progress
            decryptOp.config(text = selection)
        else:
            decryptOp.config(text = "Enter correct Key")


"""
GUI Code
"""
#Create the main Application window
window = Tk()
window.geometry("800x800")
window.title('File Secure AES')

#Created just to provide perspective
frame = Frame(window, bg = 'SkyBlue1', bd = 10)
frame.place(relx = 0.5, rely = 0.025,relwidth = 0.95, relheight = 0.95, anchor = 'n')

# encryptFrame contains all the functionality of encryption
encryptFrame = Frame(frame, bg = 'coral', bd = 10)
encryptFrame.place(relx = 0.5, rely = 0.02,relwidth = 0.9, relheight = 0.46, anchor = 'n')

# encryptIpFrame consists of all Encryption Inputs
encryptIpFrame = Frame(encryptFrame, bg = 'thistle1', bd = 10)
encryptIpFrame.place(relx = 0.5, rely = 0.05,relwidth = 0.75, relheight = 0.65, anchor = 'n')

encryptLabel = Label(encryptIpFrame, text = 'Encryption',bg = 'thistle1', bd = 5)
encryptLabel.place(relwidth = 1, relheight =0.15)


AESlabel = Label(encryptIpFrame, text = 'Select AES \nTechnique',bg = 'plum')
AESlabel.place(relx = 0, rely = 0.15, relwidth = 0.5, relheight =0.3)
# Selcts the correct AES Key Length
var = StringVar()
R1 = Radiobutton(encryptIpFrame, text = "AES\n128", variable = var, value = '128')
R1.place(relx = 0.5,rely = 0.15, relwidth = 0.17, relheight =0.3)

R2 = Radiobutton(encryptIpFrame, text = "AES\n192", variable = var, value = '192')
R2.place(relx = 0.67,rely = 0.15, relwidth = 0.17, relheight =0.3)

R3 = Radiobutton(encryptIpFrame, text = "AES\n256", variable = var, value = '256')
R3.place(relx = 0.83,rely = 0.15, relwidth = 0.17, relheight =0.3)


encryptFileLabel = Label(encryptIpFrame, text = 'Encrypt File',bg = 'yellow')
encryptFileLabel.place(rely = 0.45, relwidth = 0.5, relheight =0.15)

# contains file and folder paths
window.sourceFile = ''
window.sourceFolder = ''
# Button selects file to be encrypted
encryptChooseFile = Button(encryptIpFrame, text = "Select File", width = 20, height = 3, command = chooseFile)
encryptChooseFile.place(relx = 0.5,rely = 0.45, relwidth = 0.5, relheight =0.15)

encryptFolderLabel = Label(encryptIpFrame, text = 'Select Folder to save\nEncrypted file',bg = 'cyan')
encryptFolderLabel.place(rely = 0.6, relwidth = 0.5, relheight =0.2)
# select Directory where key and encrypted file is placed
encryptChooseFolder = Button(encryptIpFrame, text = "Select Directory", width = 20, height = 3, command = chooseDir)
encryptChooseFolder.place(relx = 0.5,rely = 0.6, relwidth = 0.5, relheight =0.2)
# Starts encryption process by calling function encryption
encryptButton = Button(encryptIpFrame, text = "Start Encryption", command = lambda: encryption(var.get(),window.sourceFile,window.sourceFolder))
encryptButton.place(relx = 0.5,rely = 0.8, relwidth = 0.5, relheight =0.2)

# contains output of the encryption
encryptOpFrame = Frame(encryptFrame, bg = 'thistle1', bd = 10)
encryptOpFrame.place(relx = 0.5, rely = 0.75,relwidth = 0.95, relheight = 0.25, anchor = 'n')

encryptOp = Label(encryptOpFrame)
encryptOp.place(relx = 0, rely = 0,relwidth = 1,relheight = 0.6)



# decryptFrame contains all the functionality of decryption
decryptFrame = Frame(frame, bg = 'coral', bd = 10)
decryptFrame.place(relx = 0.5, rely = 0.5,relwidth = 0.9, relheight = 0.5, anchor = 'n')

# decryptIpFrame consists of all Decryption Inputs
decryptIpFrame = Frame(decryptFrame, bg = 'thistle1', bd = 10)
decryptIpFrame.place(relx = 0.5, rely = 0.025,relwidth = 0.75, relheight = 0.78, anchor = 'n')

decryptLabel = Label(decryptIpFrame, text = 'Decryption',bg = 'thistle1', bd = 5)
decryptLabel.place(relwidth = 1, relheight =0.1)

decryptAESlabel = Label(decryptIpFrame, text = 'Select AES Technique',bg = 'plum')
decryptAESlabel.place(relx = 0, rely = 0.15, relwidth = 0.5, relheight =0.15)
# Selcts the correct AES Key Length
decryptVar = StringVar()
decryptR1 = Radiobutton(decryptIpFrame, text = "AES\n128", variable = decryptVar, value = '128')
decryptR1.place(relx = 0.5,rely = 0.15, relwidth = 0.17, relheight =0.15)

decryptR2 = Radiobutton(decryptIpFrame, text = "AES\n192", variable = decryptVar, value = '192')
decryptR2.place(relx = 0.67,rely = 0.15, relwidth = 0.17, relheight =0.15)

decryptR3 = Radiobutton(decryptIpFrame, text = "AES\n256", variable = decryptVar, value = '256')
decryptR3.place(relx = 0.83,rely = 0.15, relwidth = 0.17, relheight =0.15)

decryptFileLabel = Label(decryptIpFrame, text = 'Decrypt File',bg = 'yellow')
decryptFileLabel.place(rely = 0.3, relwidth = 0.5, relheight =0.1)
# Button selects file to be decrypted
decryptChooseFile = Button(decryptIpFrame, text = "Select File", width = 20, height = 3, command = chooseFile)
decryptChooseFile.place(relx = 0.5,rely = 0.3, relwidth = 0.5, relheight =0.1)

decryptFolderLabel = Label(decryptIpFrame, text = 'Select Folder to save File',bg = 'cyan')
decryptFolderLabel.place(rely = 0.4, relwidth = 0.5, relheight =0.1)
# select folder to save decrypted file
decryptChooseFolder = Button(decryptIpFrame, text = "Select Directory", width = 20, height = 3, command = chooseDir)
decryptChooseFolder.place(relx = 0.5,rely = 0.4, relwidth = 0.5, relheight =0.1)

decryptFormatLabel = Label(decryptIpFrame, text = 'Decrypt file format\n(e.g.: .txt)',bg = 'snow4')
decryptFormatLabel.place(rely = 0.5, relwidth = 0.5, relheight =0.18)
# requires correct file format
decryptEnterFormat = Entry(decryptIpFrame, font = ('fixed',15))
decryptEnterFormat.place(relx = 0.5,rely = 0.5, relwidth = 0.5, relheight =0.18)

decryptFormatLabel = Label(decryptIpFrame, text = 'Security Key format\n(0xABCD...8293)	',bg = 'yellow')
decryptFormatLabel.place(rely = 0.68, relwidth = 0.5, relheight =0.18)
# enter the key with which file was encrypted
decryptEnterKey = Entry(decryptIpFrame, font = ('fixed',15))
decryptEnterKey.place(relx = 0.5,rely = 0.68, relwidth = 0.5, relheight =0.18)
# start Decryption
decryptButton = Button(decryptIpFrame, text = "Start Decryption", command = lambda: decryption(decryptVar.get(),window.sourceFile,window.sourceFolder,decryptEnterFormat.get(),decryptEnterKey.get()))
decryptButton.place(relx = 0.5,rely = 0.87, relwidth = 0.5, relheight =0.15)

# contains output of the decryption
decryptOpFrame = Frame(decryptFrame, bg = 'thistle1', bd = 10)
decryptOpFrame.place(relx = 0.5, rely = 0.85,relwidth = 0.95, relheight = 0.1, anchor = 'n')

decryptOp = Label(decryptOpFrame)
decryptOp.pack()

window.mainloop()