import gzip, zlib
from pyaadhaar.utils import SHAGenerator
from io import BytesIO
from PIL import Image
import cv2
from hashlib import sha256
from .deocde import SHAGenerator

class AdhaarSecureQr:
    
    def __init__(self,base10encodedstring):
        self.base10encodedstring = base10encodedstring
        self.details = ["referenceid","name","dob","gender","careof","district","landmark","house","location","pincode","postoffice","state","street","subdistrict","vtc"]
        self.delimeter = []
        self.data = {}
    
        bytes_array = base10encodedstring.to_bytes(5000,'big').lstrip(b'\x00')
        
        self.decompressed_array = zlib.decompress(bytes_array,16+zlib.MAX_WBITS)
        
        for i in range(len(self.decompressed_array)):
            if self.decompressed_array[i] == 255:
                self.delimeter.append(i)
                
        self.data['email_mobile_status']=self.decompressed_array[0:1].decode("ISO-8859-1")
        
        for i in range(15):
            self.data[self.details[i]]=self.decompressed_array[self.delimeter[i]+1:self.delimeter[i+1]].decode("ISO-8859-1")
            
        self.data['adhaar_last_4_digit']=self.data['referenceid'][0:4]
        self.data['adhaar_last_digit']=self.data['referenceid'][3]

        if self.data['email_mobile_status'] == "0":
            self.data['email']="no"
            self.data['mobile']="no"
        elif self.data['email_mobile_status'] == "1":
            self.data['email']="yes"
            self.data['mobile']="no"
        elif self.data['email_mobile_status'] == "2":
            self.data['email']="no"
            self.data['mobile']="yes"
        elif self.data['email_mobile_status'] == "3":
            self.data['email']="yes"
            self.data['mobile']="yes"
        
    def decodedData(self):
        return self.data
    
    def signature(self):
        signature = self.decompressed_array[len(self.decompressed_array)-256:len(self.decompressed_array)]
        return signature
    
    def signedData(self):
        signeddata = self.decompressed_array[:len(self.decompressed_array)-256]
        return signeddata
    
    def isMobileNoRegistered(self):
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            return True
        return False
    
    def isEmailRegistered(self):
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
            return True
        return False        
    
    def sha256hashOfEMail(self):
        tmp = ""
        if int(self.data['email_mobile_status']) == 3:
            tmp=self.decompressed_array[len(self.decompressed_array)-256-32-32:len(self.decompressed_array)-256-32].hex()
        elif int(self.data['email_mobile_status']) == 2:
            tmp=self.decompressed_array[len(self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp
    
    def sha256hashOfMobileNumber(self):
        tmp = ""
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            tmp=self.decompressed_array[len(self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp
    
    def image(self):
        if int(self.data['email_mobile_status']) == 3:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256-32-32]))
        elif int(self.data['email_mobile_status']) == 2 or int(self.data['email_mobile_status']) == 1:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256-32]))
        elif int(self.data['email_mobile_status']) == 0:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256]))
        else:
            return None
    
    def saveimage(self,filename):
        image = self.image()
        image.save(filename)
        
    def verifyEmail(self,emailid):
        generated_sha_mail = SHAGenerator(emailid,self.data['adhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False
        
    def verifyMobileNumber(self,mobileno):
        generated_sha_mobile = SHAGenerator(mobileno,self.data['adhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False