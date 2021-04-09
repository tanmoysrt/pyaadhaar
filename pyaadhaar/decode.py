import zlib
from io import BytesIO
from PIL import Image
import xml.etree.ElementTree as ET
from io import BytesIO
import base64
import zipfile
import pyaadhaar


class AadhaarSecureQr:
    # This is the class for Adhaar Secure Qr code..  In this version of code the data is in encrypted format
    # The special thing of this type of QR is that we can extract the photo of user from the data
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, base10encodedstring):
        self.base10encodedstring = base10encodedstring
        self.details = ["referenceid", "name", "dob", "gender", "careof", "district", "landmark",
                        "house", "location", "pincode", "postoffice", "state", "street", "subdistrict", "vtc"]
        self.delimeter = []
        self.data = {}

        bytes_array = base10encodedstring.to_bytes(5000, 'big').lstrip(b'\x00')

        self.decompressed_array = zlib.decompress(
            bytes_array, 16+zlib.MAX_WBITS)

        for i in range(len(self.decompressed_array)):
            if self.decompressed_array[i] == 255:
                self.delimeter.append(i)

        self.data['email_mobile_status'] = self.decompressed_array[0:1].decode(
            "ISO-8859-1")

        for i in range(15):
            self.data[self.details[i]] = self.decompressed_array[self.delimeter[i] +
                                                                 1:self.delimeter[i+1]].decode("ISO-8859-1")

        self.data['adhaar_last_4_digit'] = self.data['referenceid'][0:4]
        self.data['adhaar_last_digit'] = self.data['referenceid'][3]

        if self.data['email_mobile_status'] == "0":
            self.data['email'] = "no"
            self.data['mobile'] = "no"
        elif self.data['email_mobile_status'] == "1":
            self.data['email'] = "yes"
            self.data['mobile'] = "no"
        elif self.data['email_mobile_status'] == "2":
            self.data['email'] = "no"
            self.data['mobile'] = "yes"
        elif self.data['email_mobile_status'] == "3":
            self.data['email'] = "yes"
            self.data['mobile'] = "yes"

    def decodeddata(self):
        # Will return the personal data in a dictionary format
        return self.data

    def signature(self):
        # Will return the signature value
        signature = self.decompressed_array[len(
            self.decompressed_array)-256:len(self.decompressed_array)]
        return signature

    def signedData(self):
        # Will return the signed data
        signeddata = self.decompressed_array[:len(self.decompressed_array)-256]
        return signeddata

    def isMobileNoRegistered(self):
        # Will return True if mobile number is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            return True
        return False

    def isEmailRegistered(self):
        # Will return True if email id is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
            return True
        return False

    def sha256hashOfEMail(self):
        # Will return the hash of the email id
        tmp = ""
        if int(self.data['email_mobile_status']) == 3:
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32-32:len(self.decompressed_array)-256-32].hex()
        elif int(self.data['email_mobile_status']) == 2:
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp

    def sha256hashOfMobileNumber(self):
        # Will return the hash of mobile number
        tmp = ""
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp

    def image(self):
        # Will return the image stream to be used in another function
        if int(self.data['email_mobile_status']) == 3:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256-32-32]))
        elif int(self.data['email_mobile_status']) == 2 or int(self.data['email_mobile_status']) == 1:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256-32]))
        elif int(self.data['email_mobile_status']) == 0:
            return Image.open(BytesIO(self.decompressed_array[self.delimeter[15]+1:len(self.decompressed_array)-256]))
        else:
            return None

    def saveimage(self, filename):
        # Will save the image of user
        image = self.image()
        image.save(filename)

    def verifyEmail(self, emailid):
        # Will return True if emailid match with the given email id
        generated_sha_mail = pyaadhaar.utils.SHAGenerator(
            emailid, self.data['adhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False

    def verifyMobileNumber(self, mobileno):
        # Will return True if mobileno match with the given mobile no
        generated_sha_mobile = pyaadhaar.utils.SHAGenerator(
            mobileno, self.data['adhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False


class AadhaarOldQr:
    # This is the class for Adhaar Normal Qr code..  In this version of code the data is in XML v1.0 format
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, qrdata):
        self.qrdata = qrdata
        self.xmlparser = ET.XMLParser(encoding="utf-8")
        self.parsedxml = ET.fromstring(qrdata, parser=self.xmlparser)
        self.data = self.parsedxml.attrib

    def decodeddata(self):
        # Will return the decoded datas inn dictionary format
        return self.data


class AadhaarOfflineXML:

    # This is the class for Adhaar Offline XML
    # The special thing of Offline XML is that we can extract the high quality photo of user from the data
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, file, passcode):
        # Need to pass the zip file and passcode/sharecode to this function
        self.passcode = passcode
        self.data = {}
        zf = zipfile.ZipFile(file, 'r')
        zf.setpassword(str(self.passcode).encode('utf-8'))
        filedata = zf.open(zf.namelist()[0]).read()
        parsedxml = ET.fromstring(
            filedata, parser=ET.XMLParser(encoding="utf-8"))
        self.root = parsedxml

        self.hashofmobile = self.root[0][0].attrib['m']
        self.hashofemail = self.root[0][0].attrib['e']

        if self.hashofmobile != "" and self.hashofemail != "":
            self.data['email_mobile_status'] = "3"
        elif self.hashofmobile == "" and self.hashofemail != "":
            self.data['email_mobile_status'] = "2"
        elif self.hashofmobile != "" and self.hashofemail == "":
            self.data['email_mobile_status'] = "1"
        elif self.hashofmobile == "" and self.hashofemail == "":
            self.data['email_mobile_status'] = "0"

        self.data['referenceid'] = self.root.attrib['referenceId']
        self.data['name'] = self.root[0][0].attrib['name']
        self.data['dob'] = self.root[0][0].attrib['dob']
        self.data['gender'] = self.root[0][0].attrib['gender']
        self.data['careof'] = self.root[0][1].attrib['careof']
        self.data['district'] = self.root[0][1].attrib['dist']
        self.data['landmark'] = self.root[0][1].attrib['landmark']
        self.data['house'] = self.root[0][1].attrib['house']
        self.data['location'] = self.root[0][1].attrib['loc']
        self.data['pincode'] = self.root[0][1].attrib['pc']
        self.data['postoffice'] = self.root[0][1].attrib['po']
        self.data['state'] = self.root[0][1].attrib['state']
        self.data['street'] = self.root[0][1].attrib['street']
        self.data['subdistrict'] = self.root[0][1].attrib['subdist']
        self.data['vtc'] = self.root[0][1].attrib['vtc']
        self.data['adhaar_last_4_digit'] = self.data['referenceid'][0:4]
        self.data['adhaar_last_digit'] = self.data['referenceid'][3]

        if self.data['email_mobile_status'] == "0":
            self.data['email'] = "no"
            self.data['mobile'] = "no"
        elif self.data['email_mobile_status'] == "1":
            self.data['email'] = "yes"
            self.data['mobile'] = "no"
        elif self.data['email_mobile_status'] == "2":
            self.data['email'] = "no"
            self.data['mobile'] = "yes"
        elif self.data['email_mobile_status'] == "3":
            self.data['email'] = "yes"
            self.data['mobile'] = "yes"

    def decodeddata(self):
        # Will return data in dictionary format
        return self.data

    def signature(self):
        # Will return the signature
        return self.root[1][1].text

    def isMobileNoRegistered(self):
        # Will return True if mobile number is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            return True
        return False

    def isEmailRegistered(self):
        # Will return True if email id is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
            return True
        return False

    def sha256hashOfEMail(self):
        # Will return the hash of the email id
        return self.hashofemail

    def sha256hashOfMobileNumber(self):
        # Will return the hash of mobile number
        return self.hashofmobile

    def image(self):
        # Will return the image stream to be used in another function
        img = self.root[0][2].text
        img = Image.open(BytesIO(base64.b64decode(img)))
        return img

    def saveimage(self, filename):
        # Will save the image of user
        image = self.image()
        image.save(filename)

    def verifyEmail(self, emailid):
        # Will return True if emailid match with the given email id
        generated_sha_mail = pyaadhaar.utils.SHAGenerator(
            str(emailid)+str(self.passcode), self.data['adhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False

    def verifyMobileNumber(self, mobileno):
        # Will return True if mobileno match with the given mobile no
        generated_sha_mobile = pyaadhaar.utils.SHAGenerator(
            str(mobileno)+str(self.passcode), self.data['adhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False
