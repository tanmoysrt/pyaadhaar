import zlib
from io import BytesIO
from PIL import Image
import xml.etree.ElementTree as ET
from io import BytesIO
from PIL import Image
import base64


class AdhaarSecureQr:

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

    def decodedData(self):
        return self.data

    def signature(self):
        signature = self.decompressed_array[len(
            self.decompressed_array)-256:len(self.decompressed_array)]
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
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32-32:len(self.decompressed_array)-256-32].hex()
        elif int(self.data['email_mobile_status']) == 2:
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp

    def sha256hashOfMobileNumber(self):
        tmp = ""
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            tmp = self.decompressed_array[len(
                self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
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

    def saveimage(self, filename):
        image = self.image()
        image.save(filename)

    def verifyEmail(self, emailid):
        generated_sha_mail = SHAGenerator(
            emailid, self.data['adhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False

    def verifyMobileNumber(self, mobileno):
        generated_sha_mobile = SHAGenerator(
            mobileno, self.data['adhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False


class AdhaarOldQr:

    def __init__(self, qrdata):
        self.qrdata = qrdata
        self.xmlparser = ET.XMLParser(encoding="utf-8")
        self.parsedxml = ET.fromstring(qrdata, parser=self.xmlparser)
        self.data = self.parsedxml.attrib

    def decodeddata(self):
        return self.data


class AdhaarOfflineXML:
    def __init__(self, filename, passcode):
        self.passcode = passcode
        self.data = {}
        self.filename = filename
        parsedxml = ET.parse(filename, parser=ET.XMLParser(encoding='utf-8'))
        self.root = parsedxml.getroot()

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
        return self.data

    def signature(self):
        return self.root[1][1].text

    def isMobileNoRegistered(self):
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            return True
        return False

    def isEmailRegistered(self):
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
            return True
        return False

    def sha256hashOfEMail(self):
        return self.hashofemail

    def sha256hashOfMobileNumber(self):
        return self.hashofmobile

    def image(self):
        img = self.root[0][2].text
        img = Image.open(BytesIO(base64.b64decode(img)))
        return img

    def saveimage(self, filename):
        image = self.image()
        image.save(filename)

    def verifyEmail(self, emailid):
        generated_sha_mail = SHAGenerator(
            str(emailid)+str(self.passcode), self.data['adhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False

    def verifyMobileNumber(self, mobileno):
        generated_sha_mobile = SHAGenerator(
            str(mobileno)+str(self.passcode), self.data['adhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False
