import zlib
from io import BytesIO
from PIL import Image, ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = True
import xml.etree.ElementTree as ET
from io import BytesIO
import base64
import zipfile
from typing import Union
from . import utils

class AadhaarSecureQr:
    # This is the class for Aadhaar Secure Qr code..  In this version of code the data is in encrypted format
    # The special thing of this type of QR is that we can extract the photo of user from the data
    # This class now supports current version of Aadhaar QR codes [version-3]
    # For more information check here : https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, base10encodedstring:str) -> None:
        self.base10encodedstring = base10encodedstring
        self.details = ["email_mobile_status","referenceid", "name", "dob", "gender", "careof", "district", "landmark",
                        "house", "location", "pincode", "postoffice", "state", "street", "subdistrict", "vtc"]
        self.delimeter = [-1]
        self.data = {}
        self._convert_base10encoded_to_decompressed_array()
        self._check_for_version2()  # Check if V2/V3 format exists
        self._create_delimeter()
        self._extract_info_from_decompressed_array()

    # Converts base10encoded string to a decompressed array
    def _convert_base10encoded_to_decompressed_array(self) -> None:
        bytes_array = self.base10encodedstring.to_bytes(5000, 'big').lstrip(b'\x00')
        self.decompressed_array = zlib.decompress(bytes_array, 16+zlib.MAX_WBITS)

    def _check_for_version2(self) -> None:
        """Check for V2/V3 version markers (non-standard extension)"""
        version_marker = self.decompressed_array[:2].decode("ISO-8859-1", errors='ignore')
        if version_marker in ('V2', 'V3'):
            # If version marker exists, add version and mobile fields
            self.details.insert(0, "version")
            self.details.append("last_4_digits_mobile_no")

    # Creates the delimeter which is used to extract the information from the decompressed array
    def _create_delimeter(self) -> None:
        for i in range(len(self.decompressed_array)):
            if self.decompressed_array[i] == 255:
                self.delimeter.append(i)

    # Extracts the information from the decompressed array
    def _extract_info_from_decompressed_array(self) -> None:
        for i in range(len(self.details)):
            self.data[self.details[i]] = self.decompressed_array[
                self.delimeter[i] + 1:self.delimeter[i+1]
            ].decode("ISO-8859-1")
        
        # Extract last 4 digits of Aadhaar (first 4 chars of referenceId)
        self.data['aadhaar_last_4_digit'] = self.data['referenceid'][:4] if len(self.data['referenceid']) >= 4 else self.data['referenceid']
        
        # Extract last digit of Aadhaar (4th char of referenceId, index 3)
        self.data['aadhaar_last_digit'] = self.data['referenceid'][3] if len(self.data['referenceid']) > 3 else ''
        
        # Set email/mobile flags based on email_mobile_status
        self.data['email'] = int(self.data['email_mobile_status']) in {1, 3}
        self.data['mobile'] = int(self.data['email_mobile_status']) in {2, 3}

    # Returns the extracted data in a dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Returns signature of the QR code
    def signature(self) -> bytes:
        return self.decompressed_array[len(self.decompressed_array) - 256 :]

    # Returns the signed data of the QR code
    def signedData(self) -> bytes:
        return self.decompressed_array[:len(self.decompressed_array)-256]

    # Check whether mobile no is registered or not
    def isMobileNoRegistered(self) -> bool:
        return self.data['mobile']

    # Check whether email id is registered or not
    def isEmailRegistered(self) -> bool:
        return self.data['email']

    # Return hash of the email id
    def sha256hashOfEMail(self) -> str:
        # V3 format doesn't store email/mobile hashes, only last 4 digits in text field
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            return ""  # V3 format uses text field verification, not hash
        
        tmp = ""
        if int(self.data['email_mobile_status']) == 3:
            # When both present: email is at [len-256-32-32:len-256-32]
            tmp = self.decompressed_array[len(self.decompressed_array)-256-32-32:len(self.decompressed_array)-256-32].hex()
        elif int(self.data['email_mobile_status']) == 1:
            # When only email: email is at [len-256-32:len-256]
            tmp = self.decompressed_array[len(self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp

    # Return hash of the mobile number
    def sha256hashOfMobileNumber(self) -> str:
        # V3 format doesn't store email/mobile hashes, only last 4 digits in text field
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            return ""  # V3 format uses text field verification, not hash
        
        # When both (3) or only mobile (2): mobile is at [len-256-32:len-256]
        return (
            self.decompressed_array[
                len(self.decompressed_array)
                - 256
                - 32 : len(self.decompressed_array)
                - 256
            ].hex()
            if int(self.data['email_mobile_status']) in {3, 2}
            else ""
        )

    # Check availability of image in the QR CODE
    def isImage(self, buffer = 10) -> bool:
        # V3 format: use last delimiter before version/last_4_digits fields
        # Standard format: use delimiter at len(self.details)
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            # V3 has extra fields, photo ends before signature only (no hash storage)
            last_text_delimiter_idx = len(self.details) - 2 if 'last_4_digits_mobile_no' in self.details else len(self.details) - 1
        else:
            last_text_delimiter_idx = len(self.details)
        
        # For V3, only signature after photo (no hashes)
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[last_text_delimiter_idx] + 1 :
                    ]
                )
                >= 256 + buffer
            )
        # Standard format with hash storage
        elif int(self.data['email_mobile_status']) == 3:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + 32 + 32 + buffer
            )
        elif int(self.data['email_mobile_status']) in {2, 1}:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + 32 + buffer
            )
        elif int(self.data['email_mobile_status']) == 0:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + buffer
            )
    
    # Return image stream
    def image(self) -> Union[Image.Image,None]:
        # V3 format: Photo starts after all text fields have been extracted
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            # Photo starts after delimiter at index len(self.details)
            # (fields use delimiters 0 through len-1, photo starts after next delimiter)
            photo_start = self.delimeter[len(self.details)] + 1
            photo_end = len(self.decompressed_array) - 256
            return Image.open(BytesIO(self.decompressed_array[photo_start:photo_end]))
        
        # Standard format with hash storage
        if int(self.data['email_mobile_status']) == 3:
            photo_end = len(self.decompressed_array) - 256 - 32 - 32
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        elif int(self.data['email_mobile_status']) in {2, 1}:
            photo_end = len(self.decompressed_array) - 256 - 32
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        elif int(self.data['email_mobile_status']) == 0:
            photo_end = len(self.decompressed_array) - 256
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        else:
            return None

    # Save the image of the user
    def saveimage(self, filepath:str) -> None:
        image = self.image()
        image.load()
        image.save(filepath)

    # Verify the email id
    def verifyEmail(self, emailid:str) -> bool:
        if type(emailid) != str:
            raise TypeError("Email id should be string")
        generated_sha_mail = utils.SHAGenerator(emailid, self.data['aadhaar_last_digit'])
        return generated_sha_mail == self.sha256hashOfEMail()

    # Verify the mobile no  
    def verifyMobileNumber(self, mobileno:str) -> bool:
        if type(mobileno) != str:
            raise TypeError("Mobile number should be string")
        
        # Check if V3 format with last_4_digits_mobile_no field
        if 'last_4_digits_mobile_no' in self.data and self.data.get('last_4_digits_mobile_no'):
            # V3 format: verify by comparing last 4 digits
            return mobileno[-4:] == self.data['last_4_digits_mobile_no']
        else:
            # V2 format or standard: verify by SHA256 hash
            generated_sha_mobile = utils.SHAGenerator(mobileno, self.data['aadhaar_last_digit'])
            return generated_sha_mobile == self.sha256hashOfMobileNumber()


class AadhaarOldQr:
    # This is the class for Aadhaar Normal Qr code..  In this version of code the data is in XML v1.0 format
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, qrdata) -> None:
        self.qrdata = qrdata
        self.xmlparser = ET.XMLParser(encoding="utf-8")
        self.parsedxml = ET.fromstring(qrdata, parser=self.xmlparser)
        self.data = self.parsedxml.attrib

    def decodeddata(self) -> dict:
        # Will return the decoded datas inn dictionary format
        return self.data


class AadhaarOfflineXML:

    # This is the class for Aadhaar Offline XML
    # The special thing of Offline XML is that we can extract the high quality photo of user from the data
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, file:str, passcode:str) -> None:
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
        self.data['aadhaar_last_4_digit'] = self.data['referenceid'][0:4]
        self.data['aadhaar_last_digit'] = self.data['referenceid'][3]

        if self.data['email_mobile_status'] == "0":
            self.data['email'] = False
            self.data['mobile'] = False
        elif self.data['email_mobile_status'] == "1":
            self.data['email'] = True
            self.data['mobile'] = False
        elif self.data['email_mobile_status'] == "2":
            self.data['email'] = False
            self.data['mobile'] = True
        elif self.data['email_mobile_status'] == "3":
            self.data['email'] = True
            self.data['mobile'] = True

    # Get decoded data in dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Fetch signature
    def signature(self) -> str:
        return self.root[1][1].text

    # Check if mobile number is registered
    def isMobileNoRegistered(self) -> bool:
        # Will return True if mobile number is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
            return True
        return False

    # Check if email id is registered
    def isEmailRegistered(self) -> bool:
        # Will return True if email id is registered
        if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
            return True
        return False

    # Get the hash of email id
    def sha256hashOfEMail(self) -> str:
        # Will return the hash of the email id
        return self.hashofemail

    # Get the hash of mobile number
    def sha256hashOfMobileNumber(self) -> str:
        # Will return the hash of mobile number
        return self.hashofmobile

    # Get the image of user
    def image(self) -> Image.Image:
        # Will return the image stream to be used in another function
        img = self.root[0][2].text
        img = Image.open(BytesIO(base64.b64decode(img)))
        return img

    # Save the image of user
    def saveimage(self, filepath:str) -> None:
        # Will save the image of user
        image = self.image()
        image.save(filepath)

    # Verify the email id
    def verifyEmail(self, emailid:str) -> bool:
        # Will return True if emailid match with the given email id
        generated_sha_mail = utils.SHAGenerator(
            str(emailid)+str(self.passcode), self.data['aadhaar_last_digit'])
        if generated_sha_mail == self.sha256hashOfEMail():
            return True
        else:
            return False

    # Verify the mobile number
    def verifyMobileNumber(self, mobileno:str) -> bool:
        # Will return True if mobileno match with the given mobile no
        generated_sha_mobile = utils.SHAGenerator(str(mobileno)+str(self.passcode), self.data['aadhaar_last_digit'])
        if generated_sha_mobile == self.sha256hashOfMobileNumber():
            return True
        else:
            return False