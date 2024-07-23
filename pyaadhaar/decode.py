# import zlib
# from io import BytesIO
# from PIL import Image, ImageFile
# ImageFile.LOAD_TRUNCATED_IMAGES = True
# import base64
# import zipfile
# import xml.etree.ElementTree as ET
# from typing import Union
# from pyaadhaar import utils

# class AadhaarSecureQr:
#     def __init__(self, base10encodedstring: str) -> None:
#         self.base10encodedstring = base10encodedstring
#         self.details_v1 = ["version", "email_mobile_status", "referenceid", "name", "dob", "gender", "careof", "district", "landmark",
#                            "house", "location", "pincode", "postoffice", "state", "street", "subdistrict", "vtc", "last_4_digits_mobile_no"]
#         self.details_v2 = ["email_mobile_status", "referenceid", "name", "dob", "gender", "careof", "district", "landmark",
#                            "house", "location", "pincode", "postoffice", "state", "street", "subdistrict", "vtc"]
#         self.delimiter = [-1]
#         self.data = {}
#         self._convert_base10encoded_to_decompressed_array()
#         self._detect_version_and_adjust_details()
#         self._create_delimiter()
#         self._extract_info_from_decompressed_array()

#     def _convert_base10encoded_to_decompressed_array(self) -> None:
#         bytes_array = self.base10encodedstring.to_bytes(5000, 'big').lstrip(b'\x00')
#         print(f"Bytes array (trimmed leading zeros): {bytes_array[:100]}")  # Debugging: print the first 100 bytes
#         try:
#             self.decompressed_array = zlib.decompress(bytes_array, 16 + zlib.MAX_WBITS)
#         except Exception as e:
#             print(f"Decompression error: {e}")
#             return
#         print(f"Decompressed array: {self.decompressed_array[:100]}")  # Debugging: print the first 100 bytes of decompressed array

#     def _detect_version_and_adjust_details(self) -> None:
#         # Check for version in the first two bytes
#         version = self.decompressed_array[:2].decode("ISO-8859-1")
#         if version.startswith('V'):
#             # Version is present, use the details list with version
#             self.details = self.details_v1
#         else:
#             # Version is not present, use the details list without version
#             self.details = self.details_v2

#     def _create_delimiter(self) -> None:
#         for i in range(len(self.decompressed_array)):
#             if self.decompressed_array[i] == 255:
#                 self.delimiter.append(i)
#         print(f"Delimiters: {self.delimiter}")

#     def _extract_info_from_decompressed_array(self) -> None:
#         for i in range(len(self.details)):
#             if i + 1 < len(self.delimiter):
#                 start_idx = self.delimiter[i] + 1
#                 end_idx = self.delimiter[i + 1]
#                 self.data[self.details[i]] = self.decompressed_array[start_idx:end_idx].decode("ISO-8859-1")

#         print(f"Extracted data before verification: {self.data}")

#         referenceid = self.data.get('referenceid', '')
#         if len(referenceid) >= 4:
#             self.data['aadhaar_last_4_digit'] = referenceid[:4]
#             self.data['aadhaar_last_digit'] = referenceid[3]
#         else:
#             print(f"Reference ID is too short: {referenceid}")
#             print(f"Extracted data: {self.data}")

#         self.data['email'] = False
#         self.data['mobile'] = False
#         email_mobile_status = self.data.get('email_mobile_status', '')
#         if email_mobile_status.isdigit():
#             email_mobile_status = int(email_mobile_status)
#             if email_mobile_status in {3, 1}:
#                 self.data['email'] = True
#             if email_mobile_status in {3, 2}:
#                 self.data['mobile'] = True

#     def decodeddata(self) -> dict:
#         return self.data

#     def signature(self) -> bytes:
#         return self.decompressed_array[len(self.decompressed_array) - 256:]

#     def signedData(self) -> bytes:
#         return self.decompressed_array[:len(self.decompressed_array) - 256]

#     def isMobileNoRegistered(self) -> bool:
#         return self.data['mobile']

#     def isEmailRegistered(self) -> bool:
#         return self.data['email']

#     def sha256hashOfEMail(self) -> str:
#         tmp = ""
#         email_mobile_status = self.data.get('email_mobile_status', '')
#         if email_mobile_status.isdigit() and int(email_mobile_status) == 3:
#             tmp = self.decompressed_array[len(self.decompressed_array) - 256 - 32 - 32:len(self.decompressed_array) - 256 - 32].hex()
#         elif email_mobile_status.isdigit() and int(email_mobile_status) == 1:
#             tmp = self.decompressed_array[len(self.decompressed_array) - 256 - 32:len(self.decompressed_array) - 256].hex()
#         return tmp

#     def sha256hashOfMobileNumber(self) -> str:
#         email_mobile_status = self.data.get('email_mobile_status', '')
#         if email_mobile_status.isdigit() and int(email_mobile_status) in {3, 2}:
#             return self.decompressed_array[len(self.decompressed_array) - 256 - 32: len(self.decompressed_array) - 256].hex()
#         return ""

#     def isImage(self, buffer=10) -> bool:
#         email_mobile_status = self.data.get('email_mobile_status', '')
#         if email_mobile_status.isdigit():
#             if int(email_mobile_status) == 3:
#                 return len(self.decompressed_array[self.delimiter[len(self.details)] + 1:]) >= 256 + 32 + 32 + buffer
#             elif int(email_mobile_status) in {2, 1}:
#                 return len(self.decompressed_array[self.delimiter[len(self.details)] + 1:]) >= 256 + 32 + buffer
#             elif int(email_mobile_status) == 0:
#                 return len(self.decompressed_array[self.delimiter[len(self.details)] + 1:]) >= 256 + buffer
#         return False

#     def image(self) -> Union[Image.Image, None]:
#         email_mobile_status = self.data.get('email_mobile_status', '')
#         if email_mobile_status.isdigit() and int(email_mobile_status) in {0, 1, 2, 3}:
#             return Image.open(BytesIO(self.decompressed_array[self.delimiter[len(self.details)] + 1:]))
#         return None

#     def saveimage(self, filepath: str) -> None:
#         image = self.image()
#         if image:
#             image.load()
#             image.save(filepath)
            
#     def contains_image(self) -> bool:
#         return self.isImage()
    

# class AadhaarOldQr:
#     # This is the class for Adhaar Normal Qr code..  In this version of code the data is in XML v1.0 format
#     # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

#     def __init__(self, qrdata):
#         self.qrdata = qrdata
#         self.xmlparser = ET.XMLParser(encoding="utf-8")
#         self.parsedxml = ET.fromstring(qrdata, parser=self.xmlparser)
#         self.data = self.parsedxml.attrib

#     def decodeddata(self):
#         # Will return the decoded datas inn dictionary format
#         return self.data


# class AadhaarOfflineXML:

#     # This is the class for Adhaar Offline XML
#     # The special thing of Offline XML is that we can extract the high quality photo of user from the data
#     # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

#     def __init__(self, file, passcode):
#         # Need to pass the zip file and passcode/sharecode to this function
#         self.passcode = passcode
#         self.data = {}
#         zf = zipfile.ZipFile(file, 'r')
#         zf.setpassword(str(self.passcode).encode('utf-8'))
#         filedata = zf.open(zf.namelist()[0]).read()
#         parsedxml = ET.fromstring(
#             filedata, parser=ET.XMLParser(encoding="utf-8"))
#         self.root = parsedxml

#         self.hashofmobile = self.root[0][0].attrib['m']
#         self.hashofemail = self.root[0][0].attrib['e']

#         if self.hashofmobile != "" and self.hashofemail != "":
#             self.data['email_mobile_status'] = "3"
#         elif self.hashofmobile == "" and self.hashofemail != "":
#             self.data['email_mobile_status'] = "2"
#         elif self.hashofmobile != "" and self.hashofemail == "":
#             self.data['email_mobile_status'] = "1"
#         elif self.hashofmobile == "" and self.hashofemail == "":
#             self.data['email_mobile_status'] = "0"

#         self.data['referenceid'] = self.root.attrib['referenceId']
#         self.data['name'] = self.root[0][0].attrib['name']
#         self.data['dob'] = self.root[0][0].attrib['dob']
#         self.data['gender'] = self.root[0][0].attrib['gender']
#         self.data['careof'] = self.root[0][1].attrib['careof']
#         self.data['district'] = self.root[0][1].attrib['dist']
#         self.data['landmark'] = self.root[0][1].attrib['landmark']
#         self.data['house'] = self.root[0][1].attrib['house']
#         self.data['location'] = self.root[0][1].attrib['loc']
#         self.data['pincode'] = self.root[0][1].attrib['pc']
#         self.data['postoffice'] = self.root[0][1].attrib['po']
#         self.data['state'] = self.root[0][1].attrib['state']
#         self.data['street'] = self.root[0][1].attrib['street']
#         self.data['subdistrict'] = self.root[0][1].attrib['subdist']
#         self.data['vtc'] = self.root[0][1].attrib['vtc']
#         self.data['adhaar_last_4_digit'] = self.data['referenceid'][0:4]
#         self.data['adhaar_last_digit'] = self.data['referenceid'][3]

#         if self.data['email_mobile_status'] == "0":
#             self.data['email'] = "no"
#             self.data['mobile'] = "no"
#         elif self.data['email_mobile_status'] == "1":
#             self.data['email'] = "yes"
#             self.data['mobile'] = "no"
#         elif self.data['email_mobile_status'] == "2":
#             self.data['email'] = "no"
#             self.data['mobile'] = "yes"
#         elif self.data['email_mobile_status'] == "3":
#             self.data['email'] = "yes"
#             self.data['mobile'] = "yes"

#     def decodeddata(self):
#         # Will return data in dictionary format
#         return self.data

#     def signature(self):
#         # Will return the signature
#         return self.root[1][1].text

#     def isMobileNoRegistered(self):
#         # Will return True if mobile number is registered
#         if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 1:
#             return True
#         return False

#     def isEmailRegistered(self):
#         # Will return True if email id is registered
#         if int(self.data['email_mobile_status']) == 3 or int(self.data['email_mobile_status']) == 2:
#             return True
#         return False

#     def sha256hashOfEMail(self):
#         # Will return the hash of the email id
#         return self.hashofemail

#     def sha256hashOfMobileNumber(self):
#         # Will return the hash of mobile number
#         return self.hashofmobile

#     def image(self):
#         # Will return the image stream to be used in another function
#         img = self.root[0][2].text
#         img = Image.open(BytesIO(base64.b64decode(img)))
#         return img

#     def saveimage(self, filename):
#         # Will save the image of user
#         image = self.image()
#         image.save(filename)

#     def contains_image(self) -> bool:
#         try:
#             img_data = self.root[0][2].text
#             if img_data:
#                 Image.open(BytesIO(base64.b64decode(img_data)))
#                 return True
#         except Exception as e:
#             print(f"Error checking image: {e}")
#         return False

#     def verifyEmail(self, emailid):
#         # Will return True if emailid match with the given email id
#         generated_sha_mail = utils.SHAGenerator(
#             str(emailid)+str(self.passcode), self.data['adhaar_last_digit'])
#         if generated_sha_mail == self.sha256hashOfEMail():
#             return True
#         else:
#             return False

#     def verifyMobileNumber(self, mobileno):
#         # Will return True if mobileno match with the given mobile no
#         generated_sha_mobile = utils.SHAGenerator(
#             str(mobileno)+str(self.passcode), self.data['adhaar_last_digit'])
#         if generated_sha_mobile == self.sha256hashOfMobileNumber():
#             return True
#         else:
#             return False
