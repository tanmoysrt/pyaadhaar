## PyAadhaar Library

---

#### Designed to decode Aadhaar Old QR Code , Secure QR Code and also Offline XML

---

### **`|| Decode New Adhaar Secure QR Code ||`**

---

#### **`=> Initialize Object & Print Decoded Data`**

```
from pyaadhaar.decode import AadhaarSecureQr

obj  = AadhaarSecureQr(<:Data got from QR:>)
print(obj.decodeddata())
```

**Output :**

```
{'email_mobile_status': '2',
'referenceid': '345642020107890441252',
'name': 'X Das',
'dob': '01-01-2000',
'gender': 'F',
'careof': 'C/O: Y Das',
'district': 'Nadia',
'landmark': 'Primary School',
'house': 'N0456',
'location': 'Taherpur',
'pincode': '741159',
'postoffice': 'Taherpur',
'state': 'West Bengal',
'street': 'Taherpur Road',
'subdistrict': 'Ranaghat - I',
'vtc': 'Taherpur ',
'adhaar_last_4_digit': '3456',
'adhaar_last_digit': '6',
'email': 'no',
'mobile': 'yes'}
```

#### **`=> Verify Email Id Or Mobile`**

```
print(obj.verifyEmail("example@gmail.com"))
print(obj.verifyMobileNumber(9999999999))
```

**Output :**

```
True  # True if Email Verified
False # True if Mobile Number Verified
```

#### **`=> Check for Email Id Or Mobile Registration`**

```
print(obj.isEmailRegistered("example@gmail.com"))
print(obj.isMobileNoRegistered(9999999999))
```

**Output :**

```
True  # True if Email Registered
False # True if Mobile Number Registered
```

#### **`=> Get if there exists any image in the QR CODE`**

```
image = obj.isImage()
```
**Output :**

```
True  # True if Image is there
False # False if Image is not there
```

#### **`=> Get The Image Of User`**

```
image = obj.image()
```

#### **`=> Save The Image Of User`**

```
obj.saveimage("filename.jpg")
```

#### **`=> Get SHA256 Hash of Email`**

```
print(obj.sha256hashOfEMail())
```

**Output :**

```
d5598a28a82666c7ed9978h8936851189c494c84e62ab9782492fd038d9cb328
```

#### **`=> Get SHA256 Hash of Mobile Number`**

```
print(obj.sha256hashOfMobileNumber())
```

**Output :**

```
15a79565f9f1880e94dc62de51o9j7bd08542e7a6df82081ce1e72f0fb199e69
```

---

---

### **`|| Decode Old Adhaar QR Code ||`**

---

#### **`=> Initialize Object & Print Decoded Data`**

```
from pyaadhaar.decode import AadhaarOldQr

obj  = AadhaarOldQr(<:Data got from QR:>)
print(obj.decodeddata())
```

**Output :**

```
{'uid': '6XXXXXXXX789',
 'name': 'X Sarkar',
 'gender': 'M',
 'yob': '2001',
 'gname': 'Y Sarkar',
 'street': 'TAHERPUR ROAD',
 'lm': 'TAHERPUR',
 'loc': '-',
 'vtc': 'Taherpur (P)',
 'po': 'Taherpur',
 'dist': 'Nadia',
 'subdist': 'Ranaghat - I',
 'state': 'West Bengal',
 'pc': '741159',
 'dob': '01/01/2001'}
```

---

---

### **`|| Decode Adhaar Offline e-KYC XML ||`**

---

#### **`=> Initialize Object & Print Decoded Data`**

```
from pyaadhaar.decode import AadhaarOfflineXML

obj  = AadhaarOfflineXML(<:Offline e-KYC XML ZIP:>,<Passcode>)
print(obj.decodeddata())
```

**Output :**

```
{'email_mobile_status': '2',
'referenceid': '345642020107890441252',
'name': 'X Das',
'dob': '01-01-2000',
'gender': 'F',
'careof': 'C/O: Y Das',
'district': 'Nadia',
'landmark': 'Primary School',
'house': 'N0456',
'location': 'Taherpur',
'pincode': '741159',
'postoffice': 'Taherpur',
'state': 'West Bengal',
'street': 'Taherpur Road',
'subdistrict': 'Ranaghat - I',
'vtc': 'Taherpur ',
'adhaar_last_4_digit': '3456',
'adhaar_last_digit': '6',
'email': 'no',
'mobile': 'yes'}
```

#### **`=> Verify Email Id Or Mobile`**

```
print(obj.verifyEmail("example@gmail.com"))
print(obj.verifyMobileNumber(9999999999))
```

**Output :**

```
True  # True if Email Verified
False # True if Mobile Number Verified
```

#### **`=> Check for Email Id Or Mobile Registration`**

```
print(obj.isEmailRegistered("example@gmail.com"))
print(obj.isMobileNoRegistered(9999999999))
```

**Output :**

```
True  # True if Email Registered
False # True if Mobile Number Registered
```

#### **`=> Get The Image Of User`**

```
image = obj.image()
```

#### **`=> Save The Image Of User`**

```
obj.saveimage("filename.jpg")
```

#### **`=> Get SHA256 Hash of Email`**

```
print(obj.sha256hashOfEMail())
```

**Output :**

```
d5598a28a82666c7ed9978h8936851189c494c84e62ab9782492fd038d9cb328
```

#### **`=> Get SHA256 Hash of Mobile Number`**

```
print(obj.sha256hashOfMobileNumber())
```

**Output :**

```
15a79565f9f1880e94dc62de51o9j7bd08542e7a6df82081ce1e72f0fb199e69
```

---

---

### **`|| Decode Image Of QR Code ||`**

---

```
from pyaadhaar.utils import Qr_img_to_text

print(Qr_img_to_text(<Image File Location or Image file stream>))
```

**Output :**

```
["google.com","amazon.in"] # Will return a list of data
```

---

---

### **`|| Aadhaar Auto Initialize Class On QR code Type ||`**

---

#### **`=> Initialize`**

```

from pyaadhaar.utils import AadhaarQrAuto

obj = AadhaarQrAuto(<Aadhaar QR code Data >)
```

- Then all the methods are same corresponding to
  - AadhaarOldQr
  - AadhaarSecureQr

---

---

### **`|| Aadhaar Check Old or Secure QR Code||`**

---

#### **`=> Initialize`**

```
from pyaadhaar.utils import isSecureQr

print(isSecureQr(<Aadhaar QR code Data >))
```

**Output :**

```
True # If it is a new secure QR code, else False
```

---

---

# Contributors

#### Thanks to the developer of these libraries

- [Opencv](https://pypi.org/project/opencv-python/)
- [Pillow](https://pypi.org/project/Pillow/)
- [Libjpeg](https://pypi.org/project/pylibjpeg-libjpeg/)
- [Numpy](https://pypi.org/project/numpy/)

---
