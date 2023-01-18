from pdf2image import convert_from_path
from pyzbar.pyzbar import decode
from decode import AadhaarSecureQr

filename = '/home/arkajit/Documents/Projects/pyaadhaar_updated/test_files/Test_Aadhar_Arkajit.pdf'
filename1 = "/home/arkajit/Documents/Projects/pyaadhaar_updated/test_files/PraveenK_Aadhaar.pdf"
working_file = '/home/arkajit/Downloads/new_aadhaar_pvc_4.pdf'
pages = convert_from_path(filename1)

scale = 2
extracted_info = []
for page_idx,page in enumerate(pages):
    page.save(f"{filename[:-4]}_page{page_idx+1}.png")
    page = page.resize((page.width*scale, page.height*scale))
    print(decode(page))
    extracted_info.append(decode(page))

temp = extracted_info[0]
obj = AadhaarSecureQr(int(temp[0].data))
extracted_fields = obj.decodeddata()
print(extracted_fields)
print(obj.signature())
print("---------------------")
print(obj.signedData())
print(obj.isImage())
obj.saveimage("/home/arkajit/Documents/Projects/pyaadhaar_updated/test_files/test.png")
