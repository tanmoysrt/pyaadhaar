from setuptools import find_packages, setup

setup(
    name='pyaadhaar',
    packages=find_packages(),
    version='0.1.0',
    description='This library is built to ease the process of decoding aadhaar QR codes and XML. It supprts old aadhaar QR codes , newly released Secure aadhaar QR codes and also Offline e-KYC XML. This library also can decode QR codes with Opncv. This library bundled with all the features to verify user\'s Email Id and Mobile Number & also to extract the photo of user. ',
    author='Tanmoy Sarkar',
    author_email='ts741127@gmail.com',
    license='MIT',
)
