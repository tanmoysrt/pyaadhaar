from setuptools import find_packages, setup

with open("README.MD", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='pyaadhaar',
    packages=find_packages(),
    version='1.1.2',
    description='This library is built to ease the process of decoding aadhaar QR codes and XML. It supprts old aadhaar QR codes , newly released Secure aadhaar QR codes and also Offline e-KYC XML. This library also can decode QR codes with Opncv. This library bundled with all the features to verify user\'s Email Id and Mobile Number & also to extract the photo of user. ',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Tanmoy Sarkar',
    author_email='ts741127@gmail.com',
    license='MIT',
    url="https://github.com/Tanmoy741127/pyaadhaar",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers ',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='software development aadhaar e-kyc verification',
    python_requires='>=3.6',
    install_requires=[
        'numpy',
        'opencv-python',
        'Pillow',
        'pylibjpeg',
        'pylibjpeg-openjpeg',
        'python-dateutil',
        'pytz',
        'pyzbar',
        'six',
        'toml'
    ],

)
