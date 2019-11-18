import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="AesOracle-LesPotter", # Replace with your own username
    version="0.0.1",
    author="Les (l3st3r) Potter",
    author_email="bugmeister3@mail.com",
    description="A Package to Decrypt/Encrypt with a Padding Oracle",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lesterpotter/AesOracle",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)