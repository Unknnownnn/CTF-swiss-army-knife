from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ctf-swiss-army-knife",
    version="1.0.1",
    author="Unknnownnn",
    description="CTF Swiss Army Knife - All-in-One CTF Solving Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Unknnownnn/CTF-swiss-army-knife",
    py_modules=["gui"],
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ctf-sak=gui:main",
        ],
    },
    include_package_data=True,
) 