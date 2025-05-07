from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="kubectl-kubeviz",
    version="0.1.0",
    author="KubeViz Developers",
    author_email="author@example.com",
    description="A kubectl plugin that visualizes Kubernetes cluster resources",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/kubectl-kubeviz",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "kubeviz": ["templates/*"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "kubernetes>=12.0.0",
        "graphviz>=0.14",
        "flask>=2.0.0",
        "click>=7.0"
    ],
    entry_points={
        "console_scripts": [
            "kubectl-kubeviz=kubeviz.cli:main",
        ],
    },
)
