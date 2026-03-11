"""
skill-sec-scan 安装配置

CoPaw Worker Skills 安全扫描工具

Usage:
    pip install -e .
    skill-sec-scan scan /path/to/skill
"""
from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='skill-sec-scan',
    version='1.0.0',
    description='CoPaw Worker Skills 安全扫描工具',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='CoPaw Worker Team',
    author_email='copaw@example.com',
    url='https://github.com/copaw/skill-sec-scan',
    packages=find_packages(),
    install_requires=[
        'click>=8.0',
        'rich>=13.0',
        'pyyaml>=6.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
            'black>=23.0',
            'flake8>=6.0',
            'mypy>=1.0',
            'types-PyYAML>=6.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'skill-sec-scan=skill_sec_scan.cli:main',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Utilities',
    ],
    keywords='security scanner skills copaw cli',
)
