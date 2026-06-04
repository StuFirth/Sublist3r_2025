from setuptools import setup, find_packages

setup(
    name='Sublist3r',
    version='2.0',
    python_requires='>=3.8',
    install_requires=['dnspython>=2.0,<3', 'requests>=2.20', 'httpx>=0.27'],
    packages=find_packages(exclude=['tests', 'tests.*']),
    py_modules=['sublist3r'],
    include_package_data=True,
    url='https://github.com/aboul3la/Sublist3r',
    license='GPL-2.0',
    description='Subdomains enumeration tool for penetration testers',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU General Public License v2',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
    keywords='subdomain dns detection',
    entry_points={
        'console_scripts': [
            'sublist3r = sublist3r:interactive',
        ],
    },
)
