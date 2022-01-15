import setuptools

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='touchstone-auth',
    version='0.3.0',
    author='Christopher Johnstone',
    author_email='meson800@gmail.com',
    description='Access Touchstone SSO sites without a web browser.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/meson800/touchstone-auth',
    project_urls={
        'Bug Tracker': 'https://github.com/meson800/touchstone-auth/issues',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP :: Session'
    ],
    package_dir={'': 'src'},
    packages=setuptools.find_packages(where='src'),
    python_requires=">=3.6",
    install_requires=[
        'beautifulsoup4',
        'requests',
        'requests-pkcs12==1.10',
        'typing-extensions'
    ]
)