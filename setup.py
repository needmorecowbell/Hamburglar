from distutils.core import setup
setup(
  name = 'Hamburglar',         # How you named your package folder (MyLib)
  packages = ['Hamburglar'],   # Chose the same as "name"
  version = '1.0',      # Start with a small number and increase it with every change you make
  license='GNU',        # Chose a license from here: https://help.github.com/articles/licensing-a-repository
  description = 'command line tool to collect useful information from urls, directories, and files',   # Give a short description about your library
  author = 'Adam Musciano',                   # Type in your name
  author_email = 'amusciano@gmail.com',      # Type in your E-Mail
  url = 'https://github.com/needmorecowbell/Hamburglar',   # Provide either the link to your github or to your website
  download_url = 'https://github.com/user/reponame/archive/v_01.tar.gz',    # I explain this later on
  keywords = [],   # Keywords that define your package best
  install_requires=[            # I get to this in a second
"beautifulsoup4==4.7.1",
"certifi==2019.6.16",
"cffi==1.13.2",
"chardet==3.0.4",
"cryptography==2.8",
"cssselect==1.0.3",
"feedfinder2==0.0.4",
"feedparser==5.2.1",
"idna==2.8",
"iocextract==1.13.1",
"jieba3k==0.35.1",
"lxml==4.3.4",
"newspaper3k==0.2.8",
"nltk==3.4.5",
"numpy==1.17.4",
"pandas==0.25.3",
"Pillow==6.0.0",
"pycparser==2.19",
"PyMySQL==0.9.3",
"python-dateutil==2.8.0",
"pytz==2019.3",
"PyYAML==5.1.1",
"regex==2019.6.8",
"requests==2.22.0",
"requests-file==1.4.3",
"six==1.12.0",
"soupsieve==1.9.1",
"SQLAlchemy==1.3.5",
"tinysegmenter==0.3",
"tldextract==2.2.1",
"urllib3==1.25.3",
"yara-python==3.11.0"
      ],
  classifiers=[
    'Development Status :: 4 - Beta',      # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
    'Intended Audience :: Forensic Analysts',      # Define that your audience are developers
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: GNU License',   # Again, pick a license
    'Programming Language :: Python :: 3',      #Specify which pyhton versions that you want to support
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
  ],
)