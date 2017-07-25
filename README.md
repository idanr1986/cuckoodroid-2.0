![Image of cuckoo-droid](https://github.com/idanr1986/cuckoo-droid/blob/master/documentation/book/src/_images/logo/cuckoo.png?raw=true)

[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2015.svg)]( https://www.blackhat.com/us-15/arsenal.html)
[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)]( https://www.blackhat.com/us-16/arsenal.html)
[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)]( https://www.blackhat.com/us-17/arsenal.html)

CuckooDroid 2.0 - Automated Android Malware Analysis.
=================================================
CuckooDroid bulit on top of Cuckoo Sandbox the Open Source software for automating analysis of suspicious files, CuckooDroid brigs to cuckoo the capabilities of execution and analysis of android application.

Installation - Easy integration script:

    git clone https://github.com/idanr1986/cuckoodroid-2.0
    cd cuckoodroid-2.0
    apt-get install -y python git python-pip
    apt-get install -y libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev
    pip install -r /requirements.txt
    apt-get install -y qemu-kvm libvirt-bin # when using esx server
    

Documentation
=============
- CuckooDroid - http://cuckoo-droid.readthedocs.org/
- Cuckoo Sandbox - http://cuckoo.readthedocs.org/

You are advised to read the Cuckoo Sandbox documentation before using CuckooDroid!

Powered by:
===========
- Androguard -> https://code.google.com/p/androguard/
- Google Play Unofficial Python API -> https://github.com/egirault/googleplay-api
- APKiD - Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android -> https://github.com/rednaga/APKiD

Credit 
======
- botherder for linux_analyzer_dev -> https://github.com/cuckoobox/cuckoo/tree/linux_analyzer_dev
- rednaga - #CalebFenton #strazzere for APKiD awesome work guys!

Authors
=======
- Idan Revivo - idanr1986@gmail.com (twitter: idanr86)
- Ofer Caspi oferc@checkpoint.com (twitter: @shablolForce)
