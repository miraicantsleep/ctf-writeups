#!/bin/bash

wget https://siber.gemastik.id/download/kode-viewer.zip -O kode-viewer.zip
wget https://siber.gemastik.id/download/anti-alchemy.zip -O anti-alchemy.zip
wget https://siber.gemastik.id/download/gleam-drive.zip -O gleam-drive.zip
wget https://siber.gemastik.id/download/tempest-poc.zip -O tempest-poc.zip
wget https://siber.gemastik.id/download/ticketer.zip -O ticketer.zip
wget https://siber.gemastik.id/download/asmr.zip -O asmr.zip
wget https://siber.gemastik.id/download/gift-voucher.zip -O gift-voucher.zip
wget https://siber.gemastik.id/download/fjb.zip -O fjb.zip

mkdir -p kode-viewer && mkdir -p anti-alchemy && mkdir -p gleam-drive && mkdir -p tempest-poc && mkdir -p ticketer && mkdir -p asmr && mkdir -p gift-voucher && mkdir -p fjb

unzip kode-viewer.zip -d kode-viewer
unzip anti-alchemy.zip -d anti-alchemy
unzip gleam-drive.zip -d gleam-drive
unzip tempest-poc.zip -d tempest-poc
unzip ticketer.zip -d ticketer
unzip asmr.zip -d asmr
unzip gift-voucher.zip -d gift-voucher
unzip fjb.zip -d fjb
 
