# Introduction #

This project is to build a Near Field Communications access control system for homes. Public key certificates will be distributed to the phone and then upon connecting to the NFC lock this is transmitted and a challenge is signed. If the certificate and the digital signature is valid the door lock will open. Homes would have a CA key which can be used to sign new door lock certificates and then these can be distributed to the device via e-mail.

It works but as the certificates are large the protocol takes a long time to process.

# Equipment #

Currently this project has been tested using
  * Google Nexus S
> > - http://www.google.co.uk/nexus/#
  * Beagleboard xM
> > - http://beagleboard.org/hardware-xM
  * KMtronic USB Relay Controller - One Channel
> > - http://www.sigma-shop.com/product/7/usb-relay-controller-one-channel.html
  * Farnell 12v AC Door Strike
> > - http://uk.farnell.com/deedlock/sr04745/rim-strike/dp/3541071
  * ACS 122U USB NFC reader
> > - http://www.acs.com.hk/index.php?pid=product&id=ACR122U

# Required Software/Libraries #

  * Angstrom Linux
  * OpenSSL
  * libNFC