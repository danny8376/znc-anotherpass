Another Password Authentication Module for ZNC
===================================

This module provides ability to login with another password
other than the original master password.
(This project is based on code of certauth module.)


Build
-----------------------------------

Build it with

    $ znc-buildmod anotherpass.cpp

Install
-----------------------------------

Place compiled anotherpass.so & folder "anotherpass" (for web interface template)
in your ZNC modules folder.

Usage
-----------------------------------

This module take no argument.

To add password

    /msg *anotherpass add YourPasswordHere [PasswordRemainder]

To list password

    /msg *anotherpass list

To delete password

    /msg *anotherpass id (get by list)

To clear all password

    /msg *anotherpass clear

For more command usage, get help in this plugin:

    /msg *anotherpass help
