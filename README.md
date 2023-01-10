# nabud - A server for the NABU PC

This is a server for the NABU Personal Computer.  For more information about the NABU PC,
please check out [NabuRetroNet](https://nabu.ca) as well as
[Adrian Black's video](https://www.youtube.com/watch?v=HLYjZoShjy0) about the NABU.

This server is written in C and is intended to be very portable to the Unix-like systems
available today (the various BSDs, Linux, etc.) while also being as self-contained as
possible, relying on no "external" software packages to build and run.  The majority of
the APIs it uses are either standard C99, standard POSIX, or extremely common extensions,
for example some common BSD APIs that are also available in Linux, such as _syslog(3)_
and _daemon(3)_.

## Features

* Define up to 254 content channels (numbered 1-255) from an arbitrary number of sources.
* Sources can be local or remote (such as NabuRetroNet).
* Serve an arbitrary number of NABU PCs:
    * As many RS422 serial ports as you can connect to your system for real NABU hardware.
    * Support for connections from NABU emulators (such as MAME) over TCP.
* Decrypt and serve NABU _pak_ files (available from NabuRetroNet).
* Serve your own or others' homebrew NABU binaries (_nabu_ files).
* High-performance; nabud implements a content cache to optimize common access patterns and avoid redundant I/O.
* Small footprint; it can run on small machines. The only thing it throws memory at is the content cache.

The NabuRetroNet _HomeBrew_ channel does not currently work with nabud.  This is because
the NABU always requests image 000001 when it boots, and DJ's Internet adapter application
presents a drop-down menu to select the image to be vended when 000001 is requested.  I plan
to introduce an interactive command-line tool that will allow nabud users to dynamically
select an image from the list and pin it to the connection, as well as allow for the connection's
channel to be changed dynamically without having to edit the config file or restart nabud.

## Configuration

nabud's configuration is held in a JSON-format configuration file.  This configuration file
must contain 3 stanzas, in the following order:

* Sources: an array of content sources.  Sources provide the content that is served by Channels.
* Channels: an array of content channels.  Connections get their content from Channels.  Each
Channel can be served by any source.
* Connections: an array of connections.

### Sources

Each Source has 3 properies:
* Name: a string that idenfies the source.  It's meant both for human consumption
as well as for specifying which Source provides a Channel.
* Location: a URL string that specifies the root of the source.

### Channels

Each Channel has 4 properites:
* Name: a string that identifies a Channel.  It's meant both for human consumption, but
also specifies the name of the directory in the Source's location that contains the Channel's
files.
* Number: a unique number from 1 to 255 that identifies the Channel to the NABU.
* Type: a string that specifies the type of files provided by the Channel:
    * pak: NABU _pak_ files (content that is pre-wrapped in packet headers).  These
    are the original NABU Network files and can be downloaded from NabuRetroNet.
    * nabu: Raw _nabu_ binary files, such as those you build yourself.  nabud packetizes
    these files on-the-fly.
* Source: a string that specifies the Source that provides the Channel.

### Connections

Each Connection has 3 properties:
* Type: a string that specifies the type of connection:
    * serial: an RS422 serial connection to real NABU hardware.
    * tcp: a TCP listener that accepts connections from emulators (e.g. MAME).
* Port: a string that specifies the "port" to use for the connection, which varies
based on the connection type:
    * serial: a string that specifies the path to the serial port to use for the connection.
    * tcp: a string that specifies the TCP port on which connections will be accepted.
* Channel: a numnber from 1 to 255 that specifies which channel to use for this connection.

### Example configuration file

This is the _nabud.conf_ configuration file I use to serve my own NABU:

    {
      "Sources": [
        {
          "Name": "Local",
          "Type": "local",
          "Location": "/home/nabu",
        },
        {
          "Name": "NabuRetroNet",
          "Location": "https://cloud.nabu.ca",
        }
      ],
      "Channels": [
        {
          "Name": "cycle1",
          "Number": 1,
          "Type": "pak",
          "Source": "NabuRetroNet"
        },
        {
          "Name": "cycle2",
          "Number": 2,
          "Type": "pak",
          "Source": "NabuRetroNet",
        },
        {
          "Name": "HomeBrew",
          "Path": "HomeBrew/titles",
          "Number": 3,
          "Type": "nabu",
          "Source": "NabuRetroNet",
        },
        {
          "Name": "cycle1",
          "Number": 11,
          "Type": "pak",
          "Source": "Local",
        },
        {
          "Name": "homebrew",
          "Number": 12,
          "Type": "nabu",
          "Source": "Local",
        }
      ],
      "Connections": [
        {
          "Type": "serial",
          "Port": "/dev/tty-uftdi-A10MHWD6-0",
          "Channel": 11,
        },
        {
          "Type": "tcp",
          "Port": "5001",
          "Channel": 1,
        },
        {
          "Type": "tcp",
          "Port": "5002",
          "Channel": 2,
        },
        {
          "Type": "tcp",
          "Port": "5003",
          "Channel": 3,
        }
      ]
    }

And this is the file layout of my one Source location:

    the-ripe-vessel:thorpej 256$ ls -l /home/nabu/                                 
    total 28
    24 drwxr-xr-x  2 thorpej  wheel  22528 Dec 28 14:49 cycle1/
     4 drwxr-xr-x  2 thorpej  wheel    512 Dec 28 14:36 homebrew/
    the-ripe-vessel:thorpej 257$ ls -l /home/nabu/homebrew/                                                      <
    total 8
    8 -rw-r--r--  1 thorpej  users  6732 Dec 28 09:09 000001.nabu
    the-ripe-vessel:thorpej 258$ ls -l /home/nabu/cycle1    
    total 6764
     28 -rw-r--r--  1 thorpej  users   27712 Dec 28 11:14 00-DD-5C-C5-82-58-D9-BA-33-D9-80-2D-19-1D-FC-55.npak
      4 -rw-r--r--  1 thorpej  users    3160 Dec 28 11:14 01-43-6A-DF-BE-45-CB-E8-A1-D7-EB-8D-AB-63-06-E7.npak
     16 -rw-r--r--  1 thorpej  users   15696 Dec 28 11:14 02-E1-D8-97-CF-F9-82-38-D0-ED-9F-8A-8B-FA-F4-73.npak
     .
     .
     .
     [ lots more .npak files ]

## Building nabud

nabud uses the GNU autotools-based build system that you're probably already familiar with, as it's used by
many software packages.  Most people will only need to do:

    % ./configure
    % make
    # make install

nabud uses POSIX threads, which must be provided by your system.

In order to handle _pak_ files, a cryptographic library is required; MD5 is used to generate _pak_ file names
and DES is used to decrypt them.  The following cryptographic libraries are currently supported:

* CommonCrypto (the native API on macOS)
* OpenSSL's _libcrypto_.  This is the native API already provided by many Unix-like systems, so it's unlikely
that you'll have to go find and install it.

In order to download from remote sources, such as NabuRetroNet, an SSL library is required.  The following
SSL libraries are currently supported:

* SecureTransport (the native API on macOS)
* OpenSSL

On Linux (at least, on the Ubuntu distribution I used), there's a good chance that OpenSSL will not already
be installed, so you will need to do so yourself.  Because Linux distributions are all different, how to do
that is left as an exercise for the reader.  However, once it's installed, there is not likely to be any
additional magic that you need to perform; the configure script will probably find it.

Because an effort has been made to keep nabud fairly self-contained and reliant only on APIs provided by
the operating system, building it just requires a toolchain.  For the BSDs and Linux, it's probably already
installed on your system, but if it's not, then doing so is left as an exercise for the reader.  For macOS,
you will need to install the [Xcode Developer Tools](https://apps.apple.com/us/app/xcode/id497799835) and
then launch Xcode to perform the "first launch" task that takes care of setting up the command-line tools
that nabud uses to build.

## Running nabud

After building nabud, copy the example _nabud.conf_ to the selected location (default: _/etc/nabud.conf_), tailor
it to your system, and then run it:

    # ./nabud

nabud requires no special permissions; only the ability to open files to be served to the NABU for reading,
and the ability to open the serial ports for reading and writing.  You can choose to run it as _root_ or as
an unprivileged user if you set the permissions on your serial port devices properly.  If you're only using
TCP functionality, it can run completely unprivileged.

nabud understands the following command line options:
* _-c conf_ -- specifies an alternate name / location for _nabud.conf_.
* _-d_ -- enables debugging.  This option also implies _-f_.
* _-f_ -- run in the foreground.  Without this, nabud will detach from the controlling terminal and run as a daemon.
* _-l logfile_ -- specifies the path to a log file.  Without this option, nabud will log to the system log using _syslog(3)_
using the _LOG_USER_ facility.  Note that when running in the foreground, log messages are always sent to the
controlling terminal.

In addition to errors, nabud logs some basic information about the requests it servies.  Here is a system log snippet
showing the messages you will typically see:

    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: main: Welcome to NABU! I'm version 0.5 of your host, nabud.
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: image_add_local_source: Adding Local source KTNet at /home/nabu
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: image_add_channel: Adding pak channel 1 (cycle1 on KTNet) at /home/nabu/cycle1
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: image_add_channel: Adding nabu channel 2 (homebrew on KTNet) at /home/nabu/homebrew
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: conn_add_serial: Creating Serial connection on /dev/tty-uftdi-A10MHWD6-0.
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: image_channel_select: [/dev/tty-uftdi-A10MHWD6-0] Selected channel 1 (cycle1 on KTNet).
    Dec 30 12:07:13 the-ripe-vessel nabud[6179]: INFO: adaptor_event_loop: [/dev/tty-uftdi-A10MHWD6-0] Connection starting.
    Dec 30 12:07:15 the-ripe-vessel nabud[6179]: INFO: image_cache_insert: Cached pak-000001 on Channel 1; total cache size: 54336
    Dec 30 12:07:15 the-ripe-vessel nabud[6179]: INFO: image_use: [/dev/tty-uftdi-A10MHWD6-0] Using image pak-000001 from Channel 1.
    Dec 30 12:07:22 the-ripe-vessel nabud[6179]: INFO: image_done: [/dev/tty-uftdi-A10MHWD6-0] Done with image pak-000001.

## Changes

### nabud-0.8 (in development on main branch)
* Support for the NabuRetroNet blob store extensions to the Adaptor protocol.  These extensions
allow programs running on the NABU to access up to 256 "slots" of cloud storage that are cached
in the server.  This opens up a lot of exciting opportunities for things like downloadable game
levels, music tracks, etc.
* nabud now builds on Linux (built and tested on Ubuntu 22.04 LTS).

### nabud-0.7.1
* Fix a compiler warning that was happening with some versions of Xcode on macOS.

### nabud-0.7
* Support for remote sources, including NabuRetroNet, althrough NabuRetroNet's "HomeBrew"
channel does not work due to how the data is vended by that channel.
* Support for SecureTransport on macOS, eliminating the dependency on OpenSSL on that platform.

### nabud-0.6
* Added TCP connection support, for emulators such as MAME.
* Changed the build system to use GNU autotools.
* Several small bug fixes.

### nabud-0.5
This was the initial "preview" release, just meant to get it out there for folks to play with.
It supported only local sources and serial connections.  Written over the course of a few days
during the Christmas 2022 holiday break.

## Acknowledgements

First off, I want to acknowledge the folks nominally responsible for this NABU "Great Awakening":
* Adrian Black and his [Adrian's Digital Basement](https://www.youtube.com/@adriansdigitalbasement)
YouTube channel. I'm a Patreon patron of this channel and the early-access to Adrian's NABU video
is how I first learned of these cool machines.  I think it's fair to say that Adrian's video is
what spurred the recent interest in these machines.
* DJ Sures (his YouTube channel [here](https://www.youtube.com/@DJSures)) who has some family history
with the NABU and did a bunch of reverse engineering on the Adaptor protocol and has led the charge
on the NabuRetroNet.
* Leo Binkowski (his YouTube channel [here](https://www.youtube.com/@leo.binkowski)), a former NABU
engineer who preserved a TON of stuff when the NABU company folded.
* The York University Computer Museum's [NABU Network Reconstruction Project](https://museum.eecs.yorku.ca/nabu),
which has been working with these machines for many years now, and has been super gracious
even while being bombarded with requests for information.

I also want to acknowledge some people whose code I have borrowed or used as a reference for this project:
* Nick Daniels' [NabuNetworkEmulator](https://github.com/GryBsh/NabuNetworkEmulator) served as a reference
for the NABU Adaptor protocol.  The _nabu_proto.h_ file was derived directly from his work, and the file
_adaptor.c_ was partially derived from his work.
* David Kuder's [nabu-tftp](https://github.com/dkgrizzly/nabu-tftp) gateway for the Raspberry Pi Pico
also served to clarify some bits of the Adaptor protocol.
* Alistair Crooks' "Minimal JSON" (_libmj_) was used to build the configuraiton file parser.
* The _fetch_ library (_libfetch_) was written by primarily by Dag-Erling Smørgrav, with additional
contributions by Joerg Sonnenberger and Thomas Klausner.  The version here comes from The NetBSD Project.
* [The NetBSD Project](https://www.netbsd.org) is where the file _nbsd_queue.h_ comes from.  _<sys/queue.h>_ from BSD
is one of the handiest system header files in existence and I wish it were available everywhere.
