# nabud - A server for the NABU PC

This is a server for the NABU Personal Computer.  For more information about
the NABU PC, please check out [NabuRetroNet](https://nabu.ca) as well as
[Adrian Black's video](https://www.youtube.com/watch?v=HLYjZoShjy0) about
the NABU.

This server is written in C and is intended to be very portable to the
Unix-like systems available today (the various BSDs, Linux, etc.) while
also being as self-contained as possible, relying on no "external" software
packages to build and run.  The majority of the APIs it uses are either
standard C99, standard POSIX, or extremely common extensions, for example
some common BSD APIs that are also available in Linux, such as _syslog(3)_
and _daemon(3)_.

## Features

* Define up to 254 content channels (numbered 1-255) from an arbitrary number
  of sources.
* Sources can be local or remote (such as NabuRetroNet).
* Serve an arbitrary number of NABU PCs:
    * As many RS422 serial ports as you can connect to your system for
      real NABU hardware.
    * Support for connections from NABU emulators (such as MAME) over TCP.
* Decrypt and serve NABU _pak_ files (available from NabuRetroNet).
* Serve your own or others' homebrew NABU binaries (_nabu_ files).
* High-performance; nabud implements a content cache to optimize common
  access patterns and avoid redundant I/O.
* Small footprint; it can run on small machines. The only thing it throws
  memory at is the content cache.
* A control program, nabuctl, that allows a user to easily change the
  channel used by a NABU connection, select programs to load from homebrew
  channels (that vend ".nabu" files), view listings provided by such channels,
  etc.

## Configuration

nabud's configuration is held in a JSON-format configuration file.  This
configuration file must contain 3 stanzas, in the following order:

* Sources: an array of content sources.  Sources provide the content that
  is served by Channels.
* Channels: an array of content channels.  Connections get their content
  from Channels.  Each Channel can be served by any source.
* Connections: an array of connections.

### Sources

Each Source has 3 properties:
* Name: a string that identifies the source.  It's meant both for human
  consumption as well as for specifying which Source provides a Channel.
* Location: a local path or a URL string that specifies the root of the source.

### Channels

Each Channel has 4 mandatory properties and 3 optional properties:
* Name: a string that identifies a Channel.  It's meant both for human
  consumption, but also specifies the name of the directory in the Source's
  location that contains the Channel's files.
* Path: an optional string that overrides the default directory for the
  Channel's content.
* ListURL: on optional string that specifies the URL for the Channel's file
  listing.
* DefaultFile: an optional string that specifies the default file to serve
  when the NABU requests image 000001.  This is used only if the Connection
  has not specified a selected file.
* Number: a unique number from 1 to 255 that identifies the Channel to the
  NABU.
* Type: a string that specifies the type of files provided by the Channel:
    * pak: NABU _pak_ files (content that is pre-wrapped in packet headers).
      These are the original NABU Network files and can be downloaded from
      NabuRetroNet.
    * nabu: Raw _nabu_ binary files, such as those you build yourself.
      nabud packetizes these files on-the-fly.
* Source: a string that specifies the Source that provides the Channel.

### Connections

Each Connection has 3 properties:
* Type: a string that specifies the type of connection:
    * serial: an RS422 serial connection to real NABU hardware.
    * tcp: a TCP listener that accepts connections from emulators (e.g. MAME).
* Port: a string that specifies the "port" to use for the connection, which
  varies based on the connection type:
    * serial: a string that specifies the path to the serial port to use for
      the connection.
    * tcp: a string that specifies the TCP port on which connections will be
      accepted.
* Channel: a number from 1 to 255 that specifies which channel to use for
  this connection.

### Example configuration file

This is the _nabud.conf_ configuration file I use to serve my own NABU:

    {
      "Sources": [
        {
          "Name": "Local",
          "Location": "/home/nabu/channels",
        },
        {
          "Name": "NabuRetroNet",
          "Location": "https://cloud.nabu.ca",
        }
      ],
      "Channels": [
        {
          "Name": "NABU Network 1984 Cycle v1",
          "Path": "cycle1",
          "Number": 1,
          "Type": "pak",
          "Source": "NabuRetroNet"
        },
        {
          "Name": "NABU Network 1984 Cycle v2",
          "Path": "cycle2",
          "Number": 2,
          "Type": "pak",
          "Source": "NabuRetroNet",
        },
        {
          "Name": "HomeBrew",
          "Path": "HomeBrew/titles",
          "ListURL": "https://cloud.nabu.ca/HomeBrew/titles/filesv2.txt",
          "Number": 9,
          "Type": "nabu",
          "Source": "NabuRetroNet",
          "RetroNetExtensions": true,
        },
        {
          "Name": "NABU Network 1984 Cycle v1",
          "Path": "cycle1",
          "Number": 11,
          "Type": "pak",
          "Source": "Local",
        },
        {
          "Name": "NABU Network 1984 Cycle v2",
          "Path": "cycle2",
          "Number": 12,
          "Type": "pak",
          "Source": "Local",
        },
        {
          "Name": "homebrew",
          "Number": 19,
          "Type": "nabu",
          "Source": "Local",
        }
      ],
      "Connections": [
        {
          "Type": "serial",
          "Port": "/dev/tty-uftdi-A10MHWD6-0",
          "Channel": 11,
          "FileRoot": "/home/nabu/storage/living-room-nabu",
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
          "Port": "5009",
          "Channel": 9,
          "FileRoot": "/home/nabu/storage/mame-nabu",
        },
        {
          "Type": "tcp",
          "Port": "5011",
          "Channel": 11,
        },
        {
          "Type": "tcp",
          "Port": "5012",
          "Channel": 12,
        },
        {
          "Type": "tcp",
          "Port": "5019",
          "Channel": 19,
          "FileRoot": "/home/nabu/storage/mame-nabu",
        }
      ]
    }

And this is the file layout of my one Source location:

    the-ripe-vessel:thorpej 256$ ls -l /home/nabu/channels
    total 28
    24 drwxr-xr-x  2 thorpej  wheel  22528 Dec 28 14:49 cycle1/
     4 drwxr-xr-x  2 thorpej  wheel    512 Dec 28 14:36 homebrew/
    the-ripe-vessel:thorpej 257$ ls -l /home/nabu/channels/homebrew
    total 8
    8 -rw-r--r--  1 thorpej  users  6732 Dec 28 09:09 000001.nabu
    the-ripe-vessel:thorpej 258$ ls -l /home/nabu/channels/cycle1    
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

In order to handle _pak_ files, a cryptographic library is required; MD5 is
used to generate _pak_ file names and DES is used to decrypt them.  The
following cryptographic libraries are currently supported:

* CommonCrypto (the native API on macOS)
* OpenSSL's _libcrypto_.  This is the native API already provided by many
  Unix-like systems, but you may have to go and install the "development"
  portion of the package in order to get the header files.

In order to download from remote sources, such as NabuRetroNet, an SSL
library is required.  The following SSL libraries are currently supported:

* SecureTransport (the native API on macOS)
* OpenSSL

On Ubuntu, the OpenSSL binaries and shared libraries were installed with
the base system, but the header files were not.  I installed them on my
Ubuntu system like so:

    % sudo apt update
    % sudo apt install libssl-dev

Linux is, of course, extremely fragmented, so if you have some other
distribution, getting OpenSSL installed is left as an exercise for the
reader.  Once it's installed, there is not likely to be any additional
magic that you need to perform; the configure script will probably find it.

Because an effort has been made to keep nabud fairly self-contained and
reliant only on APIs provided by the operating system, building it just
requires a toolchain.  For the BSDs and Linux, it's probably already
installed on your system, but if it's not, then doing so is left as an
exercise for the reader.  For macOS, you will need to install the
[Xcode Developer Tools](https://apps.apple.com/us/app/xcode/id497799835)
and then launch Xcode to perform the "first launch" task that takes care of
setting up the command-line tools that nabud uses to build.

## Running nabud

After building nabud, copy the example _nabud.conf_ to the selected location
(default: _/etc/nabud.conf_), tailor it to your system, and then run it:

    # ./nabud

nabud requires no special permissions; only the ability to open files to be
served to the NABU for reading, and the ability to open the serial ports for
reading and writing.  You can choose to run it as _root_ or as an unprivileged
user if you set the permissions on your serial port devices properly.  If
you're only using TCP functionality, it can run completely unprivileged.

nabud understands the following command line options:
* _-c conf_ -- specifies an alternate name / location for _nabud.conf_.
* _-d_ -- enables debugging.  This option also implies _-f_.
* _-f_ -- run in the foreground.  Without this, nabud will detach from the
  controlling terminal and run as a daemon.
* _-l logfile_ -- specifies the path to a log file.  Without this option,
  nabud will log to the system log using _syslog(3)_ using the _LOG_USER_
  facility.  Note that when running in the foreground, log messages are always
  sent to the controlling terminal.
* _-u user_ -- Specifies the user that nabud should run as.
* _-U umask_ -- Specifies the file creation mask that nabud should use when
creating files.

In addition to errors, nabud logs some basic information about the requests
it services.  Here is a system log snippet showing the messages you will
typically see:

    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: main: Welcome to NABU! I'm version 0.8 of your host, nabud.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: main: Running as UID 2000, file creation mask 002
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: control_init: Creating control channel at /tmp/nabuctl.sock
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_source: Adding Source Local at /home/nabu
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_source: Adding Source NabuRetroNet at https://cloud.nabu.ca
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Adding pak channel 1 (NABU Network 1984 Cycle v1 on NabuRetroNet) at https://cloud.nabu.ca/cycle1
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Adding pak channel 2 (NABU Network 1984 Cycle v2 on NabuRetroNet) at https://cloud.nabu.ca/cycle2
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Adding nabu channel 3 (HomeBrew on NabuRetroNet) at https://cloud.nabu.ca/HomeBrew/titles
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Channel 3 has a listing at: https://cloud.nabu.ca/HomeBrew/titles/files.txt
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Adding pak channel 11 (cycle1 on Local) at /home/nabu/cycle1
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_add_channel: Adding nabu channel 12 (homebrew on Local) at /home/nabu/homebrew
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_serial: Creating Serial connection on /dev/tty-uftdi-A10MHWD6-0.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [/dev/tty-uftdi-A10MHWD6-0] Selected channel 1 (NABU Network 1984 Cycle v1 on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_tcp: Creating TCP listener on port 5001.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv6-5001] Selected channel 1 (NABU Network 1984 Cycle v1 on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv4-5001] Selected channel 1 (NABU Network 1984 Cycle v1 on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: adaptor_event_loop: [/dev/tty-uftdi-A10MHWD6-0] Connection starting.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_tcp: Creating TCP listener on port 5002.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv6-5002] Selected channel 2 (NABU Network 1984 Cycle v2 on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv4-5002] Selected channel 2 (NABU Network 1984 Cycle v2 on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_tcp: Creating TCP listener on port 5003.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv6-5003] Selected channel 3 (HomeBrew on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv4-5003] Selected channel 3 (HomeBrew on NabuRetroNet).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_tcp: Creating TCP listener on port 5011.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv6-5011] Selected channel 11 (cycle1 on Local).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv4-5011] Selected channel 11 (cycle1 on Local).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: conn_add_tcp: Creating TCP listener on port 5012.
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv6-5012] Selected channel 12 (homebrew on Local).
    Jan 14 11:00:23 the-ripe-vessel nabud[19985]: INFO: image_channel_select: [IPv4-5012] Selected channel 12 (homebrew on Local).

It is recommended that you run nabud as a minimally-privileged user using
the _-u user_ option.  Typically, you would do this by following these steps:

1. Create a group that will be able to modify any files created by nabud,
   for example _nabu_.
2. Create a user specifically for running nabud, for example _nabu_.  Set
   the default group ID of that user to the group created in step 1.
3. Select a group that will be used to grant permission to open serial ports
   for NABU connections.  Historically, a _dialer_ group exists on some Unix
   systems for this purpose.  Create one, if necessary.
4. Add the user created in step 2 to the group you selected in step 3.
5. Ensure your serial port devices grant read/write permission to the group
   selected in step 3.
6. Optionally use the _-U umask_ argument to alter the default file creation
   mask so that users in the group created in step 1 can both read and write
   any files created by nabud.

For example, on my NetBSD system, I have the following user and group
configuration for nabud:

    % grep nabu /etc/group
    dialer:*:117:nabu
    nabu:*:2000:thorpej
    
    % grep nabu /etc/passwd
    nabu:*:2000:2000:NABU User:/nonexistent:/sbin/nologin
    
    % ls -l /dev/ttyU*
    0 crw-rw----  1 uucp  dialer  66, 0 Dec 31 14:15 /dev/ttyU0
    0 crw-rw----  1 uucp  dialer  66, 1 May 19  2021 /dev/ttyU1
    0 crw-rw----  1 uucp  dialer  66, 2 May 19  2021 /dev/ttyU2
    0 crw-rw----  1 uucp  dialer  66, 3 May 19  2021 /dev/ttyU3
    0 crw-rw----  1 uucp  dialer  66, 4 May 19  2021 /dev/ttyU4
    0 crw-rw----  1 uucp  dialer  66, 5 May 19  2021 /dev/ttyU5
    0 crw-rw----  1 uucp  dialer  66, 6 May 19  2021 /dev/ttyU6
    0 crw-rw----  1 uucp  dialer  66, 7 May 19  2021 /dev/ttyU7
    
    # ./nabud -u nabu -U 002

## Extras for your operating system

nabud comes with some extras that help with integration onto operating
systems on which it runs.

* NetBSD - An _rc.d_ script and an _rc.conf.d_ configuration file are
  installed into $(prefix)/share.  Tweak them to your liking and copy them
  into _/etc/rc.d_ and _/etc/rc.conf.d_.
* FreeBSD - An _rc.d_ script and an _rc.conf.d_ configuration file are
  installed into $(prefix)/share.  Tweak them to your liking and copy them
  into _/etc/rc.d_ and _/etc/rc.conf.d_.
* OpenBSD - An _rc.d_ script is installed into $(prefix)/share.
  Tweak it to your liking and install it into _/etc/rc.d_.  Make sure to
  update your "pkg_scripts" variable in _/etc/rc.conf_.
* macOS - A launchd plist file (_nabud.plist_) is installed into
  $(prefix)/share.  Tweak it to your liking and install it into
  _/Library/LaunchDaemons_.

If you are interested in providing extras for your favorite operating
system, please let me know!

## Controlling nabud with nabuctl

A control program, nabuctl, is provided that allows you to interact with
nabud to change channels, list connections, display channel listings, etc.
nabuctl must be run on the same system where nabud is running.

Upon start-up, nabuctl does a handshake with the server to ensure they're
the same version:

    % nabuctl
    Server version: 1.1
    nabuctl> 

There is some basic help available:

    nabuctl> ?
    Available commands:
            exit
            quit
            help
            ?
            channel
            connection
            list
            show
    nabuctl> 

You can list the channels available, as well as any current connections:

    nabuctl> list channels
    1  - NABU Network 1984 Cycle v1 (NabuRetroNet)
    2  - NABU Network 1984 Cycle v2 (NabuRetroNet)
    3  - DJs Playground Cycle       (NabuRetroNet)
    9  - HomeBrew                   (NabuRetroNet)
    11 - NABU Network 1984 Cycle v1 (Local)
    12 - NABU Network 1984 Cycle v2 (Local)
    19 - homebrew                   (Local)
    nabuctl> list connections
    1  - Serial   [1]  /dev/tty-uftdi-A10MHWD6-0
    2  - Listener [1]  IPv6-5001
    3  - Listener [1]  IPv4-5001
    4  - Listener [2]  IPv6-5002
    5  - Listener [2]  IPv4-5002
    6  - Listener [3]  IPv6-5003
    7  - Listener [3]  IPv4-5003
    8  - Listener [9]  IPv6-5009
    9  - Listener [9]  IPv4-5009
    10 - Listener [11] IPv6-5011
    11 - Listener [11] IPv4-5011
    12 - Listener [12] IPv6-5012
    13 - Listener [12] IPv4-5012
    14 - Listener [19] IPv6-5019
    15 - Listener [19] IPv4-5019
    nabuctl> 

You can change channels:

    nabuctl> connection 1 channel 9
    /dev/tty-uftdi-A10MHWD6-0: Selecting channel 'HomeBrew' on NabuRetroNet.
    nabuctl> 

Additional details for channels and connections can also be viewed:

    nabuctl> show channel 9
    Channel 9:
            Name: HomeBrew
          Source: NabuRetroNet
            Path: https://cloud.nabu.ca/HomeBrew/titles
            Type: NABU
     Listing URL: https://cloud.nabu.ca/HomeBrew/titles/filesv2.txt
        RetroNet: enabled
    nabuctl> show connection 1
    Connection 1:
             Name: /dev/tty-uftdi-A10MHWD6-0
             Type: Serial
            State: OK
          Channel: 9
     Storage area: /home/nabu/storage/living-room-nabu
         RetroNet: enabled
    nabuctl> 

You can see the list of files available on a connections' channel, if
that channel provides a listing:

    nabuctl> connection 1 listing
    =====> RetroNET
    1  - CPM22.nabu                Cloud CP/M 2.2 (BIOS v3.5b)
    2  - RetronetChat.nabu         Chat (v2.8b)
    3  - Telnet Client.nabu        vt100 Telnet Client (1.0b)
    4  - Slidesho.nabu             Slide Show Gallery
    =====> Demos
    5  - Demo - Christmas.nabu     Merry Christmas
    6  - Demo - Bad Apple.nabu     Bad Apple!
    7  - plasma.nabu               Plasma
    8  - HelloNABUBounce.nabu      Hello NABU Bounce
    9  - Mandelbrot.nabu           Mandelbrot
    =====> Games
    10 - brickbattle.nabu          Brick Battle (0.1b)
    11 - gamemanyeah.nabu          Game Man Yeah! (0.8b)
    12 - gamemanyeahprototype.nabu Game Man Yeah Prototype
    13 - Nabutris.nabu             Nabutris
    14 - doom.nabu                 DOOM!
    15 - AQUATTACK.nabu            Aqua Attack
    16 - FLIP_AND_FLOP.nabu        Flip and Flop
    17 - GALAXIAN.nabu             Galaxian
    18 - HEAVYWEIGHT_BOXING.nabu   Heavy Weight Boxing
    19 - LASER_ATTACK.nabu         Laser Attack
    20 - MANIA.nabu                Mania
    21 - MINER2049ER.nabu          Miner 2049er
    22 - MOONSWEEPER.nabu          Moon Sweeper
    23 - MOTORCYCLE.nabu           Motorcycle
    24 - MUMMYS_TOMB.nabu          Mummy's Tomb
    25 - pac-man.nabu              Pac-Man
    26 - Q-BERT.nabu               Q-Bert
    27 - QUEST_FOR_TIRES.nabu      Quest For Tires
    28 - TIME_PILOT.nabu           Time Pilot
    29 - TRACK_FIELD_1.nabu        Track & Field 1
    30 - UFOS.nabu                 UFOs
    31 - WINGWAR.nabu              Wing War
    =====> Utilities
    32 - Remote FS Test.nabu       Remote File System Test
    33 - ScanCodeViewer.nabu       Scan Code Viewer
    34 - ScrollTest.nabu           Scroll Test
    nabuctl> 

And you can select a file to loaded when the NABU boots and requests image
000001:

    nabuctl> connection 1 file 13
    /dev/tty-uftdi-A10MHWD6-0: Selecting file 'Nabutris.nabu'
    nabuctl> 

## Changes

### nabud-1.1
* Tweaks to image cache management: images from local sources are cached
  less aggressively.  This reduces the memory footprint of nabud at very
  little cost to overall performance, and also makes local NABU program
  development a bit easier as there is no need to manually clear the cache
  each time a new image is dropped into a local channel being used for
  that purpose.
* Added support for NabuRetroNet protocol extensions version _v2023.02.03.00_.
  This enables running the NabuRetroNet Cloud CP/M.
* Updated the example _nabud.conf_ file to show storage and RetroNet
  options.

### nabud-1.0
* Added support for the NABU HCCA Application Communication Protocol.  This
  protocol is much better specified than the NabuRetroNet protocol (which
  doesn't even really have a specification) and is more easily extensible
  to provide other services besides storage (for example, network connection
  proxy, etc.).  Information about NHACP can be found
  [here](https://github.com/hanshuebner/nabu-figforth/blob/main/nabu-comms.md).
* Added _rc.d_ and _rc.conf.d_ extras for FreeBSD.
* Added an _rc.d_ extra for OpenBSD.
* Added a launchd plist extra for macOS.
* Another change for Linux's over-restrictive cfsetspeed(3).  Thanks to
  tatokis for pointing it out and confirming the fix.
* Man pages for nabud(8) and nabuctl(1).

### nabud-0.9.1
* Fixed a problem with Linux's overly-restrictive cfsetspeed(3) whereby
  attempting to set the native NABU baud rate would cause the entire serial
  port setup to fail rather then falling back to 115.2K baud.

### nabud-0.9
* Added _rc.d_ and _rc.conf.d_ extras for NetBSD and a few other tweaks
  to make it ready for pkgsrc.
* Updated example config in preparation for additional NabuRetroNet channels.
* Fixed the time packet to properly report the day of the week.

### nabud-0.8
* Experimental for the NabuRetroNet blob store extensions to the Adaptor
  protocol.  These extensions allow programs running on the NABU to access
  up to 256 "slots" of cloud storage that are cached in the server.  This
  opens up a lot of exciting opportunities for things like downloadable game
  levels, music tracks, etc.  This work is currently unfinished, and is
  provided only as a preview.
* nabud now builds on Linux (built and tested on Ubuntu 22.04 LTS).
* Added _-u user_ and _-U umask_ options for easily running nabud as a
  minimally-privileged user.
* Added nabuctl, a program for sending control messages to nabud.  This
  allows you to easily change the channel used by individual NABU connections,
  and list and select programs to run from the NabuRetroNet _HomeBrew_ channel.

### nabud-0.7.1
* Fix a compiler warning that was happening with some versions of Xcode on
  macOS.

### nabud-0.7
* Support for remote sources, including NabuRetroNet, althrough
  NabuRetroNet's "HomeBrew" channel does not work due to how the data
  is vended by that channel.
* Support for SecureTransport on macOS, eliminating the dependency on
  OpenSSL on that platform.

### nabud-0.6
* Added TCP connection support, for emulators such as MAME.
* Changed the build system to use GNU autotools.
* Several small bug fixes.

### nabud-0.5
This was the initial "preview" release, just meant to get it out there for
folks to play with.  It supported only local sources and serial connections.
Written over the course of a few days during the Christmas 2022 holiday break.

## Acknowledgements

First off, I want to acknowledge the folks nominally responsible for this
NABU "Great Awakening":
* Adrian Black and his [Adrian's Digital Basement](https://www.youtube.com/@adriansdigitalbasement)
  YouTube channel. I'm a Patreon patron of this channel and the early-access
  to Adrian's NABU video is how I first learned of these cool machines.  I
  think it's fair to say that Adrian's video is what spurred the recent
  interest in these machines.
* DJ Sures (his YouTube channel [here](https://www.youtube.com/@DJSures))
  who has some family history with the NABU and did a bunch of reverse
  engineering on the Adaptor protocol and has led the charge on the
  NabuRetroNet.
* Leo Binkowski (his YouTube channel [here](https://www.youtube.com/@leo.binkowski)),
  a former NABU engineer who preserved a TON of stuff when the NABU company
  folded.
* The York University Computer Museum's
  [NABU Network Reconstruction Project](https://museum.eecs.yorku.ca/nabu),
  which has been working with these machines for many years now, and has
  been super gracious even while being bombarded with requests for information.

I also want to acknowledge some people whose code I have borrowed or used
as a reference for this project:
* Nick Daniels' [NabuNetworkEmulator](https://github.com/GryBsh/NabuNetworkEmulator)
  served as a reference for the NABU Adaptor protocol.  The files _nabu_proto.h_
  and _adaptor.c_ were partially derived from his work.
* David Kuder's [nabu-tftp](https://github.com/dkgrizzly/nabu-tftp) gateway
  for the Raspberry Pi Pico also served to clarify some bits of the Adaptor
  protocol.
* Alistair Crooks' "Minimal JSON" (_libmj_) was used to build the
  configuration file parser.
* The _fetch_ library (_libfetch_) was written by primarily by Dag-Erling
  Smørgrav, with additional contributions by Joerg Sonnenberger and
  Thomas Klausner.  The version here comes from The NetBSD Project.
* [The NetBSD Project](https://www.netbsd.org) is where the file _nbsd_queue.h_
  comes from.  _<sys/queue.h>_ from BSD is one of the handiest system header
  files in existence and I wish it were available everywhere.
