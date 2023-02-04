#!/bin/sh -
#
# Copyright (c) 2023 Jason R. Thorpe.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#
# pakslurp --
#
# A simple script that will slurp down the PAK cycles of the NabuRetroNet
# cycles to your local machine.  This is useful if you want to serve the
# files locally.
#

base_url="https://cloud.nabu.ca"
max_image_number=767		# this seems to be the upper bound (0x300-1)

#
# If you're lucky[*] enough to have Luke Mewburn's enhanced ftp client (that
# can also download stuff from HTTP servers), tnen you don't have to bother
# with curl.
#
# [*] If you run NetBSD, then you are so lucky.
#
# XXX curl doesn't always seem to work.  Use at your own risk.  Better yet,
# install Luke's enhanced ftp client.
#
#	https://ftp.netbsd.org/pub/NetBSD/misc/tnftp/
#
URL_DOWNLOAD=ftp
#URL_DOWNLOAD="curl -f"

slurp_one_pak()
{
	#
	# Args:
	#
	#	$1	base URL
	#	$2	directory in which to save slurped file
	#	$3	image number
	#
	local hexnum
	local filename

	hexnum=`printf "%06X" $3`
	filename="${hexnum}.pak"

	$URL_DOWNLOAD -o "$2/$filename" "$1/$filename"
}

slurp_cycle()
{
	#
	# Args:
	#
	#	$1	base URL
	#	$2	directory in which to save slurped files
	#
	local image_number

	image_number=0
	while [ "$image_number" -le "$max_image_number" ]; do
		slurp_one_pak $1 $2 $image_number
		image_number=$(expr $image_number + 1)
	done
}

mkdir -p cycle1
slurp_cycle "$base_url/cycle%201%20raw" cycle1

mkdir -p cycle2
slurp_cycle "$base_url/cycle%202%20raw" cycle2

mkdir -p cycleDJ
slurp_cycle "$base_url/cycle%20DJ%20raw" cycleDJ
