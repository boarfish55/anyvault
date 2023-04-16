#!/bin/sh
#
# anyvault -- a command-line password manager.
#
# Copyright (C) 2019-2023 Pascal Lalonde <plalonde@overnet.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

PATH=/bin:/usr/bin
db=/home/plalonde/prog/anyvault/anyvault.json.sample.gpg

usage() {
	echo "Usage: $(basename $0) -h <command>"
	echo ""
	echo "       $(basename $0) encrypt"
	echo ""
	echo "           Encrypts the JSON database using GnuPG"
	echo ""
	echo "       $(basename $0) decrypt"
	echo ""
	echo "           Decrypts the JSON database using GnuPG"
}

fatal() {
	echo "$(basename $0): $@" >&1
	exit 1
}

if [ "$1" = "-h" ]; then
	usage
	exit 2
fi

# The encrypt command should read from STDIN. It is best if data is passed
# directly into the encryption command which handles the decrypted data
# carefully without passing it through multiple buffer which may or may
# not keep the decrypted data around for a long time.
#
# Be mindful of the path of each command.
encrypt() {
	umask 0077

	tmpdb=`mktemp -t anyvault.XXXXXX`
	[ $? -ne 0 ] && exit 1

	# Of course you wouldn't put the passphrase here; this is only an
	# example.
	gpg --batch --yes -c --passphrase anyvault -o $tmpdb -
	if [ $? -ne 0 ]; then
		rm -f $tmpdb
		exit 1
	fi
	mv $tmpdb $db || exit 1
}

# The decrypt command should make sure the db exists, and if it doesn't,
# initialize it.
decrypt() {
	if [ ! -r $db ]; then
		# Provide an empty JSON database
		echo '{ "secrets": {} }'
		exit 0
	fi
	exec /usr/bin/gpg --decrypt $db
}

case $1 in
	encrypt)
		encrypt
		;;
	decrypt)
		decrypt
		;;
	*)
		usage
		exit 2
esac

exit $?
