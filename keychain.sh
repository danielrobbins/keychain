#!/bin/sh

versinfo() {
	qprint
	qprint "   Copyright ${CYANN}2002-##CUR_YEAR##${OFF} Daniel Robbins, BreezyOps"
	qprint "   lockfile() Copyright ${CYANN}2009${OFF} Parallels, Inc."
	qprint "   Copyright ${CYANN}2007${OFF} Aron Griffis"
	qprint "   Copyright ${CYANN}2002-2006${OFF} Gentoo Foundation"
	qprint
	qprint " Keychain is free software: you can redistribute it and/or modify"
	qprint " it under the terms of the ${CYANN}GNU General Public License version 2${OFF} as"
	qprint " published by the Free Software Foundation."
	qprint
}

umask 0077
NEWLINE="
"
version=##VERSION##
PATH="${PATH}${PATH:+:}/usr/bin:/bin:/sbin:/usr/sbin:/usr/ucb"
unset pidfile_out
unset myaction
havelock=false
unset hostopt
extended=false
confallhosts=false
ignoreopt=false
noaskopt=false
noguiopt=false
nolockopt=false
lockwait=5
openssh=unknown
sunssh=unknown
quickopt=false
quietopt=false
clearopt=false
allow_inherited=true
color=true
unset stopwhich
unset timeout
unset ssh_agent_socket
unset ssh_timeout
unset sshavail
unset sshkeys
unset gpgkeys
unset cmdline_keys
keydir="${HOME}/.keychain"
unset envf
evalopt=false
confirmopt=false
absoluteopt=false
systemdopt=false
unset ssh_confirm
unset GREP_OPTIONS
gpg_prog_name="gpg"
gpg_started=false
ssh_allow_forwarded=false
ssh_allow_gpg=false
ssh_spawn_gpg=false
debugopt=false
CYAN="[36;01m"
CYANN="[36m"
GREEN="[32;01m"
RED="[31;01m"
PURP="[35;01m"
YEL="[33;01m"
OFF="[0m"

# GNU awk and sed have regex issues in a multibyte environment.  If any locale
# variables are set, then override by setting LC_ALL
unset pinentry_locale
if [ -n "$LANG$LC_ALL" ] || locale 2>/dev/null | grep -E -qv '="?(|POSIX|C)"?$' 2>/dev/null; then
	# save LC_ALL so that pinentry-curses works right.	This has always worked
	# correctly for me but peper and kloeri had problems with it.
	pinentry_lc_all="$LC_ALL"
	LC_ALL=C
	export LC_ALL
fi

qprint() {
	# shellcheck disable=SC2048,SC2086
	$quietopt || echo "$@" >&2; return 0
}

mesg() { # general information; suppressed with --quiet
	qprint " ${GREEN}*${OFF} $*"
}

warn() { # important warning; not suppressed with --quiet
	# shellcheck disable=SC2048,SC2086
	echo " ${RED}* Warning${OFF}: "$* >&2
}

note() { # important notice; suppressed with --quiet
	# shellcheck disable=SC2048,SC2086
	qprint " ${YEL}* Note${OFF}: "$* >&2
}

debug() {
	# shellcheck disable=SC2048,SC2086
	$debugopt && echo " ${CYAN}debug>" $*"${OFF}" >&2; return 0
}

error() {
	# shellcheck disable=SC2048,SC2086
	echo " ${RED}* Error${OFF}:" $* >&2
}

die() {
	[ -n "$1" ] && error "$*"
	qprint
	$evalopt && { echo; echo "false;"; }
	exit 1
}

helpinfo() {
	cat >&1 <<EOHELP
INSERT_POD_OUTPUT_HERE
EOHELP
}

me=$(id -un) || die "Who are you?  id -un doesn't know..."

# synopsis: get_owner path
# Portable function to extract the owner (username) of a file or directory.
# Handles usernames with spaces by using POSIX-defined ls -l output format.
#
# POSIX defines ls -l format as: permissions links owner group size ...
# Field 3 is owner, field 4 is group. However, on some systems (e.g., Windows/Cygwin),
# usernames can contain spaces, making field parsing ambiguous:
#   - "drobbins drobbins 4096" -> owner="drobbins", group="drobbins", size=4096
#   - "Mathew Binkley 197609 4096" -> owner="Mathew Binkley", group="197609", size=4096
#
# We distinguish by checking if the field after potential owner+space is numeric:
# If field 5 is NOT numeric, then field 4 is part of the owner name (space in username).
# If field 5 IS numeric, then field 4 is the group name (no space in username).
get_owner() {
	go_path="$1"
	# shellcheck disable=SC2012 # Using ls -ld for POSIX-defined formatted output; not parsing ls in a loop
	ls -ld "$go_path" 2>/dev/null | awk '{
		result = $3
		if (NF >= 5 && $5 !~ /^[0-9]+$/) {
			result = result " " $4
		}
		print result
	}'
}

# synopsis: testssh
# Figure out which ssh is in use, set the global boolean $openssh and $sunssh
testssh() {
	# Query local host for SSH application, presently supporting OpenSSH and Sun SSH:
	openssh=false
	sunssh=false

	case "$(ssh -V 2>&1)" in
		*OpenSSH*) openssh=true ;;
		*Sun?SSH*) sunssh=true ;;
	esac
	# See if gpg-agent is available and provides ssh-agent functionality:
	if $ssh_spawn_gpg; then
		if  ! out="$(gpg-agent --help | grep enable-ssh-support)" || [ -z "$out" ]; then
			warn "gpg-agent ssh functionality not available; not using..."
			ssh_spawn_gpg=false
		fi
	fi
}

# synopsis: verifykeydir
# Make sure the key dir is set up correctly.  Exits on error.
verifykeydir() {
	# Create keydir if it doesn't exist already
	if [ -f "${keydir}" ]; then
		die "${keydir} is a file (it should be a directory)"
	# Solaris 9 doesn't have -e; using -d....
	elif [ ! -d "${keydir}" ]; then
		mkdir "${keydir}" || die "can't create ${keydir}"
	fi
	dir_owner="$(get_owner "${keydir}")"
	[ "$dir_owner" != "$me" ] && warn "${keydir} is owned by ${dir_owner}, not ${me}. Please fix."
	# shellcheck disable=SC2012 # POSIX defines the first 9 chars of ls -l:
	[ "$(ls -ld "${keydir}" | cut -c5-10)" != "------" ] && warn "Keychain dir has lax permissions. Use ${CYAN}chmod -R go-rwx '${keydir}'${OFF} to fix."
	if ! :> "$pidf.foo"; then
		die "can't write inside $pidf"
	else
		rm -f "$pidf.foo"
	fi
}

lockfile() {
	# This function originates from Parallels Inc.'s OpenVZ vpsreboot script.

	# Description: This function attempts to acquire the lock. If it succeeds,
	# it returns 0. If it fails, it returns 1. This function retuns immediately
	# and only tries to acquire the lock once.

	tmpfile="$lockf.$$"

	echo $$ >"$tmpfile" 2>/dev/null || exit
	if ln "$tmpfile" "$lockf" 2>/dev/null; then
		rm -f "$tmpfile"
		havelock=true && return 0
	fi
	if kill -0 "$(cat "$lockf" 2>/dev/null)" 2>/dev/null; then
		rm -f "$tmpfile"
		return 1
	fi
	if ln "$tmpfile" "$lockf" 2>/dev/null; then
		rm -f "$tmpfile"
		havelock=true && return 0
	fi
	rm -f "$tmpfile" "$lockf" && return 1
}

takelock() {
	# Description: This function calls lockfile() multiple times if necessary
	# to try to acquire the lock. It returns 0 on success and 1 on failure.
	# Change in behavior: if timeout expires, we will forcefully acquire lock.

	[ "$havelock" = "true" ] && return 0
	[ "$nolockopt" = "true" ] && return 0

	# First attempt:
	lockfile && return 0

	counter=0
	mesg "Waiting $lockwait seconds for lock..."
	while [ "$counter" -lt "$(( lockwait * 10 ))" ]
	do
		lockfile && return 0
		sleep 0.1; counter=$(( counter + 1 ))
	done
	rm -f "$lockf" && lockfile && return 0
	return 1
}

# synopsis: droplock
# Drops the lock if we're holding it.
droplock() {
	$havelock && [ -n "$lockf" ] && rm -f "$lockf"
}

# synopsis: findpids [prog]
# Returns a space-separated list of agent pids.
# prog can be ssh or gpg, defaults to ssh.	Note that if another prog is ever
# added, need to pay attention to the length for Solaris compatibility.
findpids() {
	fp_prog=${1-ssh}
	unset fp_psout

	# Different systems require different invocations of ps.  Try to generalize
	# the best we can.	The only requirement is that the agent command name
	# appears in the line, and the PID is the first item on the line.
	if [ -z "$OSTYPE" ]; then
		OSTYPE=$(uname) || die 'uname failed'
	fi

	# Try systems where we know what to do first
	case "$OSTYPE" in
		AIX|*bsd*|*BSD*|CYGWIN|darwin*|Linux|linux-gnu|OSF1)
			fp_psout=$(ps x 2>/dev/null) ;;		# BSD syntax
		HP-UX)
			fp_psout=$(ps -u "$me" 2>/dev/null) ;; # SysV syntax
		SunOS)
			case $(uname -r) in
				[56]*)
					fp_psout=$(ps -u "$me" 2>/dev/null) ;; # SysV syntax
				*)
					fp_psout=$(ps x 2>/dev/null) ;; # BSD syntax
			esac ;;
		GNU|gnu)
			fp_psout=$(ps -g 2>/dev/null) ;; # GNU Hurd syntax
	esac

	# If we didn't get a match above, try a list of possibilities...
	# The first one will probably fail on systems supporting only BSD syntax.
	if [ -z "$fp_psout" ]; then
		# shellcheck disable=SC2009
		fp_psout=$(UNIX95=1 ps -u "$me" -o pid,comm 2>/dev/null | grep '^ *[0-9]+')
		[ -z "$fp_psout" ] && fp_psout=$(ps x 2>/dev/null)
		[ -z "$fp_psout" ] && fp_psout=$(ps w 2>/dev/null) # Busybox syntax
	fi

	# Return the list of pids; ignore case for Cygwin.
	# Check only 8 characters since Solaris truncates at that length.
	# Ignore defunct ssh-agents (bug 28599)
        # Ignore gpg-agent with non-default --homedir option (issue #202)
	if [ -n "$fp_psout" ]; then
		echo "$fp_psout" | \
			awk "BEGIN{IGNORECASE=1} /defunct/{next} /homedir/{next}
				/$fp_prog-[a]gen/{print \$1}" | xargs
		return 0
	fi

	# If none worked, we're stuck
	error "Unable to use \"ps\" to scan for $fp_prog-agent processes"
	error "Please report to https://github.com/danielrobbins/keychain/issues."
	return 1
}

stop_ssh_agents() {
	mesg "Stopping ssh-agent(s)..."
	takelock || die
	[ "$stopwhich" != all ] && eval "$(catpidf_shell sh)" # get SSH_AGENT_PID if defined
	ssh_pids=$(findpids ssh) || die
	if [ -z "$ssh_pids" ]; then
		mesg "No ssh-agent(s) found running"
	elif [ "$stopwhich" = all ]; then
		# shellcheck disable=SC2086
		kill $ssh_pids >/dev/null 2>&1
		mesg "All ${CYANN}$me${OFF}'s ssh-agents stopped: ${CYANN}$ssh_pids${OFF}"
	elif [ -n "$SSH_AGENT_PID" ]; then
		if [ "$stopwhich" = mine ]; then
			kill "$SSH_AGENT_PID" >/dev/null 2>&1
			mesg "Keychain ssh-agents stopped: ${CYANN}$SSH_AGENT_PID${OFF}"
		else # others
			for ssh_pid in $ssh_pids; do
				[ "$ssh_pid" = "$SSH_AGENT_PID" ] && continue
				kill "$ssh_pid" >/dev/null 2>&1
				killed_pids="$killed_pids $ssh_pid"
			done
			mesg "Other ${CYANN}$me${OFF}'s ssh-agents stopped:${CYANN}$killed_pids${OFF}"
		fi
	else
		mesg "No keychain ssh-agent found running"
	fi

	# remove pid files if keychain-controlled
	if [ "$stopwhich" != others ]; then
		rm -f "${pidf}" "${cshpidf}" "${fishpidf}" 2>/dev/null
	fi
	qprint && exit 0
}

# synopsis: catpidf_shell shell
# cat the pid file for the specified shell.
catpidf_shell() {
	case "$1" in
		*/fish|fish) cp_pidf="$fishpidf" ;;
		*csh)		 cp_pidf="$cshpidf" ;;
		*)			 cp_pidf="$pidf" ;;
	esac
	if [ ! -f "$cp_pidf" ]; then
		debug "pidfile doesn't exist"; return 1
	else
		cat "${cp_pidf}"; echo; return 0
	fi
}

startagent_gpg() {
	if $gpg_started; then
		return 0
	else
		gpg_started=true
	fi
	if gpg_agent_sock="$( echo "GETINFO socket_name" | gpg-connect-agent --no-autostart | head -n1 | sed -n 's/^D //;1p' )" && [ -S "$gpg_agent_sock" ]; then
		mesg "Using existing gpg-agent: ${CYANN}$gpg_agent_sock${OFF}"
		pidfile_out="SSH_AUTH_SOCK=$gpg_agent_sock; export SSH_AUTH_SOCK" # make sure we adopt it
	else
		gpg_opts="--daemon"
		[ -n "${timeout}" ] && gpg_opts="$gpg_opts --default-cache-ttl $(( timeout * 60 )) --max-cache-ttl $(( timeout * 60 ))"
		$ssh_spawn_gpg && gpg_opts="$gpg_opts --enable-ssh-support"
		mesg "Starting gpg-agent..."
		# shellcheck disable=SC2086 # this is intentional
		pidfile_out="$(gpg-agent --sh $gpg_opts)"
		return $?
	fi
}

ssh_envcheck() {
	# Initial short-circuits for known abort cases:
	[ -z "$SSH_AUTH_SOCK" ] && return 1
	if [ ! -S "$SSH_AUTH_SOCK" ]; then
		debug "SSH_AUTH_SOCK in $1 is invalid; ignoring it"
		unset SSH_AUTH_SOCK && return 1
	fi

	# Throw away the PID with a devug warning if it's invalid:

	if [ -n "$SSH_AGENT_PID" ] && ! kill -0 "$SSH_AGENT_PID" >/dev/null 2>&1; then
		unset SSH_AGENT_PID && debug "SSH_AGENT_PID in $1 is invalid; ignoring it"
	fi

	# Now, find potential agents:

	if [ -z "$SSH_AGENT_PID" ]; then

		# There are some cases where we can accept a socket without an associated SSH_AGENT_PID:

		if gpg_socket="$(echo "GETINFO ssh_socket_name" | gpg-connect-agent --no-autostart 2>/dev/null | head -n1 | sed -n 's/^D //;1p' )"; then
			if [ "$gpg_socket" = "$SSH_AUTH_SOCK" ]; then
				if $ssh_allow_gpg; then
					$quickopt || mesg "Using ssh-agent ($1): ${CYANN}$gpg_socket${OFF} (GnuPG)"
					return 0
				else
					unset SSH_AUTH_SOCK && debug "Ignoring SSH_AUTH_SOCK -- this is the GnuPG-supplied socket" && return 1
				fi
			fi
		fi

		if $ssh_allow_forwarded; then
			SSH_AGENT_PID="forwarded"
			$quickopt || mesg "Using ${GREEN}forwarded${OFF} ssh-agent: ${GREEN}$SSH_AUTH_SOCK${OFF}"
			return 0
		else
			unset SSH_AUTH_SOCK && debug "Ignoring SSH_AUTH_SOCK -- this is a forwarded socket" && return 1
		fi
	else
		# We have valid SSH_AGENT_PID, so we accept the socket too:
		$quickopt || mesg "Existing ssh-agent ($1): ${CYANN}$SSH_AGENT_PID${OFF}"
		return 0
	fi
}

# synopsis: startagent_ssh
# This function specifically handles (potential) starting of ssh-agent. Unlike the
# classic startagent function, it does not handle writing out contents of pidfiles,
# which will be done in a combined way after startagent_gpg() is called as well.

startagent_ssh() {
	if $quickopt; then
		if ( unset SSH_AGENT_PID SSH_AUTH_SOCK && eval "$(catpidf_shell sh)" && ssh_envcheck quick && ssh_l > /dev/null ); then
			mesg "Found existing populated ssh-agent (quick)"
			return 0
		else
			if ( eval "$(catpidf_shell sh)" && ssh_envcheck quick ); then
				note "Quick start unsuccessful -- no keys loaded..."
			else
				note "Quick start unsuccessful -- no agent found..."
			fi
			quickopt=false
		fi
	fi
	takelock || die
	# See if our pidfile is valid without wiping env:
	if ( unset SSH_AGENT_PID SSH_AUTH_SOCK && eval "$(catpidf_shell sh)" && ssh_envcheck pidfile ); then
		# Our pidfile is valid! :) We can simply use it:
		debug "pidfile is valid" && unset SSH_AGENT_PID SSH_AUTH_SOCK && eval "$(catpidf_shell sh)"
	elif $allow_inherited && ssh_envcheck env; then
		# If our env is OK, then let's grab it for our pidfile, as long as we don't have a forwarded ssh connection:
		if [ "$SSH_AGENT_PID" != forwarded ]; then
			pidfile_out="SSH_AUTH_SOCK=$SSH_AUTH_SOCK; export SSH_AUTH_SOCK"
			if [ -n "$SSH_AGENT_PID" ]; then
				pidfile_out="$pidfile_out
SSH_AGENT_PID=$SSH_AGENT_PID; export SSH_AGENT_PID;"
			fi
		fi
	else  # spawn, we must...
		rm -f "${pidf}" "${cshpidf}" "${fishpidf}" 2>/dev/null # pidfile is either non-existant or invalid
		if $ssh_spawn_gpg; then
			startagent_gpg ssh # this function will set pidfile_out itself
			return $?
		else
			mesg "Starting ssh-agent..."
			# shellcheck disable=SC2086 # We purposely don't want to double-quote the args to ssh-agent so they disappear if not used:
			pidfile_out="$(ssh-agent -s ${ssh_timeout} ${ssh_agent_socket})"
			return $?
		fi
	fi
}

write_pidfile() {
	if [ -n "$pidfile_out" ]; then
		pidfile_out=$(echo "$pidfile_out" | grep -v 'Agent pid')
		case $pidfile_out in setenv\ *) error "unexpected csh-style ssh-agent output (expected -s)"; exit 1;; esac
		rm -f "$pidf" "$cshpidf" "$fishpidf" # Remove first, so we can recreate with our umask

		# Robust approach: eval the output in a subshell to extract actual variable values
		# This avoids fragile string parsing and handles any ssh-agent output format changes
		wp_auth_sock=$(eval "$pidfile_out" >/dev/null 2>&1; echo "$SSH_AUTH_SOCK")
		wp_agent_pid=$(eval "$pidfile_out" >/dev/null 2>&1; echo "$SSH_AGENT_PID")

		# Write sh format - quote SSH_AUTH_SOCK to handle spaces, SSH_AGENT_PID is numeric
		{
			[ -n "$wp_auth_sock" ] && echo "SSH_AUTH_SOCK=\"${wp_auth_sock}\"; export SSH_AUTH_SOCK"
			[ -n "$wp_agent_pid" ] && echo "SSH_AGENT_PID=${wp_agent_pid}; export SSH_AGENT_PID;"
		} >"$pidf"

		# Write csh format
		{
			[ -n "$wp_auth_sock" ] && echo "setenv SSH_AUTH_SOCK \"${wp_auth_sock}\";"
			[ -n "$wp_agent_pid" ] && echo "setenv SSH_AGENT_PID ${wp_agent_pid};"
		} >"$cshpidf"

		# Write fish format
		{
			[ -n "$wp_auth_sock" ] && echo "set -e SSH_AUTH_SOCK; set -x -U SSH_AUTH_SOCK \"${wp_auth_sock}\";"
			[ -n "$wp_agent_pid" ] && echo "set -e SSH_AGENT_PID; set -x -U SSH_AGENT_PID ${wp_agent_pid};"
		} >"$fishpidf"
	else
		debug skipping creation of pidfiles!
	fi
}

# synopsis: extract_fingerprints
# Extract the fingerprints from standard input, returns space-separated list.
# Utility routine for ssh_l and ssh_f
extract_fingerprints() {
	while read -r ef_line; do
		case "$ef_line" in
			*\ *\ [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:*)
				# Sun SSH spits out different things depending on the type of
				# key.	For example:
				#	md5 1024 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 /home/barney/.ssh/id_dsa(DSA)
				#	2048 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 /home/barney/.ssh/id_rsa.pub
				echo "$ef_line" | cut -f3 -d' '
				;;
			*\ [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:*)
				# The more consistent OpenSSH format, we hope
				#	1024 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 /home/barney/.ssh/id_dsa (DSA)
				echo "$ef_line" | cut -f2 -d' '
				;;
			*\ [A-Z0-9][A-Z0-9]*:[A-Za-z0-9+/][A-Za-z0-9+/]*)
				# The new OpenSSH 6.8+ format,
				#   1024 SHA256:mVPwvezndPv/ARoIadVY98vAC0g+P/5633yTC4d/wXE /home/barney/.ssh/id_dsa (DSA)
				echo "$ef_line" | cut -f2 -d' '
				;;
			*)
				# Fall back to filename.  Note that commercial ssh is handled
				# explicitly in ssh_l and ssh_f, so hopefully this rule will
				# never fire.
				warn "Can't determine fingerprint from the following line, falling back to filename"
				mesg "$ef_line"
				basename "$ef_line" | sed 's/[ (].*//'
				;;
		esac
	done | xargs
}

# synopsis: ssh_l
# Return space-separated list of known fingerprints
ssh_l() {
	sl_mylist=$(ssh-add -l 2>/dev/null)
	sl_retval=$?

	if $openssh; then
		# Error codes:
		#	0  success
		#	1  OpenSSH_3.8.1p1 on Linux: no identities (not an error)
		#	   OpenSSH_3.0.2p1 on HP-UX: can't connect to auth agent
		#	2  can't connect to auth agent
		case $sl_retval in
			0)
				echo "$sl_mylist" | extract_fingerprints
				;;
			1)
				case "$sl_mylist" in
					*"open a connection"*) sl_retval=2 ;;
				esac
				;;
		esac
		return $sl_retval

	elif $sunssh; then
		# Error codes (from http://docs.sun.com/db/doc/817-3936/6mjgdbvio?a=view)
		#	0  success (even when there are no keys)
		#	1  error
		case $sl_retval in
			0)
				echo "$sl_mylist" | extract_fingerprints
				;;
			1)
				case "$sl_mylist" in
					*"open a connection"*) sl_retval=2 ;;
				esac
				;;
		esac
		return $sl_retval
	else
		# Error codes:
		#	0  success - however might say "The authorization agent has no keys."
		#	1  can't connect to auth agent
		#	2  bad passphrase
		#	3  bad identity file
		#	4  the agent does not have the requested identity
		#	5  unspecified error
		if [ $sl_retval = 0 ]; then
			# Output of ssh-add -l:
			#	The authorization agent has one key:
			#	id_dsa_2048_a: 2048-bit dsa, agriffis@alpha.zk3.dec.com, Fri Jul 25 2003 10:53:49 -0400
			# Since we don't have a fingerprint, just get the filenames *shrug*
			echo "$sl_mylist" | sed '2,$s/:.*//' | xargs
		fi
		return $sl_retval
	fi
}

# synopsis: ssh_f filename
# Return fingerprint for a keyfile
# Requires $openssh or $sunssh
ssh_f() {
	sf_filename="$1"

	if $openssh || $sunssh; then
		realpath_bin="$(command -v realpath)"
		# if private key is symlink and symlink to *.pub is missing:
		if [ -L "$sf_filename" ] && [ -n "$realpath_bin" ]; then
			sf_filename="$($realpath_bin "$sf_filename")"
		fi
		lsf_filename="$sf_filename.pub"
		if [ ! -f "$lsf_filename" ]; then
			# try to remove extension from private key, *then* add .pub, and see if we now find it:
			if [ -L "$sf_filename" ] && [ -n "$realpath_bin" ]; then
				sf_filename="$($realpath_bin "$sf_filename")"
			fi
			lsf_filename=$(echo "$sf_filename" | sed 's/\.[^\.]*$//').pub
			if [ ! -f "$lsf_filename" ]; then
				note "Cannot find separate public key for $1."
				lsf_filename="$sf_filename"
			fi
		fi
		sf_fing=$(ssh-keygen -l -f "$lsf_filename") || return 1
		echo "$sf_fing" | extract_fingerprints
	else
		# can't get fingerprint for ssh2 so use filename *shrug*
		basename "$sf_filename"
	fi
	return 0
}

# synopsis: gpg_listmissing
# Accepts piped input from stdin. Returns a newline-separated list of keys found to be missing.
gpg_listmissing() {
	unset glm_missing
	GPG_TTY=$(tty)

	while IFS= read -r glm_k; do
		[ -z "$glm_k" ] && continue
		# Check if this key is known to the agent.	Don't know another way...
		if env -i GPG_TTY="$GPG_TTY" PATH="$PATH" GPG_AGENT_INFO="$GPG_AGENT_INFO" "${gpg_prog_name}" --no-autostart --no-options --use-agent --no-tty --sign --local-user "$glm_k" -o- >/dev/null 2>&1 </dev/null; then
			# already know about this key
			mesg "Known gpg key: ${CYANN}${glm_k}${OFF}"
			continue
		else
			# need to add this key
			if [ -z "$glm_missing" ]; then
				glm_missing="$glm_k"
			else
				glm_missing="$glm_missing
$glm_k"
			fi
		fi
	done
	echo "$glm_missing"
}

ssh_listmissing() {
	unset slm_missing
	sshavail=$(ssh_l)
	while IFS= read -r slm_k; do
		[ -z "$slm_k" ] && continue
		# Fingerprint current user-specified key
		if ! slm_finger=$(ssh_f "$slm_k"); then
			warn "Unable to extract fingerprint from keyfile ${slm_k}.pub, skipping"
			continue
		fi
		slm_wordcount="$(printf -- '%s\n' "$slm_finger" | wc -w)"
		if [ "$slm_wordcount" -ne 1 ]; then
			warn "Unable to extract exactly one key fingerprint from keyfile ${slm_k}.pub, got $slm_wordcount instead, skipping"
			continue
		fi
		# shellcheck disable=SC2031
		case " $sshavail " in
			*" $slm_finger "*)
				# already know about this key
				mesg "Known ssh key: ${CYANN}${slm_k}${OFF}"
				;;
			*)
				# need to add this key
				if [ -z "$slm_missing" ]; then
					slm_missing="$slm_k"
				else
					slm_missing="$slm_missing
$slm_k"
				fi
				;;
		esac
	done
	echo "$slm_missing"
}

# Synopsis: Plow through ~/.ssh/config and grab all IdentityFile lines, and convert
# them to "sshk:<filename>" if they exist or "miss:<filename>" otherwise.
all_host_identities() {
	if [ ! -e ~/.ssh/config ]; then
		warn "No ~/.ssh/config -- can't extract host identities" && return
	fi
	while IFS= read -r line; do
		case $line in
			*[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy][Ff][Ii][Ll][Ee]*)
				keyf="$(echo "$line" | awk '{print $2}')"
				if [ -f "$keyf" ]; then
					echo "sshk:${keyf}"
				else
					echo "miss:${keyf}"
				fi
		esac
	done < ~/.ssh/config
}

# Synopsis: this is the default logic for categorizing command-line keys. If a file is
# specified and is found in ~/.ssh, or just exists, it's a SSH key. If gpg recognizes it,
# then it's a GPG key. Otherwise, it's a missing key.
cmdline_keys_to_extkey() {
	while read -r pm_k; do
		[ -z "$pm_k" ] && continue
		if [ -f "$pm_k" ]; then
			echo "sshk:$pm_k"
		elif [ -f "$HOME/.ssh/$pm_k" ]; then
			echo "sshk:$HOME/.ssh/$pm_k"
		elif "${gpg_prog_name}" --list-secret-keys "$pm_k" >/dev/null 2>&1; then
			echo "gpgk:$pm_k"
		else
			echo "miss:$pm_k"
		fi
	done
}

# Synopsis: sees if specified stdin $keyf exists; converts to "sshk:" or "miss:" lines
keyf_expand() {
	while read -r keyf; do
		if [ -f "$keyf" ]; then
			echo "sshk:$keyf"
		else
			echo "miss:$keyf"
		fi
	done
}

# Synopsis: We allow sshk:id_rsa from the command-line, with no path, but this needs
# to be expanded to the actual filename internally -- or "miss:". Logic is a bit different
# so we can't use cmdline_keys_to_extkey() code.
sshk_fixup() {
	while read -r extkey; do
		key_pref="$(echo "$extkey" | cut -b1-5)"
		if [ "$key_pref" != "sshk:" ]; then
			echo "$extkey"
		else
			pm_k="$(echo "$extkey" | cut -b6-)"
			if [ -f "$pm_k" ]; then
				echo "sshk:$pm_k"
			elif [ -f "$HOME/.ssh/$pm_k" ]; then
				echo "sshk:$HOME/.ssh/$pm_k"
			else
				echo "miss:$pm_k"
			fi
		fi
	done
}

# Synopsis: performs final processing on extended keys. Currently converts each "host:"
# extkeys to (possibly many) "sshk:" or "miss:" lines. Also validates all keys for basic
# syntax.
extkey_expand() {
	while read -r extkey; do
		[ -z "$extkey" ] && continue
		key_pref="$(echo "$extkey" | cut -b1-5)"
		if [ "$key_pref" = "host:" ]; then
			ssh -nG "$(echo "$extkey" | cut -b6-)" 2>/dev/null | grep -e ^identityfile | awk '{print $2}' | keyf_expand
		elif [ "$key_pref" = "sshk:" ] || [ "$key_pref" = "gpgk:" ] || [ "$key_pref" = "miss:" ]; then
			echo "$extkey"
		else
			warn "Unrecognized extended key \"$extkey\". Should have a sshk:, gpgk: or host: prefix."
		fi
	done
}

# Synopsis: gets all extended keys. SSH keys are in "sshk:<filename>" format. GPG fingerprints
# are in "gpgk:<fp>" format. Any SSH keys that cannot be found are expanded to "miss:<filename>,
# which is used for warnings later. If --extended is specified, we expect "sshk:foo" format on
# the command-line. Otherwise, we use cmdline_keys_to_extkey() to convert the standard command-
# line arguments into a format that keychain internals expect.

get_all_extkeys() {
	if $confallhosts; then
		all_host_identities
	fi
	if ! $extended; then
		echo "$cmdline_keys" | cmdline_keys_to_extkey | extkey_expand
	else
		echo "$cmdline_keys" | sshk_fixup | extkey_expand
	fi
}

setaction() {
	if [ -n "$myaction" ]; then
		die "you can't specify --$myaction and $1 at the same time"
	else
		myaction="$1"
	fi
}

wantagent() {
	[ "$1" = "gpg" ] && [ -n "$gpgkeys" ] && return 0
	return 1
}

gpg_wipe() {
	out="$( echo RELOADAGENT | gpg-connect-agent --no-autostart 2>/dev/null )"
	if [ "$out" = "OK" ]; then
		mesg "gpg-agent: All identities removed."
	else
		mesg "gpg-agent: Could not remove identities; possibly not running. (output: $out)"
	fi
}

ssh_wipe() {
	if sshout=$(ssh-add -D 2>&1); then
		mesg "ssh-agent: $sshout"
	else
		warn "ssh-agent: $sshout"
	fi

}

while [ -n "$1" ]; do
	case "$1" in
		--absolute) absoluteopt=true ;;
		--agents) shift; warn "--agents is deprecated, ignoring." ;;
		--confhost) die "--confhost is deprecated; use \"${CYANN}--extended host:<hostname>${OFF}\" instead." ;;
		--confallhosts) confallhosts=true ;;
		--confirm) confirmopt=true ;;
		--debug|-D) debugopt=true ;;
		--eval) evalopt=true ;;
		--extended|--ext|-e) extended=true ;;
		--gpg2) gpg_prog_name="gpg2" ;;
		--help|-h) setaction help ;;
		--host) shift; hostopt="$1" ;;
		--ignore-missing) ignoreopt=true ;;
		--inherit) shift; warn "--inherit is deprecated, ignoring. Use --ssh-allow-forwarded, --noinherit as needed instead.";;
		--list|-l) setaction list ;;
		--list-fp|-L) setaction list-fp ;;
		--noask) noaskopt=true ;;
		--nocolor) color=false ;;
		--nogui) noguiopt=true ;;
		--noinherit) allow_inherited=false ;;
		--nolock) nolockopt=true ;;
		--query) setaction query; quietopt=true ;;
		--quiet|-q) quietopt=true ;;
		--ssh-allow-gpg) ssh_allow_gpg=true ;;
		--ssh-spawn-gpg) ssh_spawn_gpg=true; ssh_allow_gpg=true ;;
		--ssh-agent-socket) shift; ssh_agent_socket="-a $1" ;;
		--ssh-allow-forwarded) ssh_allow_forwarded=true ;;
		--ssh-rm|-r) setaction ssh_rm ;;
		--systemd) systemdopt=true ;;
		--version|-V) setaction version ;;
		--attempts) warn "--attempts is now deprecated." ;;
		--clear)
			clearopt=true
			$quickopt && die "--quick and --clear are not compatible"
			;;
		--dir)
			shift
			case "$1" in
				*/.*) keydir="$1" ;;
				'')   die "--dir requires an argument" ;;
				*)
					if $absoluteopt; then
						keydir="$1"
					else
						keydir="$1/.keychain" # be backward-compatible
					fi
					;;
			esac
			;;
		--env)
			shift
			if [ -z "$1" ]; then
				die "--env requires an argument"
			else
				envf="$1"
			fi
			;;
		--lockwait)
			shift
			if [ "$1" -ge 0 ] 2>/dev/null; then
				lockwait="$1"
			else
				die "--lockwait requires an argument zero or greater."
			fi
			;;
		--quick|-Q)
			quickopt=true
			$clearopt && die "--quick and --clear are not compatible"
			;;
		--stop|-k)
			setaction stop
			case $2 in
				all|mine|others) stopwhich="$2" ;;
				*) die "Please specify 'all', 'mine' or 'others' for --stop" ;;
			esac
			;;
		--timeout)
			shift
			if [ "$1" -gt 0 ] 2>/dev/null; then
				timeout=$1
			else
				die "--timeout requires a numeric argument greater than zero"
			fi
			;;
		--wipe)
			shift
			case $1 in
				gpg) setaction gpg_wipe ;;
				ssh) setaction ssh_wipe ;;
				all) setaction all_wipe ;;
				*) die "Please specify ssh, gpg or all for --wipe action"
			esac
			;;
		-*)
			zero=$(basename "$0")
			echo "$zero: unknown option $1" >&2
			$evalopt && { echo; echo "false;"; }
			exit 1
			;;
		*)
			cmdline_keys="$1${NEWLINE}${cmdline_keys}"
			;;
	esac
	shift
done
if [ -z "$hostopt" ]; then
	if [ -z "$HOSTNAME" ]; then
		hostopt=$(uname -n 2>/dev/null || echo unknown)
	else
		hostopt="$HOSTNAME"
	fi
fi

pidf="${keydir}/${hostopt}-sh"
cshpidf="${keydir}/${hostopt}-csh"
fishpidf="${keydir}/${hostopt}-fish"
lockf="${keydir}/${hostopt}-lockf"
for keyf in "$pidf" "$cshpidf" "$fishpidf"; do
	if [ -f "$keyf" ]; then
		# shellcheck disable=SC2012 # POSIX defines the first 9 chars of ls -l:
		go_modes="$(ls -ld "${keyf}" | cut -c5-10 )"
		[ "$go_modes" != "------" ] && warn "Some pidfiles have lax permissions. Use ${CYAN}chmod -R go-rwx '${keydir}'${OFF} to fix."
		keyf_owner="$(get_owner "${keyf}")"
		[ -n "$keyf_owner" ] && [ "$keyf_owner" != "$me" ] && warn "${keyf} is owned by ${keyf_owner}, not ${me}. Please fix."
	fi
done

# Read the env snippet (especially for things like PATH, but could modify basically anything)
if [ -z "$envf" ]; then
	envf="${keydir}/${hostopt}-env"
	[ -f "$envf" ] || envf="${keydir}/env"
	[ -f "$envf" ] || unset envf
fi
if [ -n "$envf" ]; then
	# shellcheck disable=SC1090
	. "$envf"
fi

# Don't use color if there's no terminal on stderr
if [ -n "$OFF" ]; then
	tty <&2 >/dev/null 2>&1 || color=false
fi

$color || unset BLUE CYAN CYANN GREEN PURP OFF RED

# TODO: we can't assume pidfile has been created yet? Or not a big deal?
[ "$myaction" = list ] && eval "$(catpidf_shell sh)" && exec ssh-add -l
[ "$myaction" = list-fp ] && eval "$(catpidf_shell sh)" && exec ssh-add -L

qprint #initial newline
mesg "${PURP}keychain ${OFF}${CYANN}${version}${OFF} ~ ${GREEN}https://github.com/danielrobbins/keychain${OFF}"

[ "$myaction" = version ] && { versinfo; exit 0; }
[ "$myaction" = help ] && { versinfo; helpinfo; exit 0; }

# Don't use signal names because they don't work on Cygwin.
if $clearopt; then
	trap '' 2 # disallow ^C until we've had a chance to --clear
	trap 'droplock; exit 1' 1 15 # drop the lock on signal
	trap 'droplock;' 0 # drop the lock on exit
else
	# Don't use signal names because they don't work on Cygwin.
	trap 'droplock; exit 1' 1 2 15	# drop the lock on signal
	trap 'droplock;' 0 # drop the lock on exit
fi

testssh # sets $openssh, $sunssh and tweaks $ssh_spawn_gpg
verifykeydir # sets up $keydir

# --stop: kill the existing ssh-agent(s) (not gpg-agent) and quit
[ "$myaction" = stop ] && stop_ssh_agents

# --timeout translates almost directly to ssh-add/ssh-agent -t, but ssh.com uses
# minutes and OpenSSH uses seconds
if [ -n "$timeout" ]; then
	ssh_timeout=$timeout
	if $openssh || $sunssh; then
		ssh_timeout=$(( ssh_timeout * 60 ))
	fi
	ssh_timeout="-t $ssh_timeout"
fi

all_keys="$(get_all_extkeys | sort -u)"
if ! $ignoreopt; then
	for key in $(echo "$all_keys" | grep ^miss:); do
		warn "Can't find key \"${GREEN}$( echo "$key" | cut -c6- )${OFF}\""
	done
fi
sshkeys="$(echo "$all_keys" | sed -n '/^sshk:/s/sshk://p')"
gpgkeys="$(echo "$all_keys" | sed -n '/^gpgk:/s/gpgk://p')"
if [ "$myaction" = gpg_wipe ]; then
	gpg_wipe; qprint; exit 0
elif [ "$myaction" = ssh_wipe ]; then
	ssh_wipe; qprint; exit 0
elif [ "$myaction" = all_wipe ]; then
	ssh_wipe; gpg_wipe; qprint; exit 0
elif [ "$myaction" = query ]; then
	# --query displays current settings, but does not start an agent:
	if catpidf_shell sh > /dev/null; then
		catpidf_shell sh | cut -d\; -f1 && exit 0
	else
		die "Can't query. Does pidfile exist?"
	fi
elif [ "$myaction" = ssh_rm ]; then
	if [ -n "$sshkeys" ]; then
		die "No ssh keys specified to remove."
	fi
	for key in $sshkeys; do
		if sshout=$(ssh-add -d "$key" 2>&1); then
			mesg "ssh-agent key $key removed."
		else
			die "keychain was unable to remove ssh-agent key $key. output: $sshout"
		fi
	done
	qprint; exit 0
else
	# This will start gpg-agent as an ssh-agent if such functionality is enabled (default)
	startagent_ssh || warn "Unable to start an ssh-agent (error code: $?)"
	[ -n "$pidfile_out" ] && write_pidfile && eval "$pidfile_out" > /dev/null
	if ! $gpg_started && wantagent gpg; then
		# If we also want gpg, and it hasn't been started yet, start it also. We don't need to
		# look for pidfile output, as this would have been output from the startagent_ssh->startagent_gpg
		# call above, and gpg doesn't use pidfiles for gpg stuff anymore.
		startagent_gpg || warn "Unable to start gpg-agent (error code: $?)"
	fi
	if $clearopt; then
		ssh_wipe
		if wantagent gpg; then
			gpg_wipe
		fi
		trap 'droplock' 2 # done clearing, safe to ctrl-c
	fi
fi

if $evalopt; then
	catpidf_shell "$SHELL"
fi

$systemdopt && systemctl --user set-environment "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
$systemdopt && [ -n "$SSH_AGENT_PID" ] && systemctl --user set-environment "SSH_AGENT_PID=$SSH_AGENT_PID"
# These options don't need to load keys, so terminate early:
$noaskopt && { qprint; exit 0; }
$quickopt && { qprint; exit 0; }

load_ssh_keys() {
	missing="$(echo "${sshkeys}" | ssh_listmissing)"
	savedisplay="$DISPLAY"
	if $confirmopt; then
		if $openssh || $sunssh; then
			ssh_confirm=-c
		else
			warn "--confirm only works with OpenSSH"
		fi
	fi
	# Put $missing into args to access $# and other goodies. Since $missing is a line-delimited
	# list of files with (potentially) spaces, we must do an IFS hack to get each file in
	# $1, $2, $3, etc. For Bourne-shell compatibility, we don't have another good option:
	IFS_BAK="$IFS"; IFS="$NEWLINE"
	# shellcheck disable=SC2086
	set -- $missing
	IFS="$IFS_BAK"
	[ $# -eq 0 ] && return
	mesg "Adding ${CYANN}$#${OFF} ssh key(s): ${CYANN}$*${OFF}"
	if $noguiopt || [ -z "$SSH_ASKPASS" ] || [ -z "$DISPLAY" ]; then
		unset DISPLAY		# DISPLAY="" can cause problems
		unset SSH_ASKPASS	# make sure ssh-add doesn't try SSH_ASKPASS
	fi
	# shellcheck disable=SC2086
	sshout=$(ssh-add ${ssh_timeout} ${ssh_confirm} "$@" 2>&1)
	ret=$?
	if [ $ret = 0 ]; then
		blurb=""
		[ -n "$timeout" ] && blurb="life=${timeout}m"
		[ -n "$timeout" ] && $confirmopt && blurb="${blurb},"
		$confirmopt && blurb="${blurb}confirm"
		[ -n "$blurb" ] && blurb=" (${blurb})"
		mesg "ssh-add: Identities added: $sshkeys${blurb}"
	else
		warn "ssh-add failed: (return code: $ret; output: $sshout)"
	fi
	[ -n "$savedisplay" ] && DISPLAY="$savedisplay"
	return $ret
}

load_gpg_keys() {
	$noguiopt && unset DISPLAY
	[ -n "$DISPLAY" ] || unset DISPLAY # DISPLAY="" can cause problems
	GPG_TTY=$(tty) ; export GPG_TTY # fall back to ncurses pinentry
	for key in "$@"; do
		[ -z "$key" ] && continue
		mesg "Adding gpg key: $key"
		# the 3>&1, etc. is a temp fd to allow us to capture stderr, while throwing away stdout which is encrypted data, and avoid a "null byte on input" bash warning:
		gpgout="$(env LC_ALL="$pinentry_lc_all" "${gpg_prog_name}" --no-autostart --no-options --use-agent --sign --local-user "$key" -o- 3>&1 1>/dev/null 2>&3 </dev/null)"
		ret=$?
		if [ $ret -ne 0 ]; then
			warn "Error adding gpg key (error code: $ret; output: $gpgout)"; return 1
		fi
	done
}

load_ssh_keys || die "Unable to add keys"

if wantagent gpg; then
	# shellcheck disable=SC2046
	load_gpg_keys $(echo "${gpgkeys}" | gpg_listmissing)
fi

qprint	# trailing newline
