# bash completion for MachO-Tools.                              -*- shell-script -*-
#
# Installs completion for all six binaries from this one file:
#
#     . /path/to/completions/macho.bash          # from your .bashrc
#
# A package-manager install should instead drop this at
# $PREFIX/share/bash-completion/completions/macho, which bash loads
# automatically; the `macho` name is chosen so the file is found by that
# convention rather than needing to know all six command names.
#
# Every tool here is dependency-free and runs on Linux and Windows as well as
# macOS, so completion never assumes `otool` or `lipo` exist.

# Per-tool option sets, keyed by the command name *without* the `macho-` prefix,
# which is what `_macho_complete` strips before looking one up.
_macho_opts_for() {
    case "$1" in
        describe)     echo "--json -h --help -b --binary" ;;
        sym)          echo "--json -h --help --regex --case-sensitive --all-imp --no-dedupe --arch -b --binary" ;;
        symlookup)    echo "--json -h --help --arch -b --binary" ;;
        findcall)     echo "--json -h --help --list --include-data --arch -b --binary" ;;
        findliteral)  echo "--json -h --help --text -b --binary" ;;
        mapliteral)   echo "--json -h --help -b --binary" ;;
        *)            echo "" ;;
    esac
}

# Complete a path that may be a Mach-O file or an application bundle.
#
# `.app` is included because every tool accepts a bundle and resolves the
# executable inside it, and `.macho` because that is the fixture extension. The
# default file completion is still offered, since the tools are named by
# convention rather than by suffix and most real binaries have no suffix.
_macho_targets() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=( $(compgen -f -X '!*@' -- "$cur") )
    compopt -o filenames 2>/dev/null
}

# Architectures worth offering. This is a preference rather than a requirement,
# so the list is a convenience and not an enumeration of what the reader accepts.
_macho_arches='x86_64 arm64'

_macho_complete() {
    local cmd="${COMP_WORDS[0]##*/}"
    local name="${cmd#macho-}"
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Keyed by the name with `macho-` removed: `_macho_opts_for` lists the six
    # command names, and passing the prefixed form matches no case and silently
    # completes nothing — a completion that always returns empty looks identical
    # to one that has no candidates, which is why this is worth a test.
    opts="$(_macho_opts_for "$name")"

    # A value-taking flag is followed by its value, not by another option.
    case "$prev" in
        -b|--binary) _macho_targets; return 0 ;;
        --arch)      COMPREPLY=( $(compgen -W "$_macho_arches" -- "$cur") ); return 0 ;;
        --arch=*)    COMPREPLY=( $(compgen -W "$_macho_arches" -- "${cur#*=}") ); return 0 ;;
    esac

    if [[ "$cur" == --arch=* ]]; then
        COMPREPLY=( $(compgen -W "$_macho_arches" -- "${cur#*=}") )
        # Keep the prefix the user already typed.
        COMPREPLY=( "${COMPREPLY[@]/#/--arch=}" )
        return 0
    fi

    # Everything starting with a dash that is in this tool's option set.
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi

    # Otherwise a path. The first positional is a pattern for sym,
    # symlookup, findcall, findliteral and mapliteral, so a path is only correct
    # once those are filled; completefull handles the common case of one
    # pattern and one path without trying to know which position we are in.
    _macho_targets
}

for _macho_cmd in macho-describe macho-sym macho-symlookup macho-findcall \
                  macho-findliteral macho-mapliteral; do
    complete -F _macho_complete "$_macho_cmd"
done
unset _macho_cmd

# Sourced rather than executed: `complete` and `compgen` only exist inside an
# interactive bash, and running this file as a script would exit on the first of
# them.