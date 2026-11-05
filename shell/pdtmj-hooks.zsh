# pdtmj-ai shell hooks
# Source this from ~/.zshrc:
#   source /path/to/pdtmj-ai/shell/pdtmj-hooks.zsh
#
# Only activates for pentest/redteam personas — no-op for pentest-ctf.
# `saddle start` writes ~/.local/share/pdtmj-ai/.active_persona and
# ~/.local/share/pdtmj-ai/ops/.active_op on launch; this hook reads both.

autoload -Uz add-zsh-hook

_PDTMJ_BASE="${HOME}/.local/share/pdtmj-ai"
_PDTMJ_ACTIVE_OP_FILE="${_PDTMJ_BASE}/ops/.active_op"
_PDTMJ_ACTIVE_PERSONA_FILE="${_PDTMJ_BASE}/.active_persona"
# Resolve the hooks directory at source time; repo root is one level up
_PDTMJ_HOOKS_DIR="${${(%):-%x}:A:h}"
_PDTMJ_REPO_DIR="${_PDTMJ_HOOKS_DIR:h}"

# Auto-detect Python: repo .venv → active venv → pipenv → system python3
# Result cached for the session so pipenv --venv runs at most once.
_pdtmj_python() {
    if [[ -n "$_PDTMJ_PYTHON" ]]; then echo "$_PDTMJ_PYTHON"; return; fi
    if [[ -x "${_PDTMJ_REPO_DIR}/.venv/bin/python3" ]]; then
        _PDTMJ_PYTHON="${_PDTMJ_REPO_DIR}/.venv/bin/python3"
    elif [[ -n "$VIRTUAL_ENV" && -x "${VIRTUAL_ENV}/bin/python3" ]]; then
        _PDTMJ_PYTHON="${VIRTUAL_ENV}/bin/python3"
    elif command -v pipenv >/dev/null 2>&1; then
        local pv
        pv=$(cd "$_PDTMJ_REPO_DIR" && pipenv --venv 2>/dev/null)
        if [[ -x "${pv}/bin/python3" ]]; then
            _PDTMJ_PYTHON="${pv}/bin/python3"
        fi
    fi
    _PDTMJ_PYTHON="${_PDTMJ_PYTHON:-python3}"
    echo "$_PDTMJ_PYTHON"
}

unalias saddle 2>/dev/null
saddle() { "$(_pdtmj_python)" "${_PDTMJ_REPO_DIR}/saddle.py" "$@"; }

# Returns the active op name, or empty string
_pdtmj_active_op() {
    [[ -f "$_PDTMJ_ACTIVE_OP_FILE" ]] && cat "$_PDTMJ_ACTIVE_OP_FILE"
}

# Returns true (0) only for ops personas
_pdtmj_is_ops_persona() {
    [[ -f "$_PDTMJ_ACTIVE_PERSONA_FILE" ]] || return 1
    local p
    p=$(cat "$_PDTMJ_ACTIVE_PERSONA_FILE")
    [[ "$p" == "pentest" || "$p" == "redteam" ]]
}

# Returns the active op's log dir, or empty
_pdtmj_log_dir() {
    local op
    op=$(_pdtmj_active_op)
    [[ -z "$op" ]] && return
    echo "${_PDTMJ_BASE}/ops/${op}/logs"
}

# ── Command logging via preexec ───────────────────────────────────────────────

_pdtmj_preexec() {
    _pdtmj_is_ops_persona || return
    local log_dir
    log_dir=$(_pdtmj_log_dir)
    [[ -z "$log_dir" ]] && return
    # Don't log saddle commands — operator tooling, not engagement activity
    [[ "$1" == saddle* ]] && return
    mkdir -p "$log_dir"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${1}" >> "${log_dir}/cmd_$(date +%Y%m%d).log"
}

add-zsh-hook preexec _pdtmj_preexec

# ── RPROMPT badge from daemon ─────────────────────────────────────────────────

_pdtmj_fmt_tokens() {
    local n=$1
    if (( n >= 1000000 )); then
        printf "%.1fM" $(( n / 1000000.0 ))
    elif (( n >= 1000 )); then
        printf "%.1fk" $(( n / 1000.0 ))
    else
        printf "%d" "$n"
    fi
}

_pdtmj_precmd() {
    _pdtmj_is_ops_persona || { RPROMPT=""; return; }

    local op
    op=$(_pdtmj_active_op)
    [[ -z "$op" ]] && return

    local op_dir="${_PDTMJ_BASE}/ops/${op}"

    # ── Usage (always shown when .usage exists) ──
    local usage_rp=""
    local usage_file="${op_dir}/.usage"
    if [[ -f "$usage_file" ]]; then
        local _in _out _cost
        { read -r _in; read -r _out; read -r _cost } < "$usage_file"
        if [[ -n "$_in" ]]; then
            local in_fmt=$(_pdtmj_fmt_tokens "$_in")
            local out_fmt=$(_pdtmj_fmt_tokens "$_out")
            usage_rp="%F{243}[%F{blue}↑${in_fmt}%F{243} | %F{magenta}↓${out_fmt}%F{243} | %F{green}\$${_cost}%F{243}]%f"
        fi
    fi

    # ── Badge (transient, shown to the left of usage) ──
    local badge_rp=""
    local badge_file="${op_dir}/.badge"
    if [[ -f "$badge_file" ]]; then
        local _badge _badge_type
        { read -r _badge; read -r _badge_type } < "$badge_file"
        if [[ -n "$_badge" ]]; then
            case "$_badge_type" in
                frontier)     badge_rp="%F{green}[${_badge}]%f " ;;
                notable_lead) badge_rp="%F{cyan}[lead]%f " ;;
                opsec)        badge_rp="%F{red}[${_badge}]%f " ;;
                *)            badge_rp="%F{yellow}[${_badge}]%f " ;;
            esac
        fi
    fi

    RPROMPT="${badge_rp}${usage_rp}"
}

add-zsh-hook precmd _pdtmj_precmd

# ── SSH wrapper: capture full interactive session ─────────────────────────────

ssh() {
    local log_dir
    log_dir=$(_pdtmj_log_dir)
    if [[ -z "$log_dir" ]] || ! _pdtmj_is_ops_persona; then
        command ssh "$@"
        return
    fi
    mkdir -p "$log_dir"
    local host="unknown"
    for arg in "$@"; do
        [[ "$arg" != -* ]] && host="$arg"
    done
    host="${host//[^a-zA-Z0-9._-]/_}"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local raw_log="${log_dir}/ssh_${host}_${ts}.raw"
    local ts_log="${log_dir}/ssh_${host}_${ts}.log"
    local proc="${_PDTMJ_HOOKS_DIR}/log_processor.py"
    if [[ -f "$proc" ]]; then
        python3 -u "$proc" --watch "$raw_log" --out "$ts_log" &
        local proc_pid=$!
        script -q -f -e -c "command ssh $*" "$raw_log"
        kill $proc_pid 2>/dev/null
    else
        script -q -f -e -c "command ssh $*" "$raw_log"
    fi
    rm -f "$raw_log"
}

# ── evil-winrm wrapper ────────────────────────────────────────────────────────

evil-winrm() {
    local log_dir
    log_dir=$(_pdtmj_log_dir)
    if [[ -z "$log_dir" ]] || ! _pdtmj_is_ops_persona; then
        command evil-winrm "$@"
        return
    fi
    mkdir -p "$log_dir"
    local logfile="${log_dir}/evilwinrm_$(date +%Y%m%d_%H%M%S).log"
    command evil-winrm "$@" --log "$logfile" 2>&1 | \
        python3 -u "${_PDTMJ_HOOKS_DIR}/log_processor.py" --stdin "${logfile}.log"
}

# ── pdtmj_op: start TTY capture for the active op ────────────────────────────

pdtmj_op() {
    _pdtmj_is_ops_persona || { echo "pdtmj-ai: shell capture is only active for pentest/redteam personas."; return 1; }
    local log_dir
    log_dir=$(_pdtmj_log_dir)
    if [[ -z "$log_dir" ]]; then
        echo "pdtmj-ai: no active op — run: saddle start --op <name>"
        return 1
    fi
    mkdir -p "$log_dir"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local raw_log="${log_dir}/tty_${ts}.raw"
    local ts_log="${log_dir}/tty_${ts}.log"
    local proc="${_PDTMJ_HOOKS_DIR}/log_processor.py"
    echo "pdtmj-ai: capturing TTY to ${ts_log}"
    export _PDTMJ_IN_SCRIPT=1
    if [[ -f "$proc" ]]; then
        python3 -u "$proc" --watch "$raw_log" --out "$ts_log" &
        local proc_pid=$!
        script -q -f "$raw_log"
        kill $proc_pid 2>/dev/null
    else
        script -q -f "$raw_log"
    fi
    rm -f "$raw_log"
    unset _PDTMJ_IN_SCRIPT
}

# ── Auto-start TTY capture ───────────────────────────────────────────────────
# When an op is active and we're not already inside script(1), start capture.

if [[ -z "$_PDTMJ_IN_SCRIPT" ]] && _pdtmj_is_ops_persona; then
    _pdtmj_auto_log=$(_pdtmj_log_dir)
    if [[ -n "$_pdtmj_auto_log" ]]; then
        pdtmj_op
    fi
    unset _pdtmj_auto_log
fi
