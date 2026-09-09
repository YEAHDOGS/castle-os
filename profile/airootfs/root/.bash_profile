# ~/.bash_profile — Castle OS live session (root, autologin on tty1)
#
# In GUI mode (kernel cmdline carries castle.mode=gui) this starts the
# labwc Wayland compositor on this console. In headless mode it falls
# through to an ordinary root shell.

if [[ -z "${WAYLAND_DISPLAY:-}" && "$(tty)" == "/dev/tty1" ]] \
   && grep -q 'castle\.mode=gui' /proc/cmdline 2>/dev/null; then
    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/0}"
    [[ -d "$XDG_RUNTIME_DIR" ]] || { mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"; }
    # labwc reads ~/.config/labwc/{rc.xml,autostart}
    exec labwc
fi

[[ -f ~/.bashrc ]] && . ~/.bashrc
