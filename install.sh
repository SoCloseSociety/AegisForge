#!/bin/bash
# AegisForge installer (formerly macmon) -- Mac Developer Monitor + System Cleaner
# Installs the `aegis` command plus the deprecated `macmon` alias.
# State stays in ~/.macmon (unchanged by the rename: existing configs keep working).
set -e

MACMON_DIR="$HOME/.macmon"
VENV_DIR="$MACMON_DIR/venv"
APP_DIR="$MACMON_DIR/app"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  AegisForge  (CLI: aegis, formerly macmon)"
echo ""
echo " Mac Developer Monitor + System Cleaner"
echo -e "${NC}"

# Check Python version
echo -e "${CYAN}Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

    if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
        echo -e "${RED}Python 3.11+ required (found $PY_VERSION)${NC}"
        echo "Install via: brew install python@3.12"
        exit 1
    fi
    echo -e "${GREEN}Python $PY_VERSION found${NC}"
else
    echo -e "${RED}Python 3 not found!${NC}"
    echo "Install via: brew install python@3.12"
    exit 1
fi

# Create the state directory (kept as ~/.macmon across the rename)
echo -e "${CYAN}Setting up ~/.macmon...${NC}"
mkdir -p "$MACMON_DIR"
mkdir -p "$MACMON_DIR/reports"

# Copy application files to a stable location (survives moving the clone dir)
echo -e "${CYAN}Copying application files to $APP_DIR...${NC}"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
cp "$SCRIPT_DIR/macmon.py" "$APP_DIR/"
cp -R "$SCRIPT_DIR/macmon_core" "$APP_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$APP_DIR/"

# Create virtual environment
echo -e "${CYAN}Creating virtual environment...${NC}"
if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Existing venv found, recreating...${NC}"
    rm -rf "$VENV_DIR"
fi
python3 -m venv "$VENV_DIR"

# Install dependencies
echo -e "${CYAN}Installing dependencies...${NC}"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# Create wrapper scripts: `aegis` (the command) + `macmon` (deprecated alias,
# same CLI, prints a one-line rename notice on an interactive terminal).
BIN_DIR="/usr/local/bin"
SUDO=""
if ! { [ -w "$BIN_DIR" ] && { [ ! -e "$BIN_DIR/aegis" ] || [ -w "$BIN_DIR/aegis" ]; } && { [ ! -e "$BIN_DIR/macmon" ] || [ -w "$BIN_DIR/macmon" ]; }; }; then
    # /usr/local/bin may not exist or be writable (Apple Silicon)
    echo -e "${YELLOW}Need sudo to install to $BIN_DIR${NC}"
    SUDO="sudo"
fi
$SUDO mkdir -p "$BIN_DIR"

install_wrapper() {
    # $1 = command name, $2 = extra env for the exec line ("" for none)
    local target="$BIN_DIR/$1"
    if [ -e "$target" ] || [ -L "$target" ]; then
        # `aegis` (and `macmon`) are common names: never clobber another tool's
        # launcher, and never write THROUGH a symlink (an Intel Homebrew link in
        # /usr/local/bin points into the Cellar). Only our own wrapper or console
        # script is replaced, by a fresh file.
        if [ -L "$target" ] || ! grep -qs -e 'macmon\.py' -e 'from macmon import' "$target"; then
            echo -e "${YELLOW}Skipped $target: another '$1' is already installed there (left untouched).${NC}"
            echo -e "${YELLOW}  Run this CLI with: \"$VENV_DIR/bin/python\" \"$APP_DIR/macmon.py\"${NC}"
            return 0
        fi
        $SUDO rm -f "$target"
    fi
    echo -e "${CYAN}Creating $1 command...${NC}"
    $SUDO bash -c "cat > '$target'" << WRAPPER_EOF
#!/bin/bash
${2}exec "$VENV_DIR/bin/python" "$APP_DIR/macmon.py" "\$@"
WRAPPER_EOF
    $SUDO chmod +x "$target"
    echo -e "${GREEN}Installed to $target${NC}"
}

install_wrapper aegis ""
install_wrapper macmon "AEGISFORGE_INVOKED_AS=macmon "

# Initialize config
echo -e "${CYAN}Initializing config...${NC}"
"$VENV_DIR/bin/python" "$APP_DIR/macmon.py" config --init 2>/dev/null || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} AegisForge installed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}Command Cheatsheet:${NC}"
echo ""
echo -e "  ${GREEN}aegis${NC}                         Live dashboard"
echo -e "  ${GREEN}aegis dashboard${NC}               Dashboard with custom refresh"
echo ""
echo -e "  ${GREEN}aegis ps${NC}                      List dev processes"
echo -e "  ${GREEN}aegis ps --sort ram${NC}           Sort by RAM usage"
echo -e "  ${GREEN}aegis ps --filter llm${NC}         Filter by category"
echo -e "  ${GREEN}aegis ps --tree${NC}               Process hierarchy"
echo -e "  ${GREEN}aegis kill <name|pid>${NC}         Kill a process"
echo -e "  ${GREEN}aegis suspend <name|pid>${NC}      Suspend a process"
echo -e "  ${GREEN}aegis resume <name|pid>${NC}       Resume a process"
echo ""
echo -e "  ${GREEN}aegis sweep${NC}                   Kill zombies + orphans + stale locks"
echo -e "  ${GREEN}aegis ports${NC}                   Show port usage"
echo -e "  ${GREEN}aegis ports --free 3000${NC}       Free a port"
echo -e "  ${GREEN}aegis ports --free-all-dev${NC}    Free all dev ports"
echo -e "  ${GREEN}aegis purge${NC}                   Purge inactive RAM"
echo ""
echo -e "  ${GREEN}aegis clean --scan${NC}            Preview system cleanup"
echo -e "  ${GREEN}aegis clean --run${NC}             Interactive cleanup"
echo -e "  ${GREEN}aegis clean --all -y${NC}          Full auto cleanup"
echo -e "  ${GREEN}aegis clean --browsers${NC}        Browser cache cleanup"
echo -e "  ${GREEN}aegis clean --module xcode${NC}    Clean specific app"
echo -e "  ${GREEN}aegis clean --clipboard${NC}       Clear clipboard"
echo ""
echo -e "  ${GREEN}aegis gc --scan${NC}               Preview dev garbage"
echo -e "  ${GREEN}aegis gc --clean${NC}              Interactive dev cleanup"
echo -e "  ${GREEN}aegis gc --all -y${NC}             Full dev garbage nuke"
echo ""
echo -e "  ${GREEN}aegis privacy --scan${NC}          List privacy traces"
echo -e "  ${GREEN}aegis privacy --clean${NC}         Interactive privacy wipe"
echo -e "  ${GREEN}aegis privacy --full -y${NC}       Full trace wipe"
echo ""
echo -e "  ${GREEN}aegis health${NC}                  System health check (/100)"
echo -e "  ${GREEN}aegis health --fix${NC}            Auto-fix safe issues"
echo -e "  ${GREEN}aegis health --report${NC}         Save health report"
echo ""
echo -e "  ${GREEN}aegis startup --list${NC}          List startup items"
echo -e "  ${GREEN}aegis startup --broken${NC}        Show broken items"
echo -e "  ${GREEN}aegis startup --audit${NC}         Flag suspicious items"
echo -e "  ${GREEN}aegis startup --disable <n>${NC}   Disable startup item"
echo ""
echo -e "  ${GREEN}aegis uninstall <App>${NC}         Full app uninstaller"
echo -e "  ${GREEN}aegis uninstall --list${NC}        List all apps by size"
echo -e "  ${GREEN}aegis uninstall --scan <App>${NC}  Preview leftovers"
echo ""
echo -e "  ${GREEN}aegis dupes ~/Downloads${NC}       Find duplicate files"
echo -e "  ${GREEN}aegis dupes --empty-dirs${NC}      Find empty directories"
echo -e "  ${GREEN}aegis dupes --broken-symlinks${NC}  Find broken symlinks"
echo ""
echo -e "  ${GREEN}aegis bigfiles${NC}                Find large files"
echo -e "  ${GREEN}aegis bigfiles --min 100MB${NC}    Custom size threshold"
echo -e "  ${GREEN}aegis bigfiles --older 90${NC}     Files not accessed 90+ days"
echo ""
echo -e "  ${GREEN}aegis disk${NC}                    Disk usage analyzer"
echo -e "  ${GREEN}aegis disk ~/Projects${NC}         Analyze specific directory"
echo ""
echo -e "  ${GREEN}aegis network${NC}                 Network connections"
echo -e "  ${GREEN}aegis network --listening${NC}     Listening ports only"
echo -e "  ${GREEN}aegis flush-dns${NC}               Flush DNS cache"
echo ""
echo -e "  ${GREEN}aegis security${NC}                Full security audit (/100)"
echo -e "  ${GREEN}aegis security --connections${NC}   Scan active connections"
echo -e "  ${GREEN}aegis security --firewall${NC}     Firewall status"
echo -e "  ${GREEN}aegis security --malware${NC}      Malware indicator scan"
echo -e "  ${GREEN}aegis security --remote${NC}       Remote access tool detection"
echo -e "  ${GREEN}aegis security --rules${NC}        Active security rules"
echo -e "  ${GREEN}aegis security --block-ip X${NC}   Block an IP address"
echo -e "  ${GREEN}aegis security --quarantine X${NC}  Kill + block a process"
echo ""
echo -e "  ${GREEN}aegis docker${NC}                  Docker overview"
echo -e "  ${GREEN}aegis docker --containers${NC}     List all containers"
echo -e "  ${GREEN}aegis docker --images${NC}         List images"
echo -e "  ${GREEN}aegis docker --volumes${NC}        List volumes"
echo -e "  ${GREEN}aegis docker --prune -y${NC}       Full Docker cleanup"
echo -e "  ${GREEN}aegis docker --stop-all${NC}       Stop all containers"
echo -e "  ${GREEN}aegis docker --stats${NC}          Live container stats"
echo -e "  ${GREEN}aegis docker --compose${NC}        List Compose projects"
echo -e "  ${GREEN}aegis docker --scan${NC}           Docker security audit"
echo ""
echo -e "  ${GREEN}aegis auto --start${NC}            Start autopilot daemon"
echo -e "  ${GREEN}aegis auto --stop${NC}             Stop autopilot daemon"
echo -e "  ${GREEN}aegis auto --status${NC}           Daemon status + recent actions"
echo ""
echo -e "  ${GREEN}aegis focus${NC}                   Enter focus mode"
echo -e "  ${GREEN}aegis restore${NC}                 Restore after focus"
echo ""
echo -e "  ${GREEN}aegis report${NC}                  Session summary"
echo -e "  ${GREEN}aegis report --full${NC}           Full report with health check"
echo -e "  ${GREEN}aegis config --show${NC}           View config"
echo -e "  ${GREEN}aegis config --edit${NC}           Edit config in \$EDITOR"
echo ""
echo -e "${CYAN}Config: ~/.macmon/config.toml${NC}"
echo -e "${CYAN}Logs:   ~/.macmon/macmon.log${NC}"
echo -e "${CYAN}DB:     ~/.macmon/macmon.db${NC}"
echo -e "${YELLOW}'macmon' still works as an alias of 'aegis' (deprecated, removed in a future release).${NC}"
echo ""
echo -e "${GREEN}Ready! Run 'aegis' to launch the dashboard.${NC}"
